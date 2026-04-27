# =============================================================================
# backend/services/sandbox_service.py
# 역할: Docker SDK로 Browserless 컨테이너를 매 요청마다 생성/분석/폐기하는 샌드박스 서비스.
# 아키텍처 원칙: 샌드박스는 관찰만 한다. 판정을 바꾸지 않는다.
#
# [Windows 이벤트 루프 설계]
# uvicorn은 Windows에서 SelectorEventLoop를 사용하는데, 이 루프는 subprocess를
# 지원하지 않는다. Playwright는 내부적으로 Node.js 드라이버 subprocess를 생성하므로
# SelectorEventLoop에서 직접 호출하면 NotImplementedError가 발생한다.
# 해결책: Playwright 분석 전용 함수(_playwright_analysis)를 별도 스레드에서
# ProactorEventLoop으로 실행한다. Docker 작업은 기존 루프에서 처리한다.
#
# [네트워크 보안 설계]
# 컨테이너별 격리 네트워크를 생성해 ICC를 차단하고, Playwright route()로
# 내부 IP 대역 요청을 가로채 SSRF 공격 경로를 이중으로 차단한다.
# =============================================================================

import asyncio
import base64
import logging
import os
import re
import sys
from uuid import uuid4
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

BROWSERLESS_IMAGE = os.getenv("BROWSERLESS_IMAGE", "ghcr.io/browserless/chromium:latest")
CONTAINER_READY_WAIT = 3  # 컨테이너 시작 후 Playwright 연결 전 대기(초)

# docker.from_env()는 Docker Desktop이 실행 중일 때만 동작한다.
try:
    import docker
    from docker.types import Ulimit
    _DOCKER_AVAILABLE = True
except Exception as _docker_err:
    _DOCKER_AVAILABLE = False
    logger.warning("[샌드박스] docker 패키지 import 실패: %s", _docker_err)

# playwright는 greenlet C 확장에 의존한다.
# import 실패 시 서버는 정상 기동되고 sandbox 엔드포인트만 오류를 반환한다.
try:
    from playwright.async_api import async_playwright
    _PLAYWRIGHT_AVAILABLE = True
except Exception as _playwright_err:
    _PLAYWRIGHT_AVAILABLE = False
    logger.warning("[샌드박스] playwright import 실패: %s", _playwright_err)


# =============================================================================
# 내부 IP 차단 규칙 (Playwright route 레벨)
# 지정된 패턴에 대응하는 정규식으로 변환: 글로브 패턴이 URL 호스트 매칭에
# 부정확하므로 regex로 구현한다.
# =============================================================================
_INTERNAL_IP_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"https?://127\."),                             "127.x.x.x (루프백)"),
    (re.compile(r"https?://10\."),                              "10.x.x.x (사설망 A)"),
    (re.compile(r"https?://192\.168\."),                        "192.168.x.x (사설망 C)"),
    (re.compile(r"https?://172\.(1[6-9]|2[0-9]|3[01])\."),     "172.16-31.x.x (사설망 B)"),
]


# =============================================================================
# Docker 네트워크 헬퍼 (동기 — asyncio.to_thread 로 호출)
# =============================================================================

def _create_sandbox_network(client) -> object:
    """
    샌드박스 전용 격리 Docker 네트워크를 생성하고 반환한다.

    매 요청마다 UUID 기반 고유 이름으로 네트워크를 생성하여
    컨테이너 간 충돌 없이 독립된 환경을 보장한다.
    분석 완료 후 호출 측의 finally 블록에서 반드시 network.remove()로 삭제한다.

    Args:
        client: docker.DockerClient 인스턴스

    Returns:
        docker.models.networks.Network: 생성된 네트워크 객체
    """
    net_name = f"sandbox_net_{uuid4().hex[:8]}"
    network = client.networks.create(
        net_name,
        driver="bridge",
        # ICC 차단: 같은 브릿지 네트워크 내 다른 컨테이너끼리의 직접 통신 방지
        options={"com.docker.network.bridge.enable_icc": "false"},
        # internal=False: Chromium이 외부 인터넷(피싱 사이트)에는 접근 가능하도록 유지
        internal=False,
    )
    logger.info("[샌드박스] 격리 네트워크 생성: %s", net_name)
    return network


# =============================================================================
# Playwright 전용 분석 함수 (ProactorEventLoop 스레드에서 실행)
# =============================================================================

async def _playwright_analysis(url: str, ws_url: str) -> dict:
    """
    Playwright로 URL을 분석하고 탐지 결과와 스크린샷을 반환한다.
    이 함수는 반드시 ProactorEventLoop 위에서 실행해야 한다.

    Args:
        url: 분석 대상 URL
        ws_url: Browserless WebSocket 주소

    Returns:
        dict: findings, screenshot_initial, screenshot_after3s, error
    """
    findings: list[str] = []
    screenshot_initial: str | None = None
    screenshot_after3s: str | None = None
    error_msg: str | None = None

    try:
        async with async_playwright() as p:
            browser = await p.chromium.connect(ws_url)
            try:
                page = await browser.new_page()

                # ── Playwright 레벨 내부 IP 차단 ──────────────────────────
                # Docker 네트워크 수준 차단 외에 Playwright route()로 이중 차단.
                # 페이지 JS가 내부 IP로 fetch/XHR을 시도해도 여기서 가로챈다.
                async def _block_internal(route):
                    findings.append(
                        f"[경고] 내부 IP 접근 시도 차단됨: {route.request.url}"
                    )
                    await route.abort()

                for pattern, _ in _INTERNAL_IP_RULES:
                    # 각 내부 IP 대역에 대한 route 핸들러 등록
                    await page.route(pattern, _block_internal)

                # ── 자동 다운로드 이벤트 감지 ──────────────────────────────
                def _on_download(_download):
                    findings.append("[경고] 자동 다운로드 시도가 감지되었습니다.")

                page.on("download", _on_download)

                # ── 페이지 접속 ────────────────────────────────────────────
                try:
                    await page.goto(url, wait_until="domcontentloaded", timeout=20_000)
                except Exception as nav_err:
                    findings.append(f"[경고] 페이지 탐색 오류: {nav_err}")

                # ── 접속 직후 스크린샷 ─────────────────────────────────────
                try:
                    screenshot_initial = base64.b64encode(
                        await page.screenshot()
                    ).decode()
                except Exception as e:
                    findings.append(f"[경고] 초기 스크린샷 실패: {e}")

                # ── 개인정보 요구 input 폼 감지 ────────────────────────────
                try:
                    sensitive_inputs = await page.query_selector_all(
                        "input[type='password'], "
                        "input[name*='account'], input[name*='passwd'], "
                        "input[name*='jumin'], input[name*='card']"
                    )
                    if sensitive_inputs:
                        findings.append(
                            f"[경고] 개인정보 요구 input 폼이 {len(sensitive_inputs)}개 "
                            "감지되었습니다. (비밀번호·계좌·주민번호·카드번호 등)"
                        )
                except Exception as e:
                    findings.append(f"[경고] input 폼 분석 실패: {e}")

                # ── form action 외부 도메인 감지 ───────────────────────────
                try:
                    target_host = urlparse(url).netloc
                    forms = await page.query_selector_all("form[action]")
                    for form in forms:
                        action = await form.get_attribute("action") or ""
                        if action.startswith("http"):
                            action_host = urlparse(action).netloc
                            if action_host and action_host != target_host:
                                findings.append(
                                    f"[경고] form action이 외부 도메인으로 향합니다: {action_host}"
                                )
                except Exception as e:
                    findings.append(f"[경고] form action 분석 실패: {e}")

                # ── 3초 대기 후 스크린샷 ───────────────────────────────────
                await asyncio.sleep(3)
                try:
                    screenshot_after3s = base64.b64encode(
                        await page.screenshot()
                    ).decode()
                except Exception as e:
                    findings.append(f"[경고] 3초 후 스크린샷 실패: {e}")

            finally:
                # 예외 발생 여부와 무관하게 브라우저 반드시 종료
                await browser.close()

    except Exception as e:
        error_msg = str(e)
        findings.append(f"[오류] Playwright 분석 중 예외: {e}")
        logger.exception("[샌드박스] Playwright 분석 예외")

    return {
        "findings": findings,
        "screenshot_initial": screenshot_initial,
        "screenshot_after3s": screenshot_after3s,
        "error": error_msg,
    }


def _run_playwright_in_proactor_loop(url: str, ws_url: str) -> dict:
    """
    별도 스레드에서 ProactorEventLoop을 생성하여 Playwright를 실행한다.

    Windows uvicorn의 SelectorEventLoop는 subprocess를 지원하지 않으므로
    Playwright 전용 이벤트 루프를 이 함수 안에서 직접 생성한다.
    asyncio.to_thread()로 호출하면 별도 스레드에서 안전하게 실행된다.

    Args:
        url: 분석 대상 URL
        ws_url: Browserless WebSocket 주소

    Returns:
        _playwright_analysis()의 반환값과 동일한 dict
    """
    # Windows: ProactorEventLoop만 subprocess를 지원한다
    if sys.platform == "win32":
        loop = asyncio.ProactorEventLoop()
    else:
        loop = asyncio.new_event_loop()

    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_playwright_analysis(url, ws_url))
    except Exception as e:
        logger.exception("[샌드박스] ProactorEventLoop 실행 예외")
        return {
            "findings": [f"[오류] 샌드박스 이벤트 루프 실행 실패: {e}"],
            "screenshot_initial": None,
            "screenshot_after3s": None,
            "error": str(e),
        }
    finally:
        loop.close()


# =============================================================================
# 공개 인터페이스
# =============================================================================

async def run_sandbox_auto(url: str) -> dict:
    """
    지정된 URL을 격리된 Browserless 컨테이너에서 분석하고 결과를 반환한다.

    매 호출마다 새 컨테이너와 전용 네트워크를 생성하고 분석 완료 즉시 폐기한다.
    Docker 작업: asyncio.to_thread()로 이벤트 루프 차단 방지
    Playwright 작업: _run_playwright_in_proactor_loop()로 전용 스레드에서 실행

    보안:
    - 컨테이너 전용 격리 네트워크 (ICC 차단)
    - host.docker.internal → 0.0.0.0 덮어쓰기 (호스트 내부 접근 차단)
    - 파일 디스크립터 ulimit 제한 (리소스 남용 방지)
    - Playwright route()로 내부 IP 대역 이중 차단

    Args:
        url: 분석 대상 URL (http/https 스킴 필수)

    Returns:
        dict: {
            "url": str,
            "findings": List[str],
            "screenshot_initial": str | None,
            "screenshot_after3s": str | None,
            "error": str | None
        }
    """
    findings: list[str] = []
    screenshot_initial: str | None = None
    screenshot_after3s: str | None = None
    container = None
    network = None
    error_msg: str | None = None

    # ── 패키지 사용 가능 여부 확인 ────────────────────────────────────────────
    if not _PLAYWRIGHT_AVAILABLE:
        error_msg = (
            "playwright 패키지를 로드할 수 없습니다. "
            "Python 3.11/3.12에서 'pip install playwright' 후 "
            "'playwright install chromium'을 실행하세요."
        )
        return {
            "url": url,
            "findings": [f"[오류] {error_msg}"],
            "screenshot_initial": None,
            "screenshot_after3s": None,
            "error": error_msg,
        }
    if not _DOCKER_AVAILABLE:
        error_msg = "docker 패키지를 로드할 수 없습니다. 'pip install docker'를 실행하세요."
        return {
            "url": url,
            "findings": [f"[오류] {error_msg}"],
            "screenshot_initial": None,
            "screenshot_after3s": None,
            "error": error_msg,
        }

    # ── URL 스킴 검증 ─────────────────────────────────────────────────────────
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        error_msg = f"지원하지 않는 URL 스킴입니다: '{parsed.scheme}' (http/https만 허용)"
        return {
            "url": url,
            "findings": [f"[오류] {error_msg}"],
            "screenshot_initial": None,
            "screenshot_after3s": None,
            "error": error_msg,
        }

    # ── Docker 클라이언트 연결 ────────────────────────────────────────────────
    try:
        client = await asyncio.to_thread(docker.from_env)
    except Exception as e:
        error_msg = f"Docker 연결 실패 (Docker Desktop이 실행 중인지 확인): {e}"
        logger.error(error_msg)
        return {
            "url": url,
            "findings": [error_msg],
            "screenshot_initial": None,
            "screenshot_after3s": None,
            "error": error_msg,
        }

    try:
        # ── 격리 네트워크 생성 ────────────────────────────────────────────────
        network = await asyncio.to_thread(_create_sandbox_network, client)

        # ── 컨테이너 생성 ─────────────────────────────────────────────────────
        logger.info("[샌드박스] 컨테이너 생성 중: %s", BROWSERLESS_IMAGE)
        container = await asyncio.to_thread(
            client.containers.run,
            BROWSERLESS_IMAGE,
            detach=True,
            # remove=True: 컨테이너 종료 시 자동 삭제 — 수동 정리 불필요
            remove=True,
            # 랜덤 포트 할당: 고정 포트 사용 시 충돌 방지
            ports={"3000/tcp": None},
            environment={"TOKEN": "sandbox_token"},
            # 격리 네트워크 사용: 기본 bridge 대신 ICC가 차단된 전용 네트워크
            network=network.name,
            # host.docker.internal 차단: 컨테이너에서 호스트 내부 서비스 접근 방지
            extra_hosts={"host.docker.internal": "0.0.0.0"},
            # ulimit — nofile: 파일 디스크립터 상한 제한으로 리소스 고갈 공격 방지
            ulimits=[Ulimit(name="nofile", soft=1024, hard=1024)],
        )

        await asyncio.sleep(CONTAINER_READY_WAIT)

        # ── 포트 조회 ─────────────────────────────────────────────────────────
        await asyncio.to_thread(container.reload)
        port_bindings = container.ports.get("3000/tcp") or []
        host_port = port_bindings[0].get("HostPort") if port_bindings else None
        if not host_port:
            raise RuntimeError("컨테이너 포트 매핑을 읽을 수 없습니다.")

        ws_url = f"ws://localhost:{host_port}/chromium/playwright?token=sandbox_token"
        logger.info("[샌드박스] Playwright 연결: %s", ws_url)

        # ── Playwright 분석 (ProactorEventLoop 전용 스레드에서 실행) ─────────
        playwright_result = await asyncio.to_thread(
            _run_playwright_in_proactor_loop, url, ws_url
        )

        findings.extend(playwright_result["findings"])
        screenshot_initial = playwright_result["screenshot_initial"]
        screenshot_after3s = playwright_result["screenshot_after3s"]
        if playwright_result.get("error"):
            error_msg = playwright_result["error"]

    except Exception as e:
        error_msg = str(e)
        findings.append(f"[오류] 샌드박스 실행 중 예외 발생: {e}")
        logger.exception("[샌드박스] 예외 발생")
    finally:
        # 컨테이너 종료 (remove=True 이므로 stop 후 자동 삭제됨)
        if container is not None:
            try:
                await asyncio.to_thread(container.stop, timeout=5)
                logger.info("[샌드박스] 컨테이너 종료 완료")
            except Exception as stop_err:
                logger.warning("[샌드박스] 컨테이너 종료 실패: %s", stop_err)

        # 격리 네트워크 삭제 (컨테이너 종료 후 연결 해제 확인 후 삭제)
        if network is not None:
            try:
                await asyncio.to_thread(network.remove)
                logger.info("[샌드박스] 격리 네트워크 삭제 완료: %s", network.name)
            except Exception as net_err:
                logger.warning("[샌드박스] 네트워크 삭제 실패: %s", net_err)

    if not findings:
        findings.append("특이사항 없음 — 개인정보 요구 폼·외부 form·자동 다운로드 미감지")

    return {
        "url": url,
        "findings": findings,
        "screenshot_initial": screenshot_initial,
        "screenshot_after3s": screenshot_after3s,
        "error": error_msg,
    }
