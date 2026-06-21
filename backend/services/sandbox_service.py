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
from urllib.parse import urlparse
from uuid import uuid4

import datetime
import json
import socket
import time

from database.blacklist_service import compute_url_hash, normalize_url

logger = logging.getLogger(__name__)

BROWSERLESS_IMAGE = os.getenv("BROWSERLESS_IMAGE", "ghcr.io/browserless/chromium:latest")
CONTAINER_READY_WAIT = 3  # 컨테이너 시작 후 Playwright 연결 전 대기(초)

# 가짜 개인정보 주입 상수 — 실제 피싱 폼에 전송되는 값을 통제한다
FAKE_CREDS = {
    "name": "홍길동",
    "phone": "010-1234-5678",
    "email": "test@security-hub.local",
    "password": "Fake!P@ss0826",
    "id": "testhong2026",
    "birth": "19900101",
    "card": "0000-0000-0000-0000",
}

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

try:
    from services.gemini_service import gemini_service as _gemini_svc
    _GEMINI_AVAILABLE = True
except Exception as _gemini_err:
    _GEMINI_AVAILABLE = False
    _gemini_svc = None
    logger.warning("[샌드박스] gemini_service import 실패: %s", _gemini_err)


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
# 7-B 자동탐지 헬퍼 함수
# =============================================================================

def _wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    """TCP 연결 시도로 포트가 열릴 때까지 최대 timeout 초 대기한다."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except (OSError, ConnectionRefusedError):
            time.sleep(0.5)
    return False


def _wait_for_browserless_ready(host: str, port: int, token: str, timeout: float = 20.0) -> bool:
    """
    Browserless HTTP 엔드포인트가 실제로 응답할 때까지 대기한다.

    TCP 포트가 열린 직후에도 Browserless 내부 WebSocket 서버가 초기화되기까지
    수 초가 걸릴 수 있다. _wait_for_port 이후에 이 함수를 호출해
    'socket hang up' 오류를 방지한다.
    4xx 포함 HTTP 응답이 오면 WS 서버도 준비된 것으로 판단한다.
    """
    import urllib.request
    import urllib.error

    deadline = time.monotonic() + timeout
    url = f"http://{host}:{port}/?token={token}"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status < 500:
                    return True
        except urllib.error.HTTPError as e:
            if e.code < 500:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def get_latest_sandbox_score(url: str) -> int | None:
    """
    ANL-11: 이전 7-B 자동탐지 결과의 sandbox_score를 반환한다.

    url_hash로 sandbox_results에서 mode='7b' 행을 조회한다.
    만료 여부와 무관하게 가장 최근 점수를 반환한다 (이력 시그널 용도).
    레코드가 없거나 오류 시 None을 반환한다.

    Args:
        url: 조회 대상 URL

    Returns:
        sandbox_score (0~100) 또는 None
    """
    # P0-1: 블랙리스트와 동일한 정규화로 키를 만든다 (보고서 D-3).
    url_hash = compute_url_hash(normalize_url(url))
    try:
        from database.db_init import get_ro_connection
        with get_ro_connection() as conn:
            row = conn.execute(
                """
                SELECT sandbox_score FROM sandbox_results
                WHERE url_hash = ? AND mode = '7b'
                ORDER BY analyzed_at DESC
                LIMIT 1
                """,
                (url_hash,),
            ).fetchone()
            if row is not None:
                return row["sandbox_score"] or 0
    except Exception as e:
        logger.warning("[샌드박스] sandbox_score 조회 실패: %s", e)
    return None


def _check_sandbox_cache(url_hash: str) -> dict | None:
    """24시간 이내의 유효한 7b sandbox_results 캐시를 반환한다. 없으면 None."""
    try:
        from database.db_init import get_ro_connection
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat()
        with get_ro_connection() as conn:
            row = conn.execute(
                "SELECT * FROM sandbox_results WHERE url_hash = ? AND mode = '7b' AND expires_at > ? AND error IS NULL",
                (url_hash, now),
            ).fetchone()
            if row:
                return {
                    "session_id": row["session_id"] or "",
                    "url": row["url"],
                    "sandbox_score": row["sandbox_score"] or 0,
                    "findings": json.loads(row["findings"] or "[]"),
                    "summary": row["summary"] or "",
                    "screenshots": json.loads(row["screenshots"] or "[]"),
                    "final_url": row["final_url"] or row["url"],
                    "redirect_count": row["redirect_count"] or 0,
                    "error": row["error"],
                    "cached": True,
                }
    except Exception as e:
        logger.warning("[자동탐지 캐시] 조회 실패: %s", e)
    return None


def _save_sandbox_result(
    session_id: str,
    url_hash: str,
    url: str,
    sandbox_score: int,
    findings: list[str],
    summary: str,
    screenshots: list[str],
    final_url: str,
    redirect_count: int,
    error: str | None,
) -> None:
    """sandbox_results 테이블에 분석 결과를 저장한다 (TTL 24h)."""
    try:
        from database.db_init import get_rw_connection
        from services.url_validator import get_registered_domain
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        expires = now + datetime.timedelta(hours=24)
        domain = urlparse(url).hostname or ""
        registered_domain = get_registered_domain(url)
        with get_rw_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO sandbox_results
                    (url_hash, url, session_id, mode, domain, registered_domain,
                     sandbox_score, findings, summary,
                     screenshots, final_url, redirect_count, error,
                     analyzed_at, expires_at)
                VALUES (?, ?, ?, '7b', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    url_hash, url, session_id, domain, registered_domain,
                    sandbox_score,
                    json.dumps(findings, ensure_ascii=False),
                    summary,
                    json.dumps(screenshots, ensure_ascii=False),
                    final_url, redirect_count, error,
                    now.isoformat(), expires.isoformat(),
                ),
            )
    except Exception as e:
        logger.warning("[자동탐지 캐시] 저장 실패: %s", e)


async def _analyze_dom(page) -> dict:
    """
    Playwright page 객체의 DOM을 분석하고 indicators dict를 반환한다.

    redirect_count, auto_download는 caller가 이벤트 리스너로 별도 추적해 주입한다.
    """
    result: dict = {
        "form_with_password": False,
        "external_form_action": False,
        "redirect_count": 0,
        "clipboard_access": False,
        "auto_download": False,
        "form_fields": [],
        "final_url": page.url,
    }

    try:
        pw_inputs = await page.query_selector_all("input[type=password]")
        result["form_with_password"] = len(pw_inputs) > 0
    except Exception:
        pass

    try:
        all_inputs = await page.query_selector_all("input[type]")
        field_types: list[str] = []
        for inp in all_inputs:
            t = await inp.get_attribute("type")
            if t:
                field_types.append(t.lower())
        result["form_fields"] = field_types
    except Exception:
        pass

    try:
        target_host = urlparse(page.url).netloc
        forms = await page.query_selector_all("form[action]")
        for form in forms:
            action = await form.get_attribute("action") or ""
            if action.startswith("http"):
                action_host = urlparse(action).netloc
                if action_host and action_host != target_host:
                    result["external_form_action"] = True
                    break
    except Exception:
        pass

    try:
        result["clipboard_access"] = bool(
            await page.evaluate("() => !!window.__clipboardAccessed")
        )
    except Exception:
        pass

    result["final_url"] = page.url
    return result


async def _inject_fake_data(page, form_fields: list[str]) -> None:
    """
    HTML 네이티브 폼에 FAKE_CREDS를 주입하고 POST 전송을 page.route()로 차단한다.

    주입 대상: password, email, tel 전체 / text 첫 번째만.
    주입 실패는 조용히 무시해 서비스 중단을 방지한다.
    """
    async def _block_post(route):
        req = route.request
        if req.method == "POST" and req.resource_type in (
            "fetch", "xhr", "document", "other"
        ):
            await route.abort()
        else:
            await route.continue_()

    try:
        await page.route("**/*", _block_post)
    except Exception:
        pass

    seen_types: set[str] = set()
    first_text_done = False

    for field_type in form_fields:
        if field_type in seen_types:
            continue
        seen_types.add(field_type)

        try:
            if field_type == "password":
                for inp in await page.query_selector_all("input[type=password]"):
                    await inp.fill(FAKE_CREDS["password"])
            elif field_type == "email":
                for inp in await page.query_selector_all("input[type=email]"):
                    await inp.fill(FAKE_CREDS["email"])
            elif field_type == "tel":
                for inp in await page.query_selector_all("input[type=tel]"):
                    await inp.fill(FAKE_CREDS["phone"])
            elif field_type == "text" and not first_text_done:
                text_inputs = await page.query_selector_all("input[type=text]")
                if text_inputs:
                    await text_inputs[0].fill(FAKE_CREDS["name"])
                    first_text_done = True
        except Exception:
            pass


def _calc_score(indicators: dict) -> dict:
    """
    룰 기반으로 sandbox_score를 계산하고 findings 목록을 반환한다.
    Gemini 호출 없음. 최대값 100으로 클램프.
    """
    score = 0
    findings: list[str] = []

    if indicators.get("form_with_password"):
        score += 30
        findings.append("비밀번호 입력 폼 감지")
    if indicators.get("external_form_action"):
        score += 40
        findings.append("외부 도메인 폼 전송 감지")
    if indicators.get("auto_download"):
        score += 50
        findings.append("자동 다운로드 시도 감지")
    if indicators.get("redirect_count", 0) >= 3:
        score += 20
        findings.append(f"과도한 리다이렉트 감지 ({indicators['redirect_count']}회)")
    if indicators.get("clipboard_access"):
        score += 25
        findings.append("클립보드 접근 시도 감지")

    return {"score": min(score, 100), "findings": findings}


async def _auto_test_playwright_analysis(url: str, ws_url: str) -> dict:
    """
    Playwright로 URL을 방문하고 DOM 분석·가짜 데이터 주입을 수행한다.
    반드시 ProactorEventLoop 위에서 실행해야 한다.

    Returns:
        dict: screenshots, indicators, final_url, error
    """
    screenshots: list[str] = []
    indicators: dict = {}
    final_url = url
    error_msg: str | None = None

    try:
        async with async_playwright() as p:
            browser = await p.chromium.connect(ws_url)
            try:
                context = await browser.new_context(
                    user_agent=(
                        "Mozilla/5.0 (Linux; Android 14; Pixel 8) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/120.0.0.0 Mobile Safari/537.36"
                    ),
                    # Pixel 8 세로 해상도 — UA와 뷰포트를 일치시켜야
                    # 피싱 사이트가 모바일 레이아웃을 내려준다.
                    viewport={"width": 390, "height": 844},
                )

                auto_download_flag: list[bool] = [False]

                page = await context.new_page()

                # download 이벤트는 Page에서 발생한다 (BrowserContext가 아님).
                def _on_download(_):
                    auto_download_flag[0] = True

                page.on("download", _on_download)

                # Playwright 레벨 내부 IP 차단 (Docker 네트워크 수준 차단 외 이중 방어)
                async def _block_ssrf(route):
                    await route.abort()

                for _ssrf_pattern, _ in _INTERNAL_IP_RULES:
                    await page.route(_ssrf_pattern, _block_ssrf)

                redirect_counter: list[int] = [0]

                def _on_response(response):
                    if response.status in (301, 302, 303, 307, 308):
                        redirect_counter[0] += 1

                page.on("response", _on_response)

                # 헤드리스 탐지 우회 + 클립보드 접근 훅
                await page.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
                    Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3] });
                    window.__clipboardAccessed = false;
                    try {
                        var _origClipboard = navigator.clipboard;
                        if (_origClipboard) {
                            Object.defineProperty(navigator, 'clipboard', {
                                get: function() {
                                    window.__clipboardAccessed = true;
                                    return _origClipboard;
                                }
                            });
                        }
                    } catch(e) {}
                """)

                try:
                    await page.goto(url, timeout=20_000, wait_until="domcontentloaded")
                except Exception as nav_err:
                    error_msg = str(nav_err)

                # 스크린샷 #1 (초기 접속 직후)
                try:
                    screenshots.append(
                        base64.b64encode(await page.screenshot(type="jpeg")).decode()
                    )
                except Exception:
                    pass

                indicators = await _analyze_dom(page)
                indicators["redirect_count"] = redirect_counter[0]
                indicators["auto_download"] = auto_download_flag[0]

                if indicators.get("form_with_password"):
                    try:
                        await _inject_fake_data(page, indicators["form_fields"])
                    except Exception:
                        pass

                    # 스크린샷 #2 (데이터 주입 후)
                    try:
                        screenshots.append(
                            base64.b64encode(await page.screenshot(type="jpeg")).decode()
                        )
                    except Exception:
                        pass

                    # submit 버튼 클릭 시도
                    try:
                        submit = await page.query_selector(
                            "input[type=submit], button[type=submit], button"
                        )
                        if submit:
                            await submit.click(timeout=3_000)
                    except Exception:
                        pass

                    # 스크린샷 #3 (submit 시도 후)
                    try:
                        screenshots.append(
                            base64.b64encode(await page.screenshot(type="jpeg")).decode()
                        )
                    except Exception:
                        pass

                final_url = page.url

            finally:
                await browser.close()

    except Exception as e:
        error_msg = str(e)
        logger.exception("[자동탐지] Playwright 분석 예외")

    return {
        "screenshots": screenshots,
        "indicators": indicators,
        "final_url": final_url,
        "error": error_msg,
    }


def _run_auto_test_in_proactor_loop(url: str, ws_url: str) -> dict:
    """
    별도 스레드에서 ProactorEventLoop을 생성하여 _auto_test_playwright_analysis를 실행한다.

    Windows SelectorEventLoop는 subprocess를 지원하지 않으므로
    Playwright 전용 루프를 이 함수 안에서 직접 생성한다.
    asyncio.to_thread()로 호출한다.
    """
    if sys.platform == "win32":
        loop = asyncio.ProactorEventLoop()
    else:
        loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_auto_test_playwright_analysis(url, ws_url))
    except Exception as e:
        logger.exception("[자동탐지] ProactorEventLoop 실행 예외")
        return {
            "screenshots": [],
            "indicators": {},
            "final_url": url,
            "error": str(e),
        }
    finally:
        loop.close()


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
# (구) /sandbox/run 전용 Playwright 체인 — P0-5 에서 완전 제거됨.
#   - _playwright_analysis(), _run_playwright_in_proactor_loop(),
#     run_sandbox_auto() 3종은 ports={'3000/tcp': None} (모든 인터페이스 노출) +
#     하드코딩 토큰 "sandbox_token" 의 보안 결함을 보유했고, Flutter 어디서도
#     호출되지 않는 데드 코드였다 (보고서 audit #4 + L-2).
#   - 동일 기능은 7-B 전용 run_auto_test() + _auto_test_playwright_analysis()
#     체인이 127.0.0.1 바인딩·mem/cpu 제한·24h 캐시·DB 저장과 함께 제공한다.
# =============================================================================


# =============================================================================
# 공개 인터페이스
# =============================================================================

async def run_auto_test(url: str) -> dict:
    """
    7-B AI 자동탐지: URL을 격리 컨테이너에서 분석하고 가짜 개인정보를 주입해
    피싱 폼 여부를 탐지한다. 결과는 sandbox_results 테이블에 24h 캐시된다.

    반환 dict는 SandboxAutoTestResponse 스키마와 1:1 대응한다.
    예외를 밖으로 던지지 않는다 — 실패 시 score=0, error 필드에 메시지를 담아 반환.

    Args:
        url: 분석 대상 URL (http/https 스킴 필수)

    Returns:
        dict: session_id, url, sandbox_score, findings, summary,
              screenshots, final_url, redirect_count, error, cached
    """
    # P0-1: 블랙리스트와 동일한 정규화로 키를 만든다 (보고서 D-3).
    url_hash = compute_url_hash(normalize_url(url))
    session_id = uuid4().hex

    # 1. 24h 캐시 확인
    cached = _check_sandbox_cache(url_hash)
    if cached:
        logger.info("[자동탐지] 캐시 히트: %s", url)
        return cached

    def _err(msg: str) -> dict:
        return {
            "session_id": session_id,
            "url": url,
            "sandbox_score": 0,
            "findings": [f"[오류] {msg}"],
            "summary": "",
            "screenshots": [],
            "final_url": url,
            "redirect_count": 0,
            "error": msg,
            "cached": False,
        }

    # URL 스킴 검증을 패키지 가용성 체크보다 먼저 수행한다.
    # invalid 스킴은 패키지 설치 여부와 무관하게 거부해야 한다.
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return _err(f"지원하지 않는 URL 스킴: '{parsed.scheme}' (http/https만 허용)")

    if not _PLAYWRIGHT_AVAILABLE:
        return _err(
            "playwright 패키지 미설치 — "
            "'pip install playwright && playwright install chromium'"
        )
    if not _DOCKER_AVAILABLE:
        return _err("docker 패키지 미설치 — 'pip install docker'")

    try:
        client = await asyncio.to_thread(docker.from_env)
    except Exception as e:
        return _err(f"Docker 연결 실패 (Docker Desktop 실행 여부 확인): {e}")

    container = None
    network = None
    error_msg: str | None = None

    try:
        # 격리 네트워크 생성
        network = await asyncio.to_thread(_create_sandbox_network, client)

        # 2. 컨테이너 기동 (127.0.0.1 바인딩, 메모리 512m, CPU 0.5,
        #    Linux capabilities 전부 제거 + 권한 상승 차단 + 프로세스 수 제한)
        logger.info("[자동탐지] 컨테이너 기동 중: %s", BROWSERLESS_IMAGE)
        container = await asyncio.to_thread(
            client.containers.run,
            BROWSERLESS_IMAGE,
            detach=True,
            remove=True,
            ports={"3000/tcp": ("127.0.0.1", None)},
            environment={"TOKEN": "sandbox_token"},
            network=network.name,
            extra_hosts={"host.docker.internal": "0.0.0.0"},
            mem_limit="512m",
            nano_cpus=int(0.5 * 1e9),
            cap_drop=["ALL"],
            security_opt=["no-new-privileges"],
            pids_limit=128,
        )

        await asyncio.to_thread(container.reload)
        port_bindings = container.ports.get("3000/tcp") or []
        host_port = port_bindings[0].get("HostPort") if port_bindings else None
        if not host_port:
            raise RuntimeError("컨테이너 포트 매핑을 읽을 수 없습니다.")

        # TCP 연결 확인 (최대 10초)
        ready = await asyncio.to_thread(
            _wait_for_port, "127.0.0.1", int(host_port), 10.0
        )
        if not ready:
            raise RuntimeError(f"컨테이너 포트 {host_port} 응답 없음 (10초 초과)")

        # HTTP 엔드포인트 준비 확인 (최대 20초)
        # TCP 포트 오픈 후에도 Browserless WebSocket 서버가 초기화되기까지
        # 수 초가 필요하다. 이 단계를 건너뛰면 'socket hang up' 오류가 발생한다.
        ws_ready = await asyncio.to_thread(
            _wait_for_browserless_ready, "127.0.0.1", int(host_port), "sandbox_token", 20.0
        )
        if not ws_ready:
            raise RuntimeError(f"Browserless HTTP 서버 {host_port} 초기화 실패 (20초 초과)")

        # 127.0.0.1 명시: 포트가 IPv4 전용으로 바인딩돼 있으므로 localhost가
        # IPv6(::1)로 해석되면 연결이 실패할 수 있다.
        ws_url = f"ws://127.0.0.1:{host_port}/chromium/playwright?token=sandbox_token"
        logger.info("[자동탐지] Playwright 연결: %s", ws_url)

        # 3~9. Playwright 분석 (ProactorEventLoop 전용 스레드에서 실행)
        pw_result = await asyncio.to_thread(
            _run_auto_test_in_proactor_loop, url, ws_url
        )

        if pw_result.get("error"):
            error_msg = pw_result["error"]

        indicators = pw_result.get("indicators", {})
        screenshots = pw_result.get("screenshots", [])
        final_url = pw_result.get("final_url", url)

        # 9. 룰 기반 스코어 계산
        score_result = _calc_score(indicators)
        sandbox_score = score_result["score"]
        findings = score_result["findings"]

        # 10. Gemini 요약 (findings 있을 때만, 실패 시 폴백)
        if findings:
            if _GEMINI_AVAILABLE and _gemini_svc is not None:
                try:
                    summary = _gemini_svc.generate_findings_summary(url, findings)
                except Exception:
                    summary = "탐지된 위험 요소: " + ", ".join(findings)
            else:
                summary = "탐지된 위험 요소: " + ", ".join(findings)
        else:
            summary = "탐지된 위험 요소 없음"

        redirect_count = indicators.get("redirect_count", 0)

        # 11. DB 저장
        await asyncio.to_thread(
            _save_sandbox_result,
            session_id, url_hash, url, sandbox_score, findings,
            summary, screenshots, final_url, redirect_count, error_msg,
        )

        return {
            "session_id": session_id,
            "url": url,
            "sandbox_score": sandbox_score,
            "findings": findings,
            "summary": summary,
            "screenshots": screenshots,
            "final_url": final_url,
            "redirect_count": redirect_count,
            "error": error_msg,
            "cached": False,
        }

    except Exception as e:
        error_msg = str(e)
        logger.exception("[자동탐지] 예외 발생")
        return {
            "session_id": session_id,
            "url": url,
            "sandbox_score": 0,
            "findings": [f"[오류] {e}"],
            "summary": "",
            "screenshots": [],
            "final_url": url,
            "redirect_count": 0,
            "error": error_msg,
            "cached": False,
        }
    finally:
        # 12. 컨테이너 반드시 종료
        if container is not None:
            try:
                await asyncio.to_thread(container.stop, timeout=5)
                logger.info("[자동탐지] 컨테이너 종료 완료")
            except Exception as stop_err:
                logger.warning("[자동탐지] 컨테이너 종료 실패: %s", stop_err)
        if network is not None:
            try:
                await asyncio.to_thread(network.remove)
                logger.info("[자동탐지] 격리 네트워크 삭제 완료")
            except Exception as net_err:
                logger.warning("[자동탐지] 네트워크 삭제 실패: %s", net_err)
