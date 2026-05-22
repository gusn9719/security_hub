# =============================================================================
# backend/routers/sandbox.py
# 역할: 샌드박스 분석 엔드포인트. Docker 기반 Browserless 컨테이너를 통해
#       URL을 격리 실행하고 결과를 반환한다.
# =============================================================================

import asyncio
import base64
import logging
import re
from urllib.parse import urlparse, quote

import httpx
import websockets
from fastapi import APIRouter, HTTPException, Query, Request, WebSocket
from fastapi.responses import Response
from pydantic import BaseModel

from services.sandbox_service import run_sandbox_auto, run_auto_test
from services import browse_service
from services.browse_service import create_browse_session, terminate_browse_session
from schemas.analysis import SandboxAutoTestRequest, SandboxAutoTestResponse, VoteRequest, VoteResponse
from database.vote_service import save_vote
import config as _cfg

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sandbox", tags=["sandbox"])

# NF-28: 동시 세션 제한 — Semaphore로 최대 동시 실행 수 제어
# 초과 요청은 대기 없이 즉시 503으로 거부한다 (_value 체크 후 HTTPException).
_BROWSE_SEM = asyncio.Semaphore(4)   # 7-A 직접 탐방: 최대 4세션
_AUTO_SEM   = asyncio.Semaphore(3)   # 7-B AI 자동테스트: 최대 3세션


class SandboxRequest(BaseModel):
    """샌드박스 분석 요청 모델."""
    url: str


class BrowseCreateRequest(BaseModel):
    """kasmweb/chromium 직접 탐방 세션 생성 요청 모델 (Sprint 7-A)."""
    url: str
    screen_width: int = 1080
    screen_height: int = 1920


@router.post("/auto-test", response_model=SandboxAutoTestResponse)
async def auto_test(request: SandboxAutoTestRequest) -> SandboxAutoTestResponse:
    """
    URL을 격리 컨테이너에서 자동 분석하고 가짜 개인정보를 주입해 피싱 폼을 탐지한다.

    결과는 24시간 캐시된다. 컨테이너 기동 실패 시에도 score=0으로 정상 응답한다.
    NF-28: 동시 3세션 초과 시 503 + Retry-After: 30 반환.

    Args:
        request: SandboxAutoTestRequest — 분석할 URL

    Returns:
        SandboxAutoTestResponse: 점수, 탐지 항목, 스크린샷 등 포함
    """
    if _AUTO_SEM._value == 0:
        raise HTTPException(
            status_code=503,
            headers={"Retry-After": "30"},
            detail="현재 AI 자동 테스트 세션이 최대치(3)에 도달했습니다. 잠시 후 다시 시도해주세요.",
        )
    async with _AUTO_SEM:
        logger.info("[/sandbox/auto-test] 요청: %s (슬롯 잔여: %d)", request.url, _AUTO_SEM._value)
        result = await run_auto_test(request.url)
    logger.info(
        "[/sandbox/auto-test] 완료. score=%d, findings=%d건, cached=%s",
        result.get("sandbox_score", 0),
        len(result.get("findings", [])),
        result.get("cached", False),
    )
    return SandboxAutoTestResponse(**result)


@router.post("/votes", response_model=VoteResponse)
async def submit_vote(http_request: Request, request: VoteRequest) -> VoteResponse:
    """
    7-A 직접 탐방 세션 종료 후 사용자 위험도 투표를 저장한다.

    session_id(container_id)당 1회만 저장되며 중복 투표는 조용히 무시된다.

    Args:
        http_request: FastAPI Request — X-Device-UUID 헤더 추출용
        request:      VoteRequest — url, session_id, vote("safe"|"danger")

    Returns:
        VoteResponse: success 여부와 메시지
    """
    device_uuid = http_request.headers.get("X-Device-UUID", request.device_uuid)
    logger.info("[/sandbox/votes] 요청: url=%s vote=%s uuid=%s", request.url, request.vote, device_uuid[:8])
    saved = await asyncio.to_thread(
        save_vote, request.url, request.session_id, request.vote, device_uuid
    )
    if saved:
        logger.info("[/sandbox/votes] 저장 완료: session_id=%s", request.session_id)
        return VoteResponse(success=True, message="투표가 저장되었습니다.")
    return VoteResponse(success=False, message="이미 투표하셨거나 저장에 실패했습니다.")


@router.post("/run")
async def run_sandbox(request: SandboxRequest) -> dict:
    """
    URL을 격리된 Browserless 컨테이너에서 실행하고 탐지 결과를 반환한다.

    Args:
        request: SandboxRequest — 분석할 URL

    Returns:
        dict: findings(탐지 목록), screenshot_initial, screenshot_after3s, error
    """
    logger.info("[/sandbox/run] 요청: %s", request.url)
    result = await run_sandbox_auto(request.url)
    logger.info("[/sandbox/run] 완료. findings=%d건", len(result.get("findings", [])))
    return result


@router.post("/browse")
async def browse_create(http_request: Request, request: BrowseCreateRequest) -> dict:
    """
    kasmweb/chromium 컨테이너를 생성하고 noVNC URL을 반환한다.

    Flutter WebView에서 noVNC URL을 로드해 격리 Chromium을 원격 조종하는
    직접 탐방 모드의 진입 엔드포인트.

    Args:
        request: BrowseCreateRequest — Chromium이 처음 열 URL (http/https만 허용)

    Returns:
        dict: {"container_id": str, "novnc_url": str, "network_name": str}

    Raises:
        400: http/https 외 스킴
        503: Docker가 실행 중이지 않거나 컨테이너 생성 실패
    """
    parsed = urlparse(request.url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(
            status_code=400,
            detail=f"지원하지 않는 URL 스킴입니다: '{parsed.scheme}' (http/https만 허용)",
        )

    if not browse_service._DOCKER_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Docker를 사용할 수 없습니다. Docker Desktop이 실행 중인지 확인하세요.",
        )

    # NF-28: 동시 4세션 초과 시 즉시 503
    if _BROWSE_SEM._value == 0:
        raise HTTPException(
            status_code=503,
            headers={"Retry-After": "30"},
            detail="현재 직접 탐방 세션이 최대치(4)에 도달했습니다. 잠시 후 다시 시도해주세요.",
        )

    logger.info(
        "[/sandbox/browse POST] 요청: %s (해상도: %dx%d, 슬롯 잔여: %d)",
        request.url, request.screen_width, request.screen_height, _BROWSE_SEM._value,
    )
    async with _BROWSE_SEM:
        result = await create_browse_session(
            request.url, request.screen_width, request.screen_height,
        )

    if "error" in result:
        logger.error("[/sandbox/browse POST] 생성 실패: %s", result["error"])
        raise HTTPException(status_code=503, detail=result["error"])

    container_id = result["container_id"]
    # DC-27: per-session 비밀번호 (세션 생성 시 browse_service가 생성·저장)
    vnc_pw = browse_service._active_sessions[container_id]["vnc_pw"]

    # ── Cloudflare Tunnel / 리버스 프록시 대응 스킴·포트 감지 ─────────────────
    # 우선순위: 환경변수 BASE_URL > X-Forwarded-Proto 헤더 > FORCE_HTTPS 플래그 > 로컬 추론
    host_header = http_request.headers.get("host", "localhost:8000")
    forwarded_proto = http_request.headers.get("x-forwarded-proto", "")

    if _cfg.BASE_URL:
        # 환경변수로 외부 URL이 명시된 경우 (가장 신뢰할 수 있음)
        base_origin = _cfg.BASE_URL.rstrip("/")
        # 스킴 누락 시 https:// 자동 보완 (예: BASE_URL=xxxx.trycloudflare.com)
        if "://" not in base_origin:
            base_origin = "https://" + base_origin
        scheme = "https" if base_origin.startswith("https://") else "http"
        # host_header는 noVNC &host= 파라미터에 사용 — BASE_URL에서 추출
        host_header = base_origin.split("://", 1)[1].split("/")[0]
    elif forwarded_proto == "https" or _cfg.FORCE_HTTPS:
        # Cloudflare Tunnel: CF가 X-Forwarded-Proto: https 를 주입한다
        scheme = "https"
        base_origin = f"https://{host_header}"
    else:
        scheme = "http"
        base_origin = f"http://{host_header}"

    # 호스트:포트 안전 분리 (Cloudflare 도메인에는 포트가 없다)
    if ":" in host_header:
        server_host = host_header.split(":")[0]
        server_port = host_header.split(":")[1]
    else:
        server_host = host_header
        server_port = "443" if scheme == "https" else "80"

    # noVNC URL을 FastAPI 백엔드 경로로 조립한다.
    # Flutter → https://CF_DOMAIN/sandbox/browse/{id}/novnc/ → KasmVNC WS 프록시
    novnc_base = f"{base_origin}/sandbox/browse/{container_id}/novnc"

    # path= 에 WebSocket 경로를 직접 지정한다.
    novnc_ws_path = quote(f"sandbox/browse/{container_id}/novnc", safe="")
    encrypt = "1" if scheme == "https" else "0"
    novnc_url = (
        f"{novnc_base}/"
        f"?password={vnc_pw}&username={browse_service.VNC_USER}&autoconnect=1&reconnect=1"
        f"&resize=remote&quality=6&compression=2"
        f"&host={server_host}&port={server_port}&encrypt={encrypt}"
        f"&path={novnc_ws_path}"
    )

    logger.info(
        "[/sandbox/browse POST] 생성 완료: %s → %s", container_id[:12], novnc_url,
    )
    return {
        "container_id": container_id,
        "novnc_url": novnc_url,
        "network_name": result["network_name"],
    }


@router.delete("/browse/{container_id}")
async def browse_delete(
    container_id: str,
    network_name: str = Query(..., description="create_browse_session이 반환한 네트워크 이름"),
) -> dict:
    """
    container_id의 kasmweb/chromium 컨테이너를 종료하고 네트워크를 삭제한다.

    Flutter SandboxBrowseScreen의 dispose()에서 호출되어 컨테이너를 즉시 정리한다.

    Args:
        container_id: create_browse_session()이 반환한 컨테이너 ID (path param)
        network_name: create_browse_session()이 반환한 네트워크 이름 (query param)

    Returns:
        dict: {"success": true}
    """
    logger.info(
        "[/sandbox/browse DELETE] 요청: container=%s, network=%s",
        container_id[:12],
        network_name,
    )
    await terminate_browse_session(container_id, network_name)
    logger.info("[/sandbox/browse DELETE] 완료: %s", container_id[:12])
    return {"success": True}


# ---------------------------------------------------------------------------
# noVNC HTTP 프록시
# ---------------------------------------------------------------------------
# Flutter WebView가 http://SERVER:8000/sandbox/browse/{id}/novnc/... 를 요청하면
# 내부 SSL-strip 프록시(127.0.0.1:proxy_port)로 전달한다.
# 외부에 랜덤 포트를 열지 않으므로 방화벽에 8000 포트 하나만 허용하면 된다.
# ---------------------------------------------------------------------------

# hop-by-hop 헤더는 전달하지 않는다 (HTTP/1.1 RFC 2616 §13.5.1)
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
})


@router.get("/browse/{container_id}/novnc", include_in_schema=False)
@router.get("/browse/{container_id}/novnc/{path:path}", include_in_schema=False)
async def novnc_http_proxy(
    http_request: Request,
    container_id: str,
    path: str = "",
) -> Response:
    """
    Flutter WebView → FastAPI → 내부 SSL-strip 프록시 → kasmVNC

    noVNC 페이지(HTML/JS/CSS/이미지)를 내부 프록시에서 가져와 반환한다.
    WebSocket Upgrade 요청은 아래 novnc_ws_proxy 가 처리한다.

    [HTML 재작성]
    kasmVNC의 noVNC HTML은 절대경로(src="/app/ui.js", href="/css/...")로 리소스를
    참조한다. FastAPI가 /sandbox/browse/{id}/novnc/ 경로로 서빙하면 브라우저는
    절대경로를 http://SERVER:8000/app/ui.js 로 해석해 FastAPI 404 → JS 미로드가 된다.
    이를 막기 위해 HTML 응답 내 절대경로를 /sandbox/browse/{id}/novnc/ 기준으로
    재작성하고, fetch()/XHR 도 동일하게 패치한다.
    """
    session = browse_service._active_sessions.get(container_id)
    if not session:
        raise HTTPException(status_code=404, detail="세션이 존재하지 않거나 만료됐습니다.")

    proxy_port: int = session["proxy_port"]
    proxy_url = f"http://127.0.0.1:{proxy_port}/{path}"
    if http_request.url.query:
        proxy_url += f"?{http_request.url.query}"

    # 요청 헤더에서 hop-by-hop 및 Host 제거
    fwd_headers = {
        k: v for k, v in http_request.headers.items()
        if k.lower() not in _HOP_BY_HOP and k.lower() != "host"
    }

    try:
        async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
            proxy_resp = await client.request(
                method=http_request.method,
                url=proxy_url,
                headers=fwd_headers,
                content=await http_request.body(),
            )
    except httpx.ConnectError as e:
        logger.error("[novnc-http] 내부 프록시 연결 실패 (port=%d): %s", proxy_port, e)
        raise HTTPException(status_code=502, detail="내부 프록시에 연결할 수 없습니다.")

    # 응답 헤더에서 hop-by-hop 제거 + CSP 제거 (주입 스크립트 실행 허용)
    resp_headers = {
        k: v for k, v in proxy_resp.headers.items()
        if k.lower() not in _HOP_BY_HOP
        and k.lower() != "content-security-policy"
    }

    content = proxy_resp.content
    content_type = resp_headers.get("content-type", "")

    # HTML 응답: 절대경로 재작성 + fetch/XHR 패치 주입
    # kasmVNC noVNC HTML의 src="/" href="/" 등 절대경로를 프록시 경로로 변환한다.
    is_html = "text/html" in content_type
    if not is_html and content:
        stripped = content.lstrip()
        is_html = (
            stripped[:9].lower().startswith(b"<!doctype")
            or stripped[:5].lower().startswith(b"<html")
        )

    if is_html:
        novnc_prefix = f"/sandbox/browse/{container_id}/novnc".encode()

        # CSP 메타 태그 제거 — KasmVNC HTML에 포함된 CSP 메타 태그가 인라인 스크립트를
        # 차단하면 WS 재작성·fetch 패치 스크립트가 실행되지 않는다.
        # 응답 헤더의 CSP는 이미 제거했으므로 메타 태그도 함께 제거한다.
        content = re.sub(
            rb'(?i)<meta\s[^>]*http-equiv\s*=\s*["\']?content-security-policy["\']?[^>]*>',
            b"",
            content,
        )

        # src="/  href="/  action="/  data-src="/ 절대경로를 프록시 경로로 재작성
        for attr in (b"src", b"href", b"action", b"data-src"):
            for q in (b'"', b"'"):
                old = b" " + attr + b"=" + q + b"/"
                new = b" " + attr + b"=" + q + novnc_prefix + b"/"
                content = content.replace(old, new)

        # fetch() / XMLHttpRequest.open() 절대경로 재작성 패치
        # kasmVNC가 /api/statistics 등 절대경로 API를 동적으로 호출할 때 사용.
        # window.__shP2 플래그로 Flutter UserScript(AT_DOCUMENT_START)와 중복 패치 방지.
        _FETCH_XHR_PATCH = (
            b"<script>"
            b"(function(){"
            b"if(window.__shP2)return;window.__shP2=1;"
            b"var _pm=window.location.pathname.match(/(.*\\/novnc)/);"
            b"var _pb=_pm?_pm[1]:'';"
            b"if(!_pb)return;"
            b"var _f=window.fetch;"
            b"if(_f)window.fetch=function(u,i){"
            b"if(typeof u==='string'&&u[0]==='/'&&u[1]!=='/')u=_pb+u;"
            b"return _f.call(this,u,i);};"
            b"var _x=XMLHttpRequest.prototype.open;"
            b"XMLHttpRequest.prototype.open=function(m,u,a,us,p){"
            b"if(typeof u==='string'&&u[0]==='/'&&u[1]!=='/')u=_pb+u;"
            b"return _x.call(this,m,u,a,us,p);};"
            b"})();"
            b"</script>"
        )
        if b"</head>" in content:
            content = content.replace(b"</head>", _FETCH_XHR_PATCH + b"</head>", 1)
        elif b"<body" in content:
            content = content.replace(b"<body", _FETCH_XHR_PATCH + b"<body", 1)
        else:
            content = _FETCH_XHR_PATCH + content

        logger.info(
            "[novnc-http] HTML 절대경로 재작성 + fetch/XHR 패치 주입 (prefix=%s)",
            novnc_prefix.decode(),
        )

    return Response(
        content=content,
        status_code=proxy_resp.status_code,
        headers=resp_headers,
    )


# ---------------------------------------------------------------------------
# noVNC WebSocket 프록시
# ---------------------------------------------------------------------------

async def _novnc_ws_proxy(
    websocket: WebSocket,
    container_id: str,
    path: str = "",          # {path:path} 라우트에서 주입 — 값은 사용하지 않음
) -> None:
    """
    Flutter WebView WebSocket → FastAPI → KasmVNC SSL (직접 연결)

    [흐름]
    1. 클라이언트 Sec-WebSocket-Protocol 서브프로토콜 추출.
    2. KasmVNC SSL 포트에 직접 websockets.connect() 연결.
       - HTTP proxy를 경유하면 Host 헤더 불일치로 KasmVNC가 HTTP 200을 반환함.
       - 직접 연결 시 Authorization: Basic 헤더를 additional_headers로 주입.
    3. KasmVNC가 선택한 서브프로토콜로 클라이언트 accept().
    4. 양방향 메시지 릴레이.
    """
    session = browse_service._active_sessions.get(container_id)
    if not session:
        await websocket.close(code=1008, reason="session not found")
        return

    kasm_host_port: int = session["kasm_host_port"]
    # DC-27: per-session 인증 헤더 계산
    kasm_auth_b64 = base64.b64encode(
        f"{browse_service.VNC_USER}:{session['vnc_pw']}".encode()
    ).decode()

    proto_header = websocket.headers.get("sec-websocket-protocol", "")
    client_protocols = [p.strip() for p in proto_header.split(",") if p.strip()]

    logger.info(
        "[novnc-ws] 세션 %s 연결 시작 (kasm_port=%d, subprotocols=%s)",
        container_id[:12], kasm_host_port, client_protocols,
    )

    accepted = False
    try:
        async with websockets.connect(
            f"wss://127.0.0.1:{kasm_host_port}/",
            ssl=browse_service._PROXY_SSL_CTX,
            additional_headers={
                "Authorization": f"Basic {kasm_auth_b64}",
                "Origin": f"https://127.0.0.1:{kasm_host_port}",
            },
            subprotocols=client_protocols or None,
            open_timeout=15,
            ping_interval=30,   # Cloudflare Tunnel: 100초 WS 타임아웃 방어 (30초 핑)
            max_size=10 * 1024 * 1024,
        ) as proxy_ws:
            # kasmVNC 가 선택한 서브프로토콜로 클라이언트를 수락한다.
            # accept() 를 connect() 성공 후에 호출하므로 서브프로토콜이 항상 일치한다.
            await websocket.accept(subprotocol=proxy_ws.subprotocol)
            accepted = True
            logger.info(
                "[novnc-ws] 연결 성공 (kasm_port=%d, subprotocol=%s)",
                kasm_host_port, proxy_ws.subprotocol,
            )

            async def client_to_proxy() -> None:
                """Flutter WebView → 내부 프록시"""
                try:
                    async for msg in websocket.iter_bytes():
                        await proxy_ws.send(msg)
                except Exception:
                    pass

            async def proxy_to_client() -> None:
                """내부 프록시 → Flutter WebView"""
                try:
                    async for msg in proxy_ws:
                        if isinstance(msg, bytes):
                            await websocket.send_bytes(msg)
                        else:
                            await websocket.send_text(msg)
                except Exception:
                    pass

            await asyncio.gather(
                client_to_proxy(),
                proxy_to_client(),
                return_exceptions=True,
            )

    except (OSError, websockets.exceptions.WebSocketException) as e:
        logger.warning("[novnc-ws] KasmVNC 연결 실패 (kasm_port=%d): %s", kasm_host_port, e)
        if not accepted:
            # accept() 전에 실패 → 클라이언트에게 연결 거부를 알린다
            try:
                await websocket.accept()
            except Exception:
                pass
    finally:
        # accepted 여부에 관계없이 close() 시도 — 이미 닫혔으면 예외 무시
        try:
            await websocket.close()
        except Exception:
            pass
        logger.info("[novnc-ws] 세션 %s WebSocket 종료 (kasm_port=%d)", container_id[:12], kasm_host_port)


# FastAPI WebSocket 라우터는 데코레이터 중첩을 지원하지 않으므로 경로를 명시적으로 등록한다.
#
# noVNC 기본 경로 = "websockify" → WS 재작성 후 경로 2 에서 처리
# KasmVNC 일부 버전이 "/" 만 사용할 경우 → 경로 3 (trailing slash) 에서 처리
# 예비: 경로 1 (정확히 /novnc 끝나는 경우)
router.add_api_websocket_route(
    "/browse/{container_id}/novnc",
    _novnc_ws_proxy,
)
router.add_api_websocket_route(
    "/browse/{container_id}/novnc/{path:path}",   # /websockify, /core/... 등
    _novnc_ws_proxy,
)
# Starlette의 {path:path} 는 빈 문자열을 허용하지 않으므로
# trailing slash(path="") 케이스를 별도 등록한다.
router.add_api_websocket_route(
    "/browse/{container_id}/novnc/",
    _novnc_ws_proxy,
)
