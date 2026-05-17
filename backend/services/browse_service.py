# =============================================================================
# backend/services/browse_service.py
# 역할: kasmweb/chromium 컨테이너를 생성해 KasmVNC로 격리 Chromium 화면을 스트리밍한다.
#       Flutter WebView는 noVNC URL을 로드해 사용자가 원격 조종하는 직접 탐방 모드를 제공.
#
# [아키텍처: HTTP-aware SSL-strip 프록시]
# kasmweb은 6901(HTTPS)만 사용하며 HTTP Basic Auth(kasm_user:VNC_PW)로 보호된다.
# Android WebView의 WSS SSL 우회 한계와 HTTP 401 처리를 동시에 해결하기 위해
# 백엔드에서 HTTP-aware TCP 프록시를 운영한다:
#
#   Flutter → http://10.0.2.2:PROXY_PORT  (plain HTTP, no SSL, no auth)
#          → Python HTTP-aware proxy
#            - 첫 HTTP 요청 헤더에 Authorization: Basic kasm_user:VNC_PW 주입
#            - 이후 순수 TCP 릴레이 (WebSocket upgrade 포함)
#          → https://127.0.0.1:CONTAINER_PORT  (kasmweb HTTPS, Basic Auth 충족)
# =============================================================================

import asyncio
import base64
import logging
import socket
import ssl
from uuid import uuid4

logger = logging.getLogger(__name__)

BROWSE_IMAGE = "kasmweb/chromium:1.14.0"
BROWSE_PORT = "6901/tcp"
PORT_READY_TIMEOUT = 120
PORT_POLL_INTERVAL = 1
VNC_USER = "kasm_user"
# VNC_PW는 세션별 uuid4().hex 로 생성된다 (DC-27).
# 이 파일에 고정값을 두지 않는다.

# 활성 세션: container_id → {container, network, timeout_task, proxy_task, vnc_pw}
_active_sessions: dict[str, dict] = {}

# SSL-strip 프록시용 컨텍스트 — 자체서명 인증서를 무조건 수락
_PROXY_SSL_CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_PROXY_SSL_CTX.check_hostname = False
_PROXY_SSL_CTX.verify_mode = ssl.CERT_NONE
try:
    # KasmVNC 1.14.0은 레거시 암호 스위트를 사용할 수 있으므로 SECLEVEL=1로 완화
    _PROXY_SSL_CTX.set_ciphers("DEFAULT@SECLEVEL=1")
except ssl.SSLError:
    pass

try:
    import docker
    _DOCKER_AVAILABLE = True
except Exception as _docker_err:
    _DOCKER_AVAILABLE = False
    logger.warning("[browse] docker 패키지 import 실패: %s", _docker_err)


# ---------------------------------------------------------------------------
# HTTP-aware TCP 프록시
# ---------------------------------------------------------------------------

# noVNC JS가 wss://host:kasmPort/ 로 직접 연결을 시도하면 SSL 인증서 오류로 실패한다.
# HTML 응답에 이 스크립트를 주입해 모든 WebSocket URL을 프록시(window.location.host)로 재작성한다.
# flutter_inappwebview userScript의 타이밍 불확실성을 우회하기 위해 서버사이드에서 주입한다.
_WS_PROXY_INJECT = (
    b"<script>"
    b"(function(){"
    b"if(window.WebSocket&&window.WebSocket.__shP)return;"
    b"var _W=window.WebSocket;"
    b"var _pm=window.location.pathname.match(/(.*\\/novnc)/);"
    b"var _pb=_pm?_pm[1]:'';"
    b"var b=window.location.protocol.replace('http','ws')+'//'+window.location.host+_pb;"
    b"window.WebSocket=new Proxy(_W,{"
    b"construct:function(t,a){"
    b"if(typeof a[0]==='string'){"
    # _pb를 이미 포함한 URL(path= 파라미터로 직접 설정된 경우)은 재작성하지 않는다.
    # 그 외 절대경로(stats WebSocket 등)는 백엔드 경로로 재작성한다.
    b"if(_pb&&a[0].indexOf(_pb)!==-1){"
    b"console.log('[SH] WS skip(ok):'+a[0]);"
    b"}else{"
    b"var o=a[0];"
    b"a[0]=a[0].replace(/^wss?:\\/\\/[^\\/]*/,b);"
    b"if(o!==a[0])console.log('[SH] WS rewrite:'+o+' -> '+a[0]);"
    b"else console.log('[SH] WS: '+a[0]);"
    b"}"
    b"}"
    b"return Reflect.construct(t,a);"
    b"}"
    b"});"
    b"window.WebSocket.__shP=1;"
    b"})();"
    b"</script>"
)

# JS 버전 — webpack 번들 파일 앞에 선삽입해 KasmVNC 코드가 window.WebSocket을 캡처하기 전에 패치한다.
# KasmVNC가 <head> 내 <script> 태그로 번들을 로드할 경우 HTML 주입보다 먼저 실행된다.
# __shP 플래그로 여러 번들 파일에 걸쳐 중복 패치를 방지한다.
_WS_PROXY_JS = (
    b";(function(){"
    b"if(window.WebSocket&&window.WebSocket.__shP)return;"
    b"var _W=window.WebSocket;"
    b"if(!_W)return;"
    b"var _pm=window.location.pathname.match(/(.*\\/novnc)/);"
    b"var _pb=_pm?_pm[1]:'';"
    b"var b=window.location.protocol.replace('http','ws')+'//'+window.location.host+_pb;"
    b"window.WebSocket=new Proxy(_W,{"
    b"construct:function(t,a){"
    b"if(typeof a[0]==='string'){"
    b"if(_pb&&a[0].indexOf(_pb)!==-1){"
    b"console.log('[SH] WS skip(ok):'+a[0]);"
    b"}else{"
    b"var o=a[0];"
    b"a[0]=a[0].replace(/^wss?:\\/\\/[^\\/]*/,b);"
    b"if(o!==a[0])console.log('[SH] WS rewrite:'+o+' -> '+a[0]);"
    b"else console.log('[SH] WS: '+a[0]);"
    b"}"
    b"}"
    b"return Reflect.construct(t,a);"
    b"}"
    b"});"
    b"window.WebSocket.__shP=1;"
    b"})();\n"
)

def _decode_chunked(data: bytes) -> bytes:
    """HTTP/1.1 chunked transfer encoding 디코드."""
    result = b""
    pos = 0
    try:
        while pos < len(data):
            crlf = data.find(b"\r\n", pos)
            if crlf == -1:
                break
            size = int(data[pos:crlf].split(b";")[0].strip(), 16)
            if size == 0:
                break
            chunk_start = crlf + 2
            result += data[chunk_start:chunk_start + size]
            pos = chunk_start + size + 2
    except (ValueError, IndexError):
        return data
    return result if result else data


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


async def _wait_for_host_port(host_port: int, timeout: int = 30) -> bool:
    """
    Docker port-binding이 호스트에서 SSL 수준으로 접속 가능해질 때까지 대기한다.
    평문 TCP로 테스트하면 KasmVNC가 비SSL 연결을 받고 RST로 응답해 이후 SSL 연결을
    ConnectionRefusedError로 만드는 부작용이 있으므로 반드시 SSL로 연결해야 한다.
    """
    deadline = asyncio.get_running_loop().time() + timeout
    attempt = 0
    while asyncio.get_running_loop().time() < deadline:
        attempt += 1
        writer: asyncio.StreamWriter | None = None
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    "127.0.0.1", host_port,
                    ssl=_PROXY_SSL_CTX,
                    server_hostname="localhost",
                ),
                timeout=5.0,
            )
            # SSL 연결을 정상 종료해 KasmVNC가 깨끗한 상태로 다음 연결을 받도록 한다.
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=3.0)
            except Exception:
                pass
            logger.info("[browse] 호스트측 포트 %d SSL 접속 확인 (시도 %d)", host_port, attempt)
            # KasmVNC가 연결 정리를 완료할 시간을 준다
            await asyncio.sleep(1.0)
            return True
        except Exception as e:
            logger.debug(
                "[browse] 호스트측 포트 %d SSL 대기 중 (시도 %d) — %s: %s",
                host_port, attempt, type(e).__name__, e,
            )
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass
            await asyncio.sleep(1.0)
    logger.warning("[browse] 호스트측 포트 %d SSL 접속 불가 (%d초)", host_port, timeout)
    return False


async def _relay(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    """단방향 바이트 스트림 중계."""
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def _proxy_handle(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    target_host: str,
    target_port: int,
    auth_header: bytes,
) -> None:
    """
    HTTP 요청 헤더를 읽어 Authorization을 주입한 뒤 kasmweb으로 전달하고
    이후 양방향 TCP 릴레이로 전환한다 (WebSocket upgrade도 동일하게 처리).
    auth_header: b"Authorization: Basic <base64>" 형식의 per-session 인증 헤더
    """
    # HTTP 헤더 끝(CRLFCRLF)까지 수집
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            chunk = await asyncio.wait_for(reader.read(8192), timeout=30.0)
            if not chunk:
                break
            buf += chunk
    except Exception as e:
        logger.debug("[proxy] 헤더 읽기 실패: %s", e)
        try:
            writer.close()
        except Exception:
            pass
        return

    if b"\r\n\r\n" not in buf:
        try:
            writer.close()
        except Exception:
            pass
        return

    sep = buf.index(b"\r\n\r\n")
    headers_raw = buf[:sep]
    body_tail = buf[sep + 4:]

    headers_lower = headers_raw.lower()
    is_websocket = b"upgrade: websocket" in headers_lower

    req_line = headers_raw.split(b"\r\n")[0].decode(errors="replace")
    logger.info("[proxy] %s | ws=%s", req_line[:100], is_websocket)

    # Authorization 주입 (중복 방지) — per-session auth_header 사용
    if b"authorization:" not in headers_lower:
        headers_raw += b"\r\n" + auth_header.rstrip(b"\r\n")

    if not is_websocket:
        # 일반 HTTP 요청 헤더 정규화:
        # 1. Connection: close — 1요청/1연결 강제, kasmweb이 응답 후 SSL 연결 종료
        # 2. Accept-Encoding: identity — gzip/br 비활성화
        #    (압축 시 Content-Length=압축크기인데 Chromium이 압축해제 후 크기와 비교해
        #    ERR_CONTENT_LENGTH_MISMATCH가 발생하는 경우 차단)
        req_lines = headers_raw.split(b"\r\n")
        req_lines = [l for l in req_lines
                     if not l.lower().startswith(b"connection:")
                     and not l.lower().startswith(b"keep-alive:")
                     and not l.lower().startswith(b"accept-encoding:")]
        req_lines.append(b"Connection: close")
        req_lines.append(b"Accept-Encoding: identity")
        headers_raw = b"\r\n".join(req_lines)

    # SSL 연결 재시도: KasmVNC의 SSL 준비 완료 타이밍 차이를 흡수하기 위해 재시도한다.
    _RETRIES = 10
    remote_r = remote_w = None
    last_exc: Exception | None = None
    for attempt in range(_RETRIES):
        try:
            remote_r, remote_w = await asyncio.wait_for(
                asyncio.open_connection(
                    target_host,
                    target_port,
                    ssl=_PROXY_SSL_CTX,
                    server_hostname="localhost",
                ),
                timeout=10.0,
            )
            break
        except Exception as e:
            last_exc = e
            logger.debug(
                "[proxy] 연결 시도 %d/%d 실패 %s:%d — %s: %s",
                attempt + 1, _RETRIES, target_host, target_port, type(e).__name__, e,
            )
            if attempt < _RETRIES - 1:
                await asyncio.sleep(2.0)

    if remote_w is None:
        logger.warning(
            "[proxy] 대상 연결 최종 실패 %s:%d — %s: %s",
            target_host, target_port,
            type(last_exc).__name__ if last_exc else "Unknown",
            repr(last_exc),
        )
        # ERR_EMPTY_RESPONSE 방지: HTTP 502 응답을 보내 클라이언트에 오류 원인 전달
        try:
            body = b"KasmVNC connection failed (502)"
            writer.write(
                b"HTTP/1.1 502 Bad Gateway\r\n"
                b"Content-Type: text/plain; charset=utf-8\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + body
            )
            await writer.drain()
        except Exception:
            pass
        try:
            writer.close()
        except Exception:
            pass
        return

    remote_w.write(headers_raw + b"\r\n\r\n" + body_tail)
    await remote_w.drain()

    if is_websocket:
        # WebSocket: 양방향 릴레이 (업그레이드 이후 무한 스트림)
        await asyncio.gather(
            _relay(reader, remote_w),
            _relay(remote_r, writer),
            return_exceptions=True,
        )
    else:
        # 일반 HTTP: 전체 응답을 버퍼에 수신한 뒤 Connection: close 방식으로 전달한다.
        # Content-Length 재계산 방식은 SSL 종료 타이밍 차이로 ERR_CONTENT_LENGTH_MISMATCH가
        # 여전히 발생하므로, Content-Length 없이 연결 종료로 응답 끝을 알린다.
        # 클라이언트(WebView)는 Connection: close 시 FIN 수신 시점을 응답 완료로 인식한다.
        resp_buf = b""
        try:
            while True:
                chunk = await asyncio.wait_for(remote_r.read(65536), timeout=60.0)
                if not chunk:
                    break
                resp_buf += chunk
        except Exception:
            pass

        if b"\r\n\r\n" in resp_buf:
            resp_sep = resp_buf.index(b"\r\n\r\n")
            resp_headers_raw = resp_buf[:resp_sep]
            resp_body = resp_buf[resp_sep + 4:]

            resp_lines = resp_headers_raw.split(b"\r\n")
            is_chunked = any(
                b"chunked" in l.lower()
                for l in resp_lines
                if l.lower().startswith(b"transfer-encoding:")
            )
            if is_chunked:
                resp_body = _decode_chunked(resp_body)

            resp_lines = [
                l for l in resp_lines
                if not l.lower().startswith(b"content-encoding:")
                and not l.lower().startswith(b"transfer-encoding:")
                and not l.lower().startswith(b"content-length:")
                and not l.lower().startswith(b"connection:")
            ]
            resp_lines.append(b"Connection: close")

            # HTML/JS 응답에 WebSocket URL 재작성 스크립트를 주입한다.
            # JS 번들 선삽입: KasmVNC가 <head> 내 <script>로 번들을 로드할 때
            # HTML </head> 주입보다 먼저 실행되도록 JS 파일 앞에도 패치를 삽입한다.
            req_path_only = (
                req_line.split(" ")[1].split("?")[0].lower()
                if " " in req_line else ""
            )

            is_html = any(
                b"text/html" in l.lower()
                for l in resp_lines
                if l.lower().startswith(b"content-type:")
            )
            if not is_html:
                is_html = resp_body.lstrip()[:15].lower().startswith((b"<!doctype", b"<html"))

            is_js = any(
                b"javascript" in l.lower()
                for l in resp_lines
                if l.lower().startswith(b"content-type:")
            ) or req_path_only.endswith(".js")

            if is_html:
                if b"</head>" in resp_body:
                    resp_body = resp_body.replace(b"</head>", _WS_PROXY_INJECT + b"</head>", 1)
                elif b"<body" in resp_body:
                    resp_body = resp_body.replace(b"<body", _WS_PROXY_INJECT + b"<body", 1)
                else:
                    resp_body = _WS_PROXY_INJECT + resp_body
                logger.info("[proxy] HTML WS 패치 주입 완료 (%d bytes)", len(_WS_PROXY_INJECT))
            elif is_js:
                resp_body = _WS_PROXY_JS + resp_body
                logger.info("[proxy] JS WS 패치 주입 — %s", req_path_only[-60:])
            else:
                logger.debug("[proxy] HTML/JS 아님 — WS 패치 생략")

            resp_headers_raw = b"\r\n".join(resp_lines)
            writer.write(resp_headers_raw + b"\r\n\r\n" + resp_body)
        else:
            writer.write(resp_buf)

        try:
            await writer.drain()
        except Exception:
            pass
        try:
            remote_w.close()
        except Exception:
            pass
        # 명시적 FIN 전송: drain 후 writer를 닫아 클라이언트가 응답 완료를 인식하게 한다.
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=5.0)
        except Exception:
            pass


async def _run_proxy_server(
    server: asyncio.Server,
    proxy_port: int,
    target_port: int,
) -> None:
    # async with server 를 쓰면 CancelledError 시 wait_closed()가 호출돼
    # 기존 TCP 연결이 살아있는 한 영원히 블록된다.
    # server.close()만 호출하고 wait_closed()는 생략해 즉시 반환한다.
    try:
        await server.serve_forever()
    except asyncio.CancelledError:
        pass
    finally:
        server.close()
        logger.info("[proxy] 프록시 종료: 127.0.0.1:%d → 127.0.0.1:%d", proxy_port, target_port)


async def _start_ssl_strip_proxy(target_port: int, vnc_pw: str) -> tuple[int, asyncio.Task]:
    proxy_port = _find_free_port()
    # per-session 인증 헤더 — DC-27
    session_auth_header = (
        b"Authorization: Basic "
        + base64.b64encode(f"{VNC_USER}:{vnc_pw}".encode())
        + b"\r\n"
    )

    async def _handle(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await _proxy_handle(r, w, "127.0.0.1", target_port, session_auth_header)

    # 외부에서 직접 접근 불가: 127.0.0.1 전용 바인딩.
    # Flutter는 FastAPI /sandbox/browse/{id}/novnc 를 통해 간접 접속한다.
    server = await asyncio.start_server(_handle, "127.0.0.1", proxy_port)
    task = asyncio.create_task(_run_proxy_server(server, proxy_port, target_port))
    logger.info(
        "[proxy] HTTP-aware 프록시 시작: 127.0.0.1:%d → 127.0.0.1:%d (Auth 주입: kasm_user:***)",
        proxy_port,
        target_port,
    )
    return proxy_port, task


# ---------------------------------------------------------------------------
# 컨테이너 헬스체크
# ---------------------------------------------------------------------------

async def _wait_for_http_ready(
    host_port: str,
    container=None,
    timeout: int = PORT_READY_TIMEOUT,
    vnc_pw: str = "",
) -> bool:
    """
    컨테이너 내부 curl로 KasmVNC 응답을 확인한다.
    401도 서버가 동작 중임을 의미하므로 준비 완료로 판정한다.
    """
    if container is None:
        logger.warning("[browse] 컨테이너 없음 — 헬스체크 스킵")
        return False

    deadline = asyncio.get_running_loop().time() + timeout
    attempt = 0

    while asyncio.get_running_loop().time() < deadline:
        attempt += 1

        if attempt == 1:
            try:
                diag = await asyncio.to_thread(
                    container.exec_run,
                    ["bash", "-c", "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"],
                )
                logger.info(
                    "[browse-diag] 리스닝 포트:\n%s",
                    (diag.output or b"").decode(errors="replace"),
                )
            except Exception:
                pass

        for port, scheme in ((6901, "https"), (6902, "http")):
            try:
                result = await asyncio.to_thread(
                    container.exec_run,
                    [
                        "curl", "-s", "-k",
                        "-o", "/dev/null",
                        "-w", "%{http_code}",
                        f"{scheme}://localhost:{port}/",
                        "--max-time", "5",
                    ],
                )
                code = (result.output or b"").strip()
                if code and code != b"000":
                    logger.info(
                        "[browse] KasmVNC 응답: %s://localhost:%d/ → HTTP %s (시도 %d)",
                        scheme, port, code.decode(errors="replace"), attempt,
                    )

                    # 인증 자격증명 진단 — kasm_user:vnc_pw 로 200이 오는지 확인
                    if code == b"401" and vnc_pw:
                        for uname in (VNC_USER, "user", ""):
                            try:
                                auth_result = await asyncio.to_thread(
                                    container.exec_run,
                                    [
                                        "curl", "-s", "-k",
                                        "-u", f"{uname}:{vnc_pw}",
                                        "-o", "/dev/null",
                                        "-w", "%{http_code}",
                                        f"{scheme}://localhost:{port}/",
                                        "--max-time", "5",
                                    ],
                                )
                                auth_code = (auth_result.output or b"").strip()
                                logger.info(
                                    "[browse-auth-diag] curl -u '%s:***' → HTTP %s",
                                    uname,
                                    auth_code.decode(errors="replace"),
                                )
                                if auth_code == b"200":
                                    logger.info("[browse-auth-diag] 유효 자격증명: username='%s'", uname)
                                    break
                            except Exception as diag_e:
                                logger.debug("[browse-auth-diag] 실패: %s", diag_e)

                    await asyncio.sleep(5)
                    return True
            except Exception as e:
                logger.debug("[browse] curl 실패 (시도 %d, %s:%d): %s", attempt, scheme, port, e)

        if attempt % 10 == 0:
            logger.info("[browse] 대기 중 (시도 %d / 최대 %ds)", attempt, timeout)

        await asyncio.sleep(PORT_POLL_INTERVAL)

    logger.warning("[browse] KasmVNC 타임아웃: 포트 %s (%d초)", host_port, timeout)
    try:
        logs = await asyncio.to_thread(container.logs, tail=40)
        logger.error("[browse] 컨테이너 로그:\n%s", logs.decode(errors="replace"))
    except Exception as log_err:
        logger.error("[browse] 로그 읽기 실패: %s", log_err)
    return False


# ---------------------------------------------------------------------------
# 네트워크·세션 관리
# ---------------------------------------------------------------------------

def _create_browse_network(client) -> object:
    net_name = f"browse_net_{uuid4().hex[:8]}"
    network = client.networks.create(
        net_name,
        driver="bridge",
        options={"com.docker.network.bridge.enable_icc": "false"},
        internal=False,
    )
    logger.info("[browse] 격리 네트워크 생성: %s", net_name)
    return network


async def _auto_terminate(container_id: str, network_name: str) -> None:
    await asyncio.sleep(300)
    await terminate_browse_session(container_id, network_name)
    logger.info("[browse] 세션 타임아웃 자동 종료: container=%s", container_id[:12])


async def create_browse_session(
    url: str,
    screen_width: int = 1080,
    screen_height: int = 1920,
) -> dict:
    """
    kasmweb/chromium 컨테이너를 생성하고 내부 프록시 포트를 반환한다.
    noVNC URL은 라우터(sandbox.py)가 백엔드 경로로 조립한다.

    Returns:
        dict: {"container_id": str, "proxy_port": int, "network_name": str}
              실패 시: {"error": str}
    """
    if not _DOCKER_AVAILABLE:
        return {"error": "docker 패키지를 로드할 수 없습니다. 'pip install docker'를 실행하세요."}

    container = None
    network = None

    try:
        client = await asyncio.to_thread(docker.from_env)
    except Exception as e:
        return {"error": f"Docker 연결 실패 (Docker Desktop이 실행 중인지 확인): {e}"}

    # DC-27: 세션별 랜덤 VNC 비밀번호 생성
    vnc_pw = uuid4().hex

    try:
        network = await asyncio.to_thread(_create_browse_network, client)

        resolution = f"{screen_width}x{screen_height}"
        logger.info("[browse] 컨테이너 생성 중: %s → %s (해상도: %s)", BROWSE_IMAGE, url, resolution)
        container = await asyncio.to_thread(
            client.containers.run,
            BROWSE_IMAGE,
            detach=True,
            remove=True,
            ports={BROWSE_PORT: None},
            environment={
                "VNC_PW": vnc_pw,  # DC-27: per-session
                "LAUNCH_URL": url,
                "RESOLUTION": resolution,
                # --kiosk: 탭·주소창·메뉴 등 브라우저 UI 완전 제거.
                # kasmweb/chromium 이미지 시작 스크립트가 CHROMIUM_FLAGS를
                # Chromium 실행 인수로 전달한다.
                "CHROMIUM_FLAGS": "--kiosk --no-first-run --disable-infobars",
                "KASM_CHROME_FLAGS": "--kiosk --no-first-run --disable-infobars",
            },
            shm_size="512m",
            network=network.name,
            extra_hosts={"host.docker.internal": "0.0.0.0"},
        )

        await asyncio.sleep(2)
        await asyncio.to_thread(container.reload)
        port_bindings = container.ports.get(BROWSE_PORT) or []
        host_port = port_bindings[0].get("HostPort") if port_bindings else None
        if not host_port:
            raise RuntimeError("컨테이너 포트 매핑을 읽을 수 없습니다.")

        ready = await _wait_for_http_ready(host_port, container=container, vnc_pw=vnc_pw)
        if not ready:
            raise RuntimeError(
                f"kasmweb 포트 {host_port}가 {PORT_READY_TIMEOUT}초 내에 응답하지 않았습니다."
            )

        # 컨테이너 내부 포트가 준비됐어도 Docker port-binding이 호스트에서
        # 즉시 접속 가능하지 않을 수 있다. 프록시 시작 전에 TCP 수준 연결 확인.
        await _wait_for_host_port(int(host_port))

        # ------------------------------------------------------------------
        # Chromium kiosk 모드 재시작
        # CHROMIUM_FLAGS 환경변수가 kasmweb/chromium:1.14.0에서 무시되므로
        # 실행 중인 Chromium 브라우저 프로세스만 종료하고 --kiosk 플래그로 재시작한다.
        #
        # [주의] pkill -f chrom을 쓰면 Xvnc(포트 6901 서버)까지 종료된다.
        # Xvnc의 실행 인자에 "chrom" 문자열이 포함되어 -f chrom에 매칭되기 때문이다.
        # Xvnc가 죽으면 컨테이너가 종료(remove=True)되어 포트 바인딩이 사라진다.
        # 반드시 ss로 Xvnc PID를 식별하고 kill 대상에서 제외해야 한다.
        # ------------------------------------------------------------------
        try:
            kiosk_script = (
                # 포트 6901을 소유한 Xvnc PID 식별 — 이 PID는 절대 종료 금지
                "XVNC_PID=$(ss -tlnp 2>/dev/null | grep ':6901'"
                " | grep -oP 'pid=\\K[0-9]+' | head -1); "
                # Xvnc를 제외한 Chromium 브라우저 프로세스가 뜰 때까지 최대 20초 대기
                "for i in $(seq 1 20); do "
                "  CPID=$(pgrep -f chrom 2>/dev/null"
                "    | grep -v \"^${XVNC_PID}$\" | head -1); "
                "  if [ -n \"$CPID\" ]; then "
                "    BIN=$(command -v chromium-browser 2>/dev/null"
                "      || command -v chromium 2>/dev/null"
                "      || command -v google-chrome 2>/dev/null"
                "      || readlink -f /proc/$CPID/exe 2>/dev/null); "
                "    echo \"kiosk restart: xvnc=$XVNC_PID bin=$BIN\"; "
                # Xvnc를 제외한 chrom 관련 프로세스만 종료
                "    for p in $(pgrep -f chrom 2>/dev/null); do "
                "      [ \"$p\" != \"$XVNC_PID\" ] && kill -9 \"$p\" 2>/dev/null; "
                "    done; "
                "    sleep 1; "
                "    DISPLAY=:1 \"$BIN\" --kiosk --no-first-run --disable-infobars "
                "      --noerrdialogs --disable-translate \"$KIOSK_URL\" &>/dev/null & "
                "    echo done; break; "
                "  fi; "
                "  sleep 1; "
                "done"
            )
            kiosk_result = await asyncio.to_thread(
                container.exec_run,
                ["bash", "-c", kiosk_script],
                environment={"KIOSK_URL": url},
            )
            logger.info(
                "[browse] kiosk 재시작: %s",
                (kiosk_result.output or b"").decode(errors="replace").strip() or "(출력 없음)",
            )
        except Exception as kiosk_e:
            logger.debug("[browse] kiosk 재시작 실패 (무시): %s", kiosk_e)

        kasm_host_port = int(host_port)
        proxy_port, proxy_task = await _start_ssl_strip_proxy(kasm_host_port, vnc_pw)

        container_id = container.id
        timeout_task = asyncio.create_task(_auto_terminate(container_id, network.name))
        _active_sessions[container_id] = {
            "container": container,
            "network": network,
            "timeout_task": timeout_task,
            "proxy_task": proxy_task,
            "proxy_port": proxy_port,
            # WebSocket 직접 연결용: Docker 포트 바인딩 호스트 포트
            "kasm_host_port": kasm_host_port,
            # DC-27: per-session VNC 비밀번호 (sandbox.py에서 novnc_url 구성에 사용)
            "vnc_pw": vnc_pw,
        }

        logger.info(
            "[browse] 세션 생성 완료: container=%s, 내부 proxy=127.0.0.1:%d, kasm_port=%d",
            container_id[:12], proxy_port, kasm_host_port,
        )
        return {
            "container_id": container_id,
            "proxy_port": proxy_port,
            "network_name": network.name,
        }

    except Exception as e:
        logger.exception("[browse] 세션 생성 실패")
        if container is not None:
            try:
                await asyncio.to_thread(container.stop, timeout=5)
            except Exception:
                pass
        if network is not None:
            try:
                await asyncio.to_thread(network.remove)
            except Exception:
                pass
        return {"error": str(e)}


async def terminate_browse_session(container_id: str, network_name: str) -> None:
    session = _active_sessions.pop(container_id, None)

    if session:
        for key in ("timeout_task", "proxy_task"):
            t = session.get(key)
            if t and not t.done():
                t.cancel()
        container = session.get("container")
    else:
        container = None
        if _DOCKER_AVAILABLE:
            try:
                client = await asyncio.to_thread(docker.from_env)
                container = await asyncio.to_thread(client.containers.get, container_id)
            except Exception:
                pass

    if container is not None:
        try:
            await asyncio.to_thread(container.stop, timeout=5)
            logger.info("[browse] 컨테이너 종료: %s", container_id[:12])
        except Exception as e:
            logger.warning("[browse] 컨테이너 종료 실패: %s", e)

    if _DOCKER_AVAILABLE:
        try:
            client = await asyncio.to_thread(docker.from_env)
            net = await asyncio.to_thread(client.networks.get, network_name)
            await asyncio.to_thread(net.remove)
            logger.info("[browse] 네트워크 삭제: %s", network_name)
        except Exception as e:
            logger.warning("[browse] 네트워크 삭제 실패: %s", e)


async def shutdown_all_sessions() -> None:
    """서버 종료 시 모든 활성 browse 세션을 일괄 정리한다.

    lifespan 종료 훅에서 호출한다. proxy_task·timeout_task를 취소하고
    Docker 컨테이너와 네트워크를 제거해 고아 리소스가 남지 않도록 한다.
    """
    if not _active_sessions:
        return

    logger.info("[browse] 서버 종료 — 활성 세션 %d개 정리 중", len(_active_sessions))
    for container_id, session in list(_active_sessions.items()):
        for key in ("timeout_task", "proxy_task"):
            t = session.get(key)
            if t and not t.done():
                t.cancel()

        container = session.get("container")
        if container is not None:
            try:
                await asyncio.to_thread(container.stop, timeout=3)
            except Exception as e:
                logger.warning("[browse] 종료 중 컨테이너 stop 실패 (%s): %s", container_id[:12], e)

        network = session.get("network")
        if network is not None:
            try:
                await asyncio.to_thread(network.remove)
            except Exception as e:
                logger.warning("[browse] 종료 중 네트워크 remove 실패: %s", e)

    _active_sessions.clear()
    logger.info("[browse] 모든 세션 정리 완료")
