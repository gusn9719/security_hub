# =============================================================================
# backend/services/browse_service.py
# 역할: kasmweb/chromium 컨테이너를 관리해 KasmVNC로 격리 Chromium 화면을 스트리밍한다.
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
#
# [풀 아키텍처: Pre-warm Container Pool]
# 서버 시작 시 POOL_SIZE(=2)개의 컨테이너를 미리 생성해 대기시킨다.
# 사용자 요청 시 즉시 할당(pool hit) → URL 리다이렉트만 수행 → <5초 응답.
# 풀 소진 시 온디맨드 생성(pool miss)으로 폴백한다.
# 할당 후 백그라운드에서 자동 보충한다.
# =============================================================================

import asyncio
import base64
import logging
import socket
import ssl
import threading
from uuid import uuid4

logger = logging.getLogger(__name__)

BROWSE_IMAGE = "kasmweb/chromium:1.14.0"
BROWSE_PORT = "6901/tcp"
PORT_READY_TIMEOUT = 120
PORT_POLL_INTERVAL = 1
VNC_USER = "kasm_user"

# ---------------------------------------------------------------------------
# 풀 설정
# ---------------------------------------------------------------------------

POOL_SIZE = 2              # 상시 대기 컨테이너 수
_POOL_PLACEHOLDER_URL = "about:blank"  # 워밍 시 Chromium에 열어두는 초기 URL

_pool_idle: asyncio.Queue = asyncio.Queue()
# asyncio 단일 스레드: await 없이 증감하므로 별도 락 불필요
_pool_warming: int = 0

# DC-34: CDP 실시간 이벤트 모니터링 스크립트.
# container.exec_run() 으로 컨테이너 내부에서 실행된다.
# localhost:9222 (loopback) 에 직접 접속하므로 --remote-debugging-address 불필요.
# 이벤트 발생 시 stdout 에 한 줄씩 출력한다:
#   CDP_READY                         — 연결 성공
#   CDP_NO_TABS / CDP_HANDSHAKE_FAIL  — 실패
#   NAVIGATE:{url}                    — 메인 프레임 탐색
#   DOWNLOAD:{url}:{filename}         — 다운로드 시도
_CDP_MONITOR_PY = (
    "import json,socket,base64,os,sys,struct,time\n"
    # tty=True 모드에서 출력이 즉시 전달되는지 확인하는 진단 라인
    "print('EXEC_STARTED',flush=True)\n"
    "import urllib.request as _ur\n"
    # CDP 준비 대기 (최대 30초) — 풀 컨테이너는 이미 CDP 준비됨, kill 후 재시작 시 대기 필요
    "ws_url='';dl=time.time()+30\n"
    "while time.time()<dl:\n"
    "    try:\n"
    "        d=json.loads(_ur.urlopen('http://localhost:9222/json/list',timeout=2).read())\n"
    "        for t in (d or []):\n"
    "            if t.get('webSocketDebuggerUrl'):\n"
    "                ws_url=t['webSocketDebuggerUrl'];break\n"
    "        if ws_url:break\n"
    "    except:pass\n"
    "    time.sleep(2)\n"
    "if not ws_url:print('CDP_NO_TABS',flush=True);sys.exit(1)\n"
    # WebSocket 경로 추출
    "idx=ws_url.find('/',ws_url.find('//')+2)\n"
    "path=ws_url[idx:] if idx>=0 else '/'\n"
    # WebSocket 핸드셰이크 — recv 루프에 명시적 타임아웃 추가
    "try:\n"
    "    s=socket.create_connection(('localhost',9222),timeout=10)\n"
    "    s.settimeout(10)\n"
    "    key=base64.b64encode(os.urandom(16)).decode()\n"
    "    hs=(b'GET '+path.encode()+b' HTTP/1.1\\r\\n'\n"
    "        b'Host: localhost:9222\\r\\n'\n"
    "        b'Upgrade: websocket\\r\\n'\n"
    "        b'Connection: Upgrade\\r\\n'\n"
    "        b'Origin: http://localhost:9222\\r\\n'\n"
    "        b'Sec-WebSocket-Key: '+key.encode()+b'\\r\\n'\n"
    "        b'Sec-WebSocket-Version: 13\\r\\n\\r\\n')\n"
    "    s.sendall(hs)\n"
    "    buf=b''\n"
    "    while b'\\r\\n\\r\\n' not in buf:\n"
    "        c=s.recv(4096)\n"
    "        if not c:raise RuntimeError('closed')\n"
    "        buf+=c\n"
    "    if b'101' not in buf:print('CDP_HANDSHAKE_FAIL',flush=True);sys.exit(1)\n"
    "except Exception as e:print('CDP_CONNECT_ERROR:'+str(e),flush=True);sys.exit(1)\n"
    "print('CDP_READY',flush=True)\n"
    # WebSocket 프레임 전송 헬퍼 (마스킹 포함)
    "def send(cid,m,p=None):\n"
    "    msg=json.dumps({'id':cid,'method':m,'params':p or{}}).encode()\n"
    "    mk=os.urandom(4);n=len(msg)\n"
    "    if n<126:h=bytes([0x81,0x80|n])+mk\n"
    "    elif n<65536:h=bytes([0x81,0xFE])+struct.pack('>H',n)+mk\n"
    "    else:h=bytes([0x81,0xFF])+struct.pack('>Q',n)+mk\n"
    "    s.sendall(h+bytes(x^mk[i%4]for i,x in enumerate(msg)))\n"
    # WebSocket 프레임 수신 헬퍼
    "def recvn(n):\n"
    "    d=b''\n"
    "    while len(d)<n:\n"
    "        c=s.recv(n-len(d))\n"
    "        if not c:raise ConnectionError\n"
    "        d+=c\n"
    "    return d\n"
    "def readframe():\n"
    "    h=recvn(2);op=h[0]&0xF;msk=(h[1]&0x80)!=0;n=h[1]&0x7F\n"
    "    if n==126:n=struct.unpack('>H',recvn(2))[0]\n"
    "    elif n==127:n=struct.unpack('>Q',recvn(8))[0]\n"
    "    mk=recvn(4) if msk else b''\n"
    "    p=recvn(n)\n"
    "    return op,(bytes(b^mk[i%4]for i,b in enumerate(p)) if msk else p)\n"
    # Page 이벤트 활성화 + 다운로드 이벤트 활성화
    # behavior='deny'는 일부 kasmweb Chromium에서 페이지 로딩을 막는 버그가 있음.
    # 'allow'로 다운로드를 허용하되 downloadPath를 /tmp로 지정해 이벤트만 수신한다.
    # (컨테이너는 임시이므로 /tmp에 파일이 저장돼도 무방함)
    "send(1,'Page.enable')\n"
    "send(2,'Page.setDownloadBehavior',{'behavior':'allow','downloadPath':'/tmp'})\n"
    "print('CDP_SETUP_DONE',flush=True)\n"
    # 이벤트 루프
    "s.settimeout(60)\n"
    "while True:\n"
    "    try:op,pl=readframe()\n"
    "    except socket.timeout:s.sendall(bytes([0x89,0x80])+os.urandom(4));continue\n"
    "    except:break\n"
    "    if op==8:break\n"
    "    if op==9:s.sendall(bytes([0x8A,0x80])+os.urandom(4));continue\n"
    "    if op not in(1,2):continue\n"
    "    try:ev=json.loads(pl)\n"
    "    except:continue\n"
    "    mth=ev.get('method','')\n"
    "    if mth=='Page.frameNavigated':\n"
    "        fr=ev.get('params',{}).get('frame',{})\n"
    "        if 'parentId' not in fr:\n"
    "            url=fr.get('url','')\n"
    "            if url and not url.startswith(('about:','chrome:','data:')):\n"
    "                print('NAVIGATE:'+url,flush=True)\n"
    "    elif mth=='Page.downloadWillBegin':\n"
    "        p2=ev.get('params',{})\n"
    "        print('DOWNLOAD:'+p2.get('url','')+':'+p2.get('suggestedFilename',''),flush=True)\n"
)

# CDP(Chrome DevTools Protocol) Page.navigate 스크립트.
# 컨테이너 내부에서 python3 -c 로 실행된다.
# Chromium이 --remote-debugging-port=9222 로 기동된 경우에만 작동.
_CDP_NAVIGATE_PY = (
    "import json,socket,base64,os,struct\n"
    "import urllib.request as _r\n"
    "u=os.environ['KIOSK_URL']\n"
    "try:\n"
    "    d=json.loads(_r.urlopen('http://localhost:9222/json/list',timeout=2).read())\n"
    "    if not d:raise RuntimeError('no tabs')\n"
    "    ws=d[0]['webSocketDebuggerUrl']\n"
    # ws://127.0.0.1:9222/path 또는 ws://localhost:9222/path → /path 만 추출
    "    idx=ws.find('/',ws.find('//')+2);p=ws[idx:] if idx>=0 else '/'\n"
    "    s=socket.create_connection(('localhost',9222),timeout=5)\n"
    "    k=base64.b64encode(os.urandom(16)).decode()\n"
    # Origin 헤더 필수: 없으면 Chromium이 HTTP 403 Forbidden 반환 → WS upgrade 실패
    "    hs=('GET '+p+' HTTP/1.1\\r\\n'\n"
    "        'Host: localhost:9222\\r\\n'\n"
    "        'Upgrade: websocket\\r\\n'\n"
    "        'Connection: Upgrade\\r\\n'\n"
    "        'Origin: http://localhost:9222\\r\\n'\n"
    "        'Sec-WebSocket-Key: '+k+'\\r\\n'\n"
    "        'Sec-WebSocket-Version: 13\\r\\n'\n"
    "        '\\r\\n')\n"
    "    s.sendall(hs.encode())\n"
    "    b=b'';s.settimeout(5)\n"
    "    while b'\\r\\n\\r\\n' not in b:\n"
    "        chunk=s.recv(4096)\n"
    "        if not chunk:raise RuntimeError('WS handshake closed')\n"
    "        b+=chunk\n"
    # 101 Switching Protocols 확인: 없으면 403 등 거부 응답 → cdp_fail 로 처리
    "    if b'101' not in b:raise RuntimeError('WS rejected:'+b[:80].decode(errors='replace'))\n"
    "    m=json.dumps({'id':1,'method':'Page.navigate','params':{'url':u}}).encode()\n"
    "    mk=os.urandom(4);n=len(m)\n"
    "    if n<126:h=bytes([0x81,0x80|n])+mk\n"
    "    elif n<65536:h=bytes([0x81,0xFE])+struct.pack('>H',n)+mk\n"
    "    else:h=bytes([0x81,0xFF])+struct.pack('>Q',n)+mk\n"
    "    s.sendall(h+bytes(x^mk[i%4]for i,x in enumerate(m)))\n"
    "    s.settimeout(3)\n"
    "    try:s.recv(512)\n"
    "    except:pass\n"
    "    s.close();print('cdp_ok')\n"
    "except Exception as e:\n"
    "    print('cdp_fail:'+str(e));raise SystemExit(1)\n"
)

# ---------------------------------------------------------------------------
# 활성 세션
# ---------------------------------------------------------------------------

# 활성 세션: container_id → {container, network, timeout_task, proxy_task, vnc_pw, ...}
_active_sessions: dict[str, dict] = {}

# DC-34: 위협 자동 차단 캐시. watchdog이 위협 감지 후 세션 종료 시 여기에 기록하고,
# Flutter 상태 폴링이 조회한다. 5분 TTL로 자동 정리된다.
_threat_cache: dict[str, dict] = {}

# ---------------------------------------------------------------------------
# SSL-strip 프록시용 컨텍스트
# ---------------------------------------------------------------------------

_PROXY_SSL_CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_PROXY_SSL_CTX.check_hostname = False
_PROXY_SSL_CTX.verify_mode = ssl.CERT_NONE
try:
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
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=3.0)
            except Exception:
                pass
            logger.info("[browse] 호스트측 포트 %d SSL 접속 확인 (시도 %d)", host_port, attempt)
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

    if b"authorization:" not in headers_lower:
        headers_raw += b"\r\n" + auth_header.rstrip(b"\r\n")

    if not is_websocket:
        req_lines = headers_raw.split(b"\r\n")
        req_lines = [l for l in req_lines
                     if not l.lower().startswith(b"connection:")
                     and not l.lower().startswith(b"keep-alive:")
                     and not l.lower().startswith(b"accept-encoding:")]
        req_lines.append(b"Connection: close")
        req_lines.append(b"Accept-Encoding: identity")
        headers_raw = b"\r\n".join(req_lines)

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
        await asyncio.gather(
            _relay(reader, remote_w),
            _relay(remote_r, writer),
            return_exceptions=True,
        )
    else:
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
    try:
        await server.serve_forever()
    except asyncio.CancelledError:
        pass
    finally:
        server.close()
        logger.info("[proxy] 프록시 종료: 127.0.0.1:%d → 127.0.0.1:%d", proxy_port, target_port)


async def _start_ssl_strip_proxy(target_port: int, vnc_pw: str) -> tuple[int, asyncio.Task]:
    proxy_port = _find_free_port()
    session_auth_header = (
        b"Authorization: Basic "
        + base64.b64encode(f"{VNC_USER}:{vnc_pw}".encode())
        + b"\r\n"
    )

    async def _handle(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await _proxy_handle(r, w, "127.0.0.1", target_port, session_auth_header)

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
# 네트워크 관리
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


_CDP_SCREENSHOT_PY = (
    "import json,socket,base64,os,struct\n"
    "import urllib.request as _r\n"
    "try:\n"
    "    d=json.loads(_r.urlopen('http://localhost:9222/json/list',timeout=2).read())\n"
    "    pg=[t for t in(d or[])if t.get('type')=='page'and t.get('webSocketDebuggerUrl')]\n"
    "    if not pg:raise RuntimeError('no page')\n"
    "    ws=pg[0]['webSocketDebuggerUrl']\n"
    "    idx=ws.find('/',ws.find('//')+2);p=ws[idx:]if idx>=0 else'/'\n"
    "    s=socket.create_connection(('localhost',9222),timeout=5)\n"
    "    k=base64.b64encode(os.urandom(16)).decode()\n"
    "    hs=('GET '+p+' HTTP/1.1\\r\\nHost: localhost:9222\\r\\nUpgrade: websocket\\r\\n'\n"
    "        'Connection: Upgrade\\r\\nOrigin: http://localhost:9222\\r\\n'\n"
    "        'Sec-WebSocket-Key: '+k+'\\r\\nSec-WebSocket-Version: 13\\r\\n\\r\\n')\n"
    "    s.sendall(hs.encode())\n"
    "    b=b'';s.settimeout(5)\n"
    "    while b'\\r\\n\\r\\n'not in b:\n"
    "        c=s.recv(4096)\n"
    "        if not c:raise RuntimeError('closed')\n"
    "        b+=c\n"
    "    if b'101'not in b:raise RuntimeError('rejected')\n"
    "    m=json.dumps({'id':1,'method':'Page.captureScreenshot',\n"
    "        'params':{'format':'jpeg','quality':50}}).encode()\n"
    "    mk=os.urandom(4);n=len(m)\n"
    "    if n<126:hh=bytes([0x81,0x80|n])+mk\n"
    "    elif n<65536:hh=bytes([0x81,0xFE])+struct.pack('>H',n)+mk\n"
    "    else:hh=bytes([0x81,0xFF])+struct.pack('>Q',n)+mk\n"
    "    s.sendall(hh+bytes(x^mk[i%4]for i,x in enumerate(m)))\n"
    "    def recvn(x):\n"
    "        d=b''\n"
    "        while len(d)<x:\n"
    "            c=s.recv(x-len(d))\n"
    "            if not c:raise ConnectionError\n"
    "            d+=c\n"
    "        return d\n"
    "    s.settimeout(30)\n"
    "    while True:\n"
    "        h2=recvn(2);op=h2[0]&0xF;n2=h2[1]&0x7F\n"
    "        if n2==126:n2=struct.unpack('>H',recvn(2))[0]\n"
    "        elif n2==127:n2=struct.unpack('>Q',recvn(8))[0]\n"
    "        p2=recvn(n2)\n"
    "        if op not in(1,2):continue\n"
    "        ev=json.loads(p2)\n"
    "        if ev.get('id')==1:\n"
    "            img=ev.get('result',{}).get('data','')\n"
    "            if img:print('SCREENSHOT:'+img,flush=True)\n"
    "            break\n"
    "    s.close()\n"
    "except Exception as e:print('SCREENSHOT_ERROR:'+str(e),flush=True)\n"
)


async def _take_cdp_screenshot(container) -> str | None:
    """차단 직전 피싱 사이트 화면을 JPEG base64로 캡처한다."""
    if container is None:
        return None
    try:
        result = await asyncio.to_thread(
            container.exec_run,
            ["python3", "-c", _CDP_SCREENSHOT_PY],
        )
        for line in (result.output or b"").decode(errors="replace").splitlines():
            line = line.strip()
            if line.startswith("SCREENSHOT:"):
                logger.info("[browse] 스크린샷 캡처 완료")
                return line[len("SCREENSHOT:"):]
            if line.startswith("SCREENSHOT_ERROR:"):
                logger.debug("[browse] 스크린샷 오류: %s", line)
    except Exception as e:
        logger.debug("[browse] 스크린샷 실패: %s", e)
    return None


async def _wait_for_cdp_ready(container, timeout_sec: int = 20) -> bool:
    """
    컨테이너 내 CDP 포트(9222)가 HTTP 요청에 응답할 때까지 대기한다.

    kill+restart 로 Chromium 을 재시작한 직후 포트가 아직 열리지 않은 상태에서
    풀에 추가하면, 다음 pool hit 시 CDP 가 실패해 watchdog 레이스가 재발한다.
    이 함수로 포트 준비를 확인한 뒤 풀에 추가한다.

    curl 은 kasmweb 이미지에 내장되어 있으므로 python3 없이도 사용 가능.
    """
    check_script = (
        "curl -s http://localhost:9222/json/version "
        "-m 1 -o /dev/null -w '%{http_code}' 2>/dev/null"
    )
    deadline = asyncio.get_event_loop().time() + timeout_sec
    attempt = 0
    while asyncio.get_event_loop().time() < deadline:
        attempt += 1
        try:
            result = await asyncio.to_thread(
                container.exec_run,
                ["bash", "-c", check_script],
            )
            code = (result.output or b"").decode(errors="replace").strip()
            if code == "200":
                logger.info("[pool] CDP 포트(9222) 준비 완료 (시도 %d)", attempt)
                return True
        except Exception as e:
            logger.debug("[pool] CDP 대기 중 오류 (시도 %d): %s", attempt, e)
        await asyncio.sleep(1)
    logger.warning("[pool] CDP 포트(9222) 준비 타임아웃 (%d초)", timeout_sec)
    return False


# ---------------------------------------------------------------------------
# 풀 관리: kiosk 리다이렉트
# ---------------------------------------------------------------------------

async def _do_kiosk_redirect(container, url: str) -> bool:
    """
    Chromium URL을 변경한다. kill 수행 여부를 bool로 반환한다.

    [0. 래퍼 패치 — idempotent]
    kasmweb 의 /usr/bin/chromium-browser 는 실제 바이너리를 호출하는 bash 래퍼다.
    이 래퍼에 --remote-debugging-port=9222 와 kiosk 플래그를 한 번만 삽입한다.
    이후 custom_startup.sh watchdog 이 Chromium 을 재시작할 때도 CDP 포트가 자동으로 열린다.

    [1. CDP 우선 — 즉시 탐색, kill 없음]
    port 9222 가 열려 있으면 Page.navigate 로 URL 변경.
    watchdog 레이스 없음 — False 반환.

    [2. kill + watchdog 재시작 위임 — 최초 워밍 시]
    CDP 불가(port 9222 미열림) 시 Chromium 만 종료한다.
    custom_startup.sh watchdog 이 ~1초 후 패치된 래퍼를 통해 재시작한다.
    직접 Chromium 을 기동하지 않으므로 watchdog 레이스 컨디션 자체가 없어진다.
    True 반환 → 호출측은 _wait_for_cdp_ready 로 재시작 완료를 확인해야 한다.

    [주의] pgrep -f chrom 만으로 kill 하면 Xvnc(6901)까지 종료될 수 있다.
    반드시 ss 로 Xvnc PID 를 식별하고 kill 대상에서 제외한다.
    """
    # ── 0. Chromium 래퍼 패치 (idempotent) ──────────────────────────────────────
    # sed: "$@" → kiosk/debug flags "$@" (이미 패치된 경우 grep -q 로 스킵)
    # |  구분자 사용: URL 내 / 가 있어도 안전
    # &  교체문의 &: sed 에서 "매칭된 문자열" 즉 "$@" 로 치환
    # DC-34: --remote-debugging-address=0.0.0.0 추가.
    # Chromium 기본값은 127.0.0.1 바인딩 → Docker 포트 매핑이 컨테이너 eth0(172.17.x.x)
    # 방향으로 DNAT하므로 loopback에만 열린 CDP에 호스트가 도달하지 못함.
    # 0.0.0.0 바인딩으로 변경해 호스트 → mapped port → CDP 경로를 개통.
    # idempotent 판정 기준을 'remote-debugging-address'로 교체:
    #   - 이전 패치(주소 없는 버전)가 적용된 컨테이너는 sed 재실행 → "$@"가 이미
    #     치환돼 있으면 no-op이므로 안전. 신규 컨테이너는 정상 패치.
    patch_cmd = (
        "grep -q 'remote-debugging-address' /usr/bin/chromium-browser 2>/dev/null"
        " || sed -i"
        " 's|\"\\$@\"|--kiosk --disable-infobars --noerrdialogs"
        " --disable-translate --remote-debugging-port=9222"
        " --remote-debugging-address=0.0.0.0"
        " --remote-allow-origins=http://localhost:9222 &|g'"
        " /usr/bin/chromium-browser 2>/dev/null"
        " && echo wrapper_patched || echo wrapper_already_patched"
    )
    try:
        # /usr/bin/chromium-browser 는 root 소유이므로 user="root" 필수
        pr = await asyncio.to_thread(
            container.exec_run, ["bash", "-c", patch_cmd], user="root"
        )
        logger.debug(
            "[browse] 래퍼 패치: %s",
            (pr.output or b"").decode(errors="replace").strip() or "(no output)",
        )
    except Exception as e:
        logger.debug("[browse] 래퍼 패치 실패 (무시): %s", e)

    # ── 1. CDP 시도 ─────────────────────────────────────────────────────────
    try:
        cdp_result = await asyncio.to_thread(
            container.exec_run,
            ["python3", "-c", _CDP_NAVIGATE_PY],
            environment={"KIOSK_URL": url},
        )
        output = (cdp_result.output or b"").decode(errors="replace").strip()
        if "cdp_ok" in output:
            logger.info("[browse] CDP 탐색 성공 → %s", url[:60])
            return False  # kill 없음 — 호출측 sleep 불필요
        logger.debug("[browse] CDP 불가 — kill+watchdog 폴백: %s", output)
    except Exception as e:
        logger.debug("[browse] CDP 실행 오류 — kill+watchdog 폴백: %s", e)

    # ── 2. kill 폴백 (watchdog 재시작 위임) ─────────────────────────────────────
    # Chromium 만 종료. watchdog 이 ~1초 후 패치된 래퍼로 재시작 → port 9222 열림.
    # 직접 Chromium 을 기동하지 않으므로 watchdog 과의 레이스 컨디션이 없다.
    kill_script = (
        "XVNC_PID=$(ss -tlnp 2>/dev/null | grep ':6901'"
        " | grep -oP 'pid=\\K[0-9]+' | head -1); "
        "for p in $(pgrep -f chrom 2>/dev/null); do "
        "  [ \"$p\" != \"$XVNC_PID\" ] && kill -9 \"$p\" 2>/dev/null; "
        "done; "
        "echo killed"
    )
    try:
        result = await asyncio.to_thread(
            container.exec_run,
            ["bash", "-c", kill_script],
        )
        logger.info(
            "[browse] Chromium 종료(watchdog 재시작 위임) → %s: %s",
            url[:60],
            (result.output or b"").decode(errors="replace").strip() or "(출력 없음)",
        )
    except Exception as e:
        logger.warning("[browse] Chromium 종료 실패 (무시): %s", e)
    return True  # kill 수행 — 호출측은 _wait_for_cdp_ready 로 재시작 확인 필요


# ---------------------------------------------------------------------------
# 풀 관리: 워밍 · 보충 · 초기화
# ---------------------------------------------------------------------------

async def _create_warmed_session(
    screen_width: int = 1080,
    screen_height: int = 1920,
) -> dict | None:
    """
    _POOL_PLACEHOLDER_URL 로 컨테이너를 생성하고 KasmVNC 준비까지 대기한다.
    _active_sessions 에 등록하지 않고 풀용 dict 만 반환한다.
    실패 시 None 을 반환하고 자원을 정리한다.
    """
    if not _DOCKER_AVAILABLE:
        return None

    container = None
    network = None

    try:
        client = await asyncio.to_thread(docker.from_env)
    except Exception as e:
        logger.error("[pool] Docker 연결 실패: %s", e)
        return None

    vnc_pw = uuid4().hex

    try:
        network = await asyncio.to_thread(_create_browse_network, client)
        resolution = f"{screen_width}x{screen_height}"
        logger.info("[pool] 워밍 컨테이너 생성 중 (해상도: %s)", resolution)

        container = await asyncio.to_thread(
            client.containers.run,
            BROWSE_IMAGE,
            detach=True,
            remove=True,
            ports={BROWSE_PORT: None},
            environment={
                "VNC_PW": vnc_pw,
                "LAUNCH_URL": _POOL_PLACEHOLDER_URL,
                "RESOLUTION": resolution,
                # 참고: kasmweb/chromium:1.14.0 은 CHROMIUM_FLAGS / KASM_CHROME_FLAGS 를
                # 실제 Chromium 시작 시 무시한다. 래퍼(/usr/bin/chromium-browser)를
                # _do_kiosk_redirect 가 직접 패치해 kiosk + CDP 포트를 활성화한다.
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

        await _wait_for_host_port(int(host_port))

        # kiosk 모드로 재시작 + --remote-debugging-port=9222 활성화
        await _do_kiosk_redirect(container, _POOL_PLACEHOLDER_URL)

        # CDP 포트가 실제로 열릴 때까지 대기 (최대 20초).
        # 이 대기 없이 풀에 추가하면 pool hit 시 CDP 가 실패 → kill+restart → watchdog 레이스.
        await _wait_for_cdp_ready(container)

        kasm_host_port = int(host_port)
        proxy_port, proxy_task = await _start_ssl_strip_proxy(kasm_host_port, vnc_pw)

        container_id = container.id
        logger.info(
            "[pool] 워밍 완료: container=%s, proxy=127.0.0.1:%d",
            container_id[:12], proxy_port,
        )
        return {
            "container": container,
            "container_id": container_id,
            "network": network,
            "network_name": network.name,
            "proxy_port": proxy_port,
            "proxy_task": proxy_task,
            "kasm_host_port": kasm_host_port,
            "vnc_pw": vnc_pw,
        }

    except BaseException as _exc:
        # BaseException 으로 CancelledError(asyncio 취소)와 일반 Exception 을 모두 잡는다.
        # ─ CancelledError: 서버 재시작/WatchFiles 취소 → 자원 정리 후 반드시 re-raise
        # ─ 그 외 Exception : 컨테이너 404 등 → 자원 정리 후 None 반환 (graceful fallback)
        _is_cancel = isinstance(_exc, asyncio.CancelledError)
        if _is_cancel:
            logger.warning("[pool] 워밍 취소됨(서버 재시작?) — 자원 정리")
        else:
            logger.warning("[pool] 워밍 실패(%s) — 자원 정리", type(_exc).__name__)
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
        if _is_cancel:
            raise  # CancelledError 는 반드시 re-raise 해야 asyncio 취소 체인이 완료된다
        return None  # 일반 오류는 None 반환 → _replenish_pool 이 graceful 처리


async def _replenish_pool() -> None:
    """
    풀이 POOL_SIZE 미만이면 워밍 컨테이너를 1개 생성해 큐에 적재한다.

    asyncio 단일 스레드 특성을 이용한다:
    await 전까지는 다른 코루틴이 끼어들 수 없으므로
    qsize + _pool_warming 체크 → _pool_warming 증가가 원자적으로 실행된다.
    """
    global _pool_warming
    if _pool_idle.qsize() + _pool_warming >= POOL_SIZE:
        return
    _pool_warming += 1
    logger.info(
        "[pool] 보충 시작: idle=%d, warming=%d → 목표 %d",
        _pool_idle.qsize(), _pool_warming, POOL_SIZE,
    )
    try:
        session = await _create_warmed_session()
        if session:
            await _pool_idle.put(session)
            logger.info("[pool] 보충 완료: idle=%d", _pool_idle.qsize())
        else:
            logger.warning("[pool] 보충 실패: 워밍 컨테이너 생성 불가")
    except asyncio.CancelledError:
        raise  # 취소는 그대로 전파
    except Exception as e:
        # _create_warmed_session 에서 예외가 누출되는 경우의 최후 방어선
        # "Task exception was never retrieved" 를 방지한다
        logger.warning("[pool] _replenish_pool 예외 (무시): %s", e)
    finally:
        _pool_warming -= 1


async def initialize_pool(size: int = POOL_SIZE) -> None:
    """
    서버 시작 시 백그라운드에서 워밍 컨테이너를 size개 생성한다.
    서버 기동을 블록하지 않으며, 풀이 채워지는 동안 on-demand 폴백이 작동한다.
    main.py lifespan 에서 호출한다.
    """
    if not _DOCKER_AVAILABLE:
        logger.warning("[pool] Docker 없음 — 풀 초기화 생략")
        return
    logger.info("[pool] 초기화: %d개 워밍 백그라운드 시작", size)
    for _ in range(size):
        asyncio.create_task(_replenish_pool())


# ---------------------------------------------------------------------------
# 세션 생성 (공개 API)
# ---------------------------------------------------------------------------

async def create_browse_session(
    url: str,
    screen_width: int = 1080,
    screen_height: int = 1920,
) -> dict:
    """
    kasmweb/chromium 컨테이너를 할당하고 내부 프록시 포트를 반환한다.
    noVNC URL은 라우터(sandbox.py)가 백엔드 경로로 조립한다.

    [풀 hit]  _pool_idle 에서 즉시 할당 → URL 리다이렉트 → <5초 응답
    [풀 miss] 온디맨드 컨테이너 생성 (기존 방식, 30~80초 소요)

    Returns:
        dict: {"container_id": str, "proxy_port": int, "network_name": str}
              실패 시: {"error": str}
    """
    if not _DOCKER_AVAILABLE:
        return {"error": "docker 패키지를 로드할 수 없습니다. 'pip install docker'를 실행하세요."}

    # ── 1. 풀에서 즉시 할당 시도 ─────────────────────────────────────────────
    pool_session: dict | None = None
    try:
        pool_session = _pool_idle.get_nowait()
    except asyncio.QueueEmpty:
        pass

    if pool_session is not None:
        container_id = pool_session["container_id"]
        logger.info("[pool] 풀 hit: container=%s → %s", container_id[:12], url)

        # 컨테이너 생존 확인 (idle 중에 죽었을 가능성)
        try:
            await asyncio.to_thread(pool_session["container"].reload)
            if pool_session["container"].status != "running":
                raise RuntimeError(f"컨테이너 상태 이상: {pool_session['container'].status}")
        except Exception as e:
            logger.warning("[pool] idle 컨테이너 상태 이상, 온디맨드로 폴백: %s", e)
            # 죽은 컨테이너·프록시·네트워크 정리 — 모두 asyncio.to_thread 로 감싸야 한다
            proxy_task = pool_session.get("proxy_task")
            if proxy_task and not proxy_task.done():
                proxy_task.cancel()
            try:
                await asyncio.to_thread(pool_session["container"].stop, timeout=3)
            except Exception:
                pass
            network_obj = pool_session.get("network")
            if network_obj is not None:
                try:
                    await asyncio.to_thread(network_obj.remove)
                except Exception:
                    pass
            # 풀 보충 후 온디맨드로 폴백
            asyncio.create_task(_replenish_pool())
            pool_session = None

    if pool_session is not None:
        # 풀 컨테이너: 래퍼 패치·CDP 준비는 워밍 시 완료됨.
        timeout_task = asyncio.create_task(
            _auto_terminate(container_id, pool_session["network_name"])
        )
        _active_sessions[container_id] = {
            **pool_session,
            "timeout_task": timeout_task,
        }

        # DC-34: watchdog 시작 → CDP 설정 완료(asyncio.Event) 대기 → 탐색
        # 이 순서가 보장되어야 다운로드 트리거 시 Page.downloadWillBegin이 발동함.
        cdp_ready_event = asyncio.Event()
        watchdog_task = asyncio.create_task(
            start_cdp_watchdog(container_id, cdp_ready_event=cdp_ready_event)
        )
        _active_sessions[container_id]["watchdog_task"] = watchdog_task

        # watchdog이 Page.enable + Page.setDownloadBehavior 완료할 때까지 대기 (최대 15초)
        try:
            await asyncio.wait_for(cdp_ready_event.wait(), timeout=15.0)
            logger.info("[pool] CDP 설정 확인 → 탐색 시작: container=%s", container_id[:12])
        except asyncio.TimeoutError:
            logger.warning("[pool] CDP 설정 이벤트 타임아웃 — 탐색 강행: container=%s", container_id[:12])

        # Page.setDownloadBehavior 설정 완료 후 탐색 → race condition 없음
        await _do_kiosk_redirect(pool_session["container"], url)

        # 비동기 풀 보충 (현재 요청을 블록하지 않음)
        asyncio.create_task(_replenish_pool())

        logger.info(
            "[pool] 풀 할당 완료: container=%s, proxy=127.0.0.1:%d",
            container_id[:12], pool_session["proxy_port"],
        )
        return {
            "container_id": container_id,
            "proxy_port": pool_session["proxy_port"],
            "network_name": pool_session["network_name"],
            "vnc_pw": pool_session["vnc_pw"],
        }

    # ── 2. 온디맨드 폴백 (풀 miss 또는 idle 컨테이너 상태 이상) ──────────────
    logger.info("[pool] 풀 miss — 온디맨드 생성: %s", url)

    container = None
    network = None

    try:
        client = await asyncio.to_thread(docker.from_env)
    except Exception as e:
        return {"error": f"Docker 연결 실패 (Docker Desktop이 실행 중인지 확인): {e}"}

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
                "VNC_PW": vnc_pw,
                "LAUNCH_URL": _POOL_PLACEHOLDER_URL,  # about:blank — watchdog이 탐색
                "RESOLUTION": resolution,
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

        await _wait_for_host_port(int(host_port))

        # 래퍼 패치 전용 (about:blank → CDP 포트 활성화, Chromium 재시작 위임)
        await _do_kiosk_redirect(container, _POOL_PLACEHOLDER_URL)

        kasm_host_port = int(host_port)
        proxy_port, proxy_task = await _start_ssl_strip_proxy(kasm_host_port, vnc_pw)

        container_id = container.id
        timeout_task = asyncio.create_task(_auto_terminate(container_id, network.name))
        _active_sessions[container_id] = {
            "container": container,
            "network": network,
            "network_name": network.name,
            "timeout_task": timeout_task,
            "proxy_task": proxy_task,
            "proxy_port": proxy_port,
            "kasm_host_port": kasm_host_port,
            "vnc_pw": vnc_pw,
        }

        # DC-34: watchdog 시작 → CDP 설정 완료 대기(최대 30초) → 탐색
        cdp_ready_event = asyncio.Event()
        watchdog_task = asyncio.create_task(
            start_cdp_watchdog(container_id, cdp_ready_event=cdp_ready_event)
        )
        _active_sessions[container_id]["watchdog_task"] = watchdog_task

        try:
            await asyncio.wait_for(cdp_ready_event.wait(), timeout=30.0)
            logger.info("[browse] CDP 설정 확인 → 탐색 시작: container=%s", container_id[:12])
        except asyncio.TimeoutError:
            logger.warning("[browse] CDP 설정 이벤트 타임아웃 — 탐색 강행: container=%s", container_id[:12])

        await _do_kiosk_redirect(container, url)

        logger.info(
            "[browse] 온디맨드 생성 완료: container=%s, proxy=127.0.0.1:%d, kasm_port=%d",
            container_id[:12], proxy_port, kasm_host_port,
        )
        # 온디맨드 성공 직후 풀 보충 트리거: pool miss 구간을 최소화한다
        asyncio.create_task(_replenish_pool())
        return {
            "container_id": container_id,
            "proxy_port": proxy_port,
            "network_name": network.name,
            "vnc_pw": vnc_pw,
        }

    except Exception as e:
        logger.exception("[browse] 온디맨드 세션 생성 실패")
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


# ---------------------------------------------------------------------------
# DC-34: CDP 실시간 위협 감지 watchdog
# ---------------------------------------------------------------------------

async def start_cdp_watchdog(
    container_id: str,
    cdp_ready_event: asyncio.Event | None = None,
) -> None:
    """
    컨테이너 내부에서 _CDP_MONITOR_PY 스크립트를 exec_run으로 실행해
    CDP 이벤트를 실시간 감시한다 (DC-34).

    cdp_ready_event가 주어지면 Page.enable + Page.setDownloadBehavior 설정 완료
    (CDP_SETUP_DONE 수신) 시 이벤트를 set한다.
    호출측은 이 이벤트를 기다린 후 _do_kiosk_redirect로 탐색하므로
    탐색이 항상 setDownloadBehavior 이후에 발생한다 (race condition 방지).

    [현재 방식]
    container.exec_run(stream=True) → 컨테이너 내부 python3 → localhost:9222
    기존 _CDP_NAVIGATE_PY 와 동일한 경로이므로 항상 동작한다.
    스트림 스레드가 이벤트를 asyncio.Queue 로 전달하고,
    메인 코루틴이 큐를 소비해 블랙리스트 검사 및 세션 종료를 처리한다.
    """
    from database.blacklist_service import check_blacklist

    session = _active_sessions.get(container_id)
    if not session:
        return

    container = session.get("container")
    if container is None:
        logger.warning("[cdp-watchdog] 컨테이너 없음 — watchdog 스킵: %s", container_id[:12])
        return

    logger.info("[cdp-watchdog] 시작: container=%s (exec 방식)", container_id[:12])

    loop = asyncio.get_running_loop()
    event_queue: asyncio.Queue[str | None] = asyncio.Queue()

    def _stream_worker() -> None:
        """컨테이너 내부 모니터 스크립트를 실행하고 stdout 줄을 이벤트 큐에 전달한다.

        tty=True: Docker non-TTY 모드의 내부 버퍼링을 우회한다.
        non-TTY 모드에서는 작은 출력(예: 'CDP_READY' 9바이트)이 Docker 내부 버퍼에
        쌓여 프로세스 종료 전까지 호스트로 전달되지 않는다.
        tty=True 시 멀티플렉스 헤더 없이 원시 바이트를 즉시 전달한다.
        """
        try:
            result = container.exec_run(
                ["python3", "-u", "-c", _CDP_MONITOR_PY],
                stream=True,
                tty=True,     # 버퍼링 없이 즉시 전달 — 핵심 수정
            )
            for chunk in result.output:
                if chunk:
                    for line in chunk.decode(errors="replace").splitlines():
                        line = line.strip()
                        if line:
                            loop.call_soon_threadsafe(event_queue.put_nowait, line)
        except Exception as exc:
            loop.call_soon_threadsafe(event_queue.put_nowait, f"STREAM_ERROR:{exc}")
        finally:
            loop.call_soon_threadsafe(event_queue.put_nowait, None)  # sentinel

    thread = threading.Thread(
        target=_stream_worker, daemon=True, name=f"cdp-{container_id[:8]}"
    )
    thread.start()

    try:
        while True:
            if container_id not in _active_sessions:
                break

            try:
                line = await asyncio.wait_for(event_queue.get(), timeout=35.0)
            except asyncio.TimeoutError:
                logger.warning("[cdp-watchdog] 타임아웃: %s", container_id[:12])
                break

            if line is None:
                logger.info("[cdp-watchdog] 스트림 종료: %s", container_id[:12])
                break

            # ── CDP 초기화 상태 ────────────────────────────────────────────
            if line == "CDP_READY":
                logger.info("[cdp-watchdog] CDP 연결됨: %s", container_id[:12])

            elif line == "CDP_SETUP_DONE":
                # Page.enable + Page.setDownloadBehavior 완료 → 호출측이 탐색해도 안전
                logger.info("[cdp-watchdog] CDP 설정 완료 (이벤트 구독 준비): %s", container_id[:12])
                if cdp_ready_event is not None:
                    cdp_ready_event.set()

            elif line in ("CDP_NO_TABS", "CDP_HANDSHAKE_FAIL") or line.startswith("CDP_CONNECT_ERROR:"):
                logger.warning("[cdp-watchdog] CDP 초기화 실패(%s): %s", line, container_id[:12])
                if cdp_ready_event is not None:
                    cdp_ready_event.set()  # 실패여도 호출측 블록 방지
                break

            # ── 탐색 감지 ──────────────────────────────────────────────────
            elif line.startswith("NAVIGATE:"):
                nav_url = line[len("NAVIGATE:"):]
                if not nav_url:
                    continue

                curr = _active_sessions.get(container_id)
                if curr is not None:
                    curr.setdefault("visited_urls", []).append(nav_url)

                logger.info(
                    "[cdp-watchdog] 탐색 감지: container=%s url=%.80s",
                    container_id[:12], nav_url,
                )

                # 블랙리스트 실시간 검사
                hit = await asyncio.to_thread(check_blacklist, [nav_url])
                if hit:
                    logger.warning("[cdp-watchdog] 블랙리스트 히트 — 자동 차단: %.80s", nav_url)
                    curr = _active_sessions.get(container_id)
                    if curr is None:
                        break  # 이중 terminate 방지
                    nw = curr.get("network_name", "")
                    screenshot = await _take_cdp_screenshot(curr.get("container"))
                    _threat_cache[container_id] = {
                        "threat_detected": True,
                        "threat_reason": "blacklist_hit",
                        "threat_url": nav_url,
                        "filename": "",
                        "screenshot": screenshot,
                    }
                    await terminate_browse_session(container_id, nw)
                    break

            # ── 다운로드 시도 감지 ─────────────────────────────────────────
            elif line.startswith("DOWNLOAD:"):
                rest = line[len("DOWNLOAD:"):]
                parts = rest.split(":", 1)
                dl_url = parts[0]
                filename = parts[1] if len(parts) > 1 else ""
                logger.warning(
                    "[cdp-watchdog] 다운로드 시도 — 자동 차단: url=%.80s file=%s",
                    dl_url, filename,
                )
                curr = _active_sessions.get(container_id)
                if curr is None:
                    break
                nw = curr.get("network_name", "")
                screenshot = await _take_cdp_screenshot(curr.get("container"))
                _threat_cache[container_id] = {
                    "threat_detected": True,
                    "threat_reason": "download_attempt",
                    "threat_url": dl_url,
                    "filename": filename,
                    "screenshot": screenshot,
                }
                await terminate_browse_session(container_id, nw)
                break

            elif line.startswith("STREAM_ERROR:"):
                logger.warning("[cdp-watchdog] 스트림 오류: %s — %s", container_id[:12], line)
                break

    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.warning("[cdp-watchdog] 오류: %s — %s", container_id[:12], exc)
    finally:
        logger.info("[cdp-watchdog] 종료: container=%s", container_id[:12])
        if container_id in _threat_cache:
            try:
                async def _cleanup_threat(cid: str = container_id) -> None:
                    await asyncio.sleep(300)
                    _threat_cache.pop(cid, None)
                asyncio.create_task(_cleanup_threat())
            except RuntimeError:
                pass


# ---------------------------------------------------------------------------
# 세션 종료 (공개 API)
# ---------------------------------------------------------------------------

async def terminate_browse_session(container_id: str, network_name: str) -> None:
    session = _active_sessions.pop(container_id, None)

    if session:
        for key in ("timeout_task", "proxy_task", "watchdog_task"):
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

    # 세션 종료 후 풀 보충
    asyncio.create_task(_replenish_pool())


# ---------------------------------------------------------------------------
# 서버 종료 시 전체 정리 (공개 API)
# ---------------------------------------------------------------------------

async def cleanup_stale_networks() -> None:
    """
    서버 시작 시 컨테이너 없이 남겨진 browse_net_* 고아 네트워크를 삭제한다.

    Docker 브리지 네트워크는 기본적으로 약 30개의 /20 서브넷만 허용한다.
    서버 재시작(WatchFiles, 크래시)으로 워밍 중이던 asyncio.Task 가 취소되면
    except Exception 이 CancelledError 를 잡지 못해 네트워크가 남겨진다.
    이 함수가 startup 에서 호출되어 누적된 고아 네트워크를 일괄 삭제한다.
    """
    if not _DOCKER_AVAILABLE:
        return
    try:
        client = await asyncio.to_thread(docker.from_env)
        networks = await asyncio.to_thread(
            client.networks.list,
            filters={"name": "browse_net_"},
        )
        removed = 0
        for net in networks:
            try:
                await asyncio.to_thread(net.reload)
                if not net.containers:
                    await asyncio.to_thread(net.remove)
                    logger.info("[startup] 고아 네트워크 삭제: %s", net.name)
                    removed += 1
            except Exception as e:
                logger.debug(
                    "[startup] 네트워크 처리 오류 (%s): %s",
                    getattr(net, "name", "?"), e,
                )
        if removed:
            logger.info("[startup] 고아 browse_net_* 네트워크 %d개 삭제 완료", removed)
    except Exception as e:
        logger.warning("[startup] 고아 네트워크 정리 중 오류 (무시): %s", e)


async def shutdown_all_sessions() -> None:
    """서버 종료 시 활성 세션과 풀 idle 컨테이너를 모두 정리한다."""

    # 활성 세션 정리
    if _active_sessions:
        logger.info("[browse] 서버 종료 — 활성 세션 %d개 정리 중", len(_active_sessions))
        for container_id, session in list(_active_sessions.items()):
            for key in ("timeout_task", "proxy_task", "watchdog_task"):
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
        logger.info("[browse] 활성 세션 정리 완료")

    # 풀 idle 컨테이너 정리
    idle_count = _pool_idle.qsize()
    if idle_count:
        logger.info("[pool] 서버 종료 — idle 컨테이너 %d개 정리 중", idle_count)
        while not _pool_idle.empty():
            try:
                session = _pool_idle.get_nowait()
            except asyncio.QueueEmpty:
                break

            proxy_task = session.get("proxy_task")
            if proxy_task and not proxy_task.done():
                proxy_task.cancel()

            container = session.get("container")
            if container is not None:
                try:
                    await asyncio.to_thread(container.stop, timeout=3)
                except Exception as e:
                    logger.warning(
                        "[pool] 종료 중 idle 컨테이너 stop 실패 (%s): %s",
                        session.get("container_id", "?")[:12], e,
                    )

            network = session.get("network")
            if network is not None:
                try:
                    await asyncio.to_thread(network.remove)
                except Exception as e:
                    logger.warning("[pool] 종료 중 idle 네트워크 remove 실패: %s", e)

        logger.info("[pool] idle 컨테이너 정리 완료")
