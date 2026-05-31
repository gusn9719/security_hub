# =============================================================================
# backend/main.py
# 역할: FastAPI 앱 진입점, CORS 설정, 앱 생명주기 관리
# 변경 이력:
#   - Sprint 1: 최초 작성, CORS 설정
#   - Sprint 4: lifespan으로 앱 시작 시 DB init_db() 호출 추가
#   - Sprint 5E: 보안 미들웨어 추가
#                  - TRACE/CONNECT/TRACK HTTP 메서드 차단
#                  - 보안 응답 헤더 (X-Content-Type-Options 등)
#                  - 전역 예외 핸들러 (스택 트레이스 미노출)
#                  - 시작 시 만료 평판 캐시 정리(purge_expired)
# =============================================================================

import asyncio
import logging
import os
import re
import sys
import time
import uuid as _uuid_mod
from collections import defaultdict
from contextlib import asynccontextmanager

# .env 를 다른 모듈이 import 되기 전 가장 먼저 로드한다.
# gemini_service.py 내부의 load_dotenv() 가 호출되는 시점은 import 순서에
# 따라 달라지므로 운에 의존하게 된다. JWT_SECRET 같이 모듈 함수 호출 시점에
# 환경변수가 반드시 있어야 하는 케이스는 여기서 한 번 확실히 로드.
from dotenv import load_dotenv  # noqa: E402
load_dotenv()

# Windows의 ProactorEventLoop은 asyncio SSL 연결에서 실제 SSL 오류를
# ConnectionRefusedError로 잘못 변환하는 버그가 있다.
# SelectorEventLoop으로 전환해 SSL 연결이 정상 작동하도록 한다.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from routers import analyze
from routers import auth as auth_router
from routers import sandbox
from database.db_init import init_db
from services import jwt_service
from services.browse_service import shutdown_all_sessions, initialize_pool, cleanup_stale_networks
from services.reputation_cache_service import purge_expired

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


# =============================================================================
# 보안 미들웨어
# =============================================================================

class BlockDangerousMethodsMiddleware(BaseHTTPMiddleware):
    """
    TRACE / CONNECT / TRACK HTTP 메서드 차단.

    - TRACE: XST(Cross-Site Tracing) 공격 벡터
    - CONNECT: 프록시 터널링 악용 가능
    - TRACK: 일부 MS 서버 TRACE 변형, 브라우저 추적에 악용
    """
    _BLOCKED: frozenset[str] = frozenset({"TRACE", "CONNECT", "TRACK"})

    async def dispatch(self, request: Request, call_next):
        if request.method in self._BLOCKED:
            logger.warning("[보안] 차단된 HTTP 메서드 — %s %s", request.method, request.url)
            return Response(status_code=405, content="Method Not Allowed")
        return await call_next(request)


class DeviceUUIDMiddleware(BaseHTTPMiddleware):
    """
    NF-30: 모든 요청에 X-Device-UUID 헤더를 강제한다.

    헤더 없음  → 401 Unauthorized
    UUID 형식 오류 → 400 Bad Request
    제외 경로:
      - /docs, /redoc, /openapi.json
      - /sandbox/browse/{container_id}/novnc(/...) — KasmVNC 프록시 경로.
        WebView 내부에서 noVNC JS·CSS·WebSocket 이 X-Device-UUID 헤더 없이
        직접 요청을 보내므로 제외해야 한다.

    P0-8 (보고서 M-4): 이전 구현 `"/novnc" in path` 는 단순 부분 일치라
    `/api/novnc-test`, `/v2/sandbox/novnc-status` 같이 사용자 정의 경로
    어디에든 'novnc' 가 포함되면 UUID 검증을 우회할 수 있었다. 동시에
    보고서가 권고한 path.startswith("/sandbox/browse/") 도 너무 넓어
    컨테이너 생성·삭제(POST/DELETE /sandbox/browse, /sandbox/browse/{id})
    까지 우회 대상이 된다. 정규식으로 noVNC 프록시 경로 정확히 매칭.
    """
    _EXCLUDED = frozenset({"/docs", "/redoc", "/openapi.json"})
    _NOVNC_RE = re.compile(r"^/sandbox/browse/[^/]+/novnc(?:/|$)")

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path in self._EXCLUDED or self._NOVNC_RE.match(path):
            return await call_next(request)

        device_uuid = request.headers.get("X-Device-UUID")
        if not device_uuid:
            return JSONResponse(
                status_code=401,
                content={"detail": "X-Device-UUID 헤더가 필요합니다."},
            )
        try:
            _uuid_mod.UUID(device_uuid)
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"detail": "X-Device-UUID 형식이 올바르지 않습니다 (UUID v4 필요)."},
            )
        return await call_next(request)


class OptionalAuthMiddleware(BaseHTTPMiddleware):
    """
    AUTH-01 (Phase 3): Authorization: Bearer <jwt> 헤더가 있으면 검증하고
    request.state.user_id 에 user_id 를 채운다. 없으면 익명으로 통과.

    설계 결정:
    - **없으면 통과**: 익명 사용자도 모든 엔드포인트(분석/샌드박스/투표) 접근.
      device_uuid 만 필수 (NF-30 / DeviceUUIDMiddleware).
    - **무효 토큰은 401**: 만료/서명 깨진 토큰을 silent pass-through 로
      익명 취급하면 (1) 클라이언트가 stale 토큰 들고 계속 익명 가중치로
      서비스를 받고 (2) 서버가 재로그인 흐름을 유도할 길이 없다.
      JSON 으로 401 + 에러 메시지 반환 → 클라이언트가 토큰 폐기.
    - **state.user_id 만 신뢰**: 다운스트림 라우터/헬퍼는 request.state 만
      읽어야 한다. 헤더에서 직접 user_id 를 재파싱하면 본 미들웨어 우회 경로가
      생긴다. routers.auth.get_optional_user_id 가 이 인터페이스를 강제.

    예외 경로:
    - noVNC 프록시 (/sandbox/browse/{id}/novnc) — KasmVNC JS 가 자체 헤더를
      못 붙임. DeviceUUID 미들웨어와 같은 이유.
    """
    _NOVNC_RE = re.compile(r"^/sandbox/browse/[^/]+/novnc(?:/|$)")

    async def dispatch(self, request: Request, call_next):
        # 기본값 — 라우터/헬퍼가 항상 .state.user_id 를 안전하게 읽을 수 있도록.
        request.state.user_id = None

        if self._NOVNC_RE.match(request.url.path):
            return await call_next(request)

        auth = request.headers.get("Authorization") or request.headers.get("authorization")
        if not auth:
            return await call_next(request)

        # Bearer 형식이 아닌 Authorization 헤더 (Basic 등) 는 본 앱이 지원
        # 하지 않는다. 명시적으로 401 — silent 무시는 보안 안티 패턴.
        if not auth.lower().startswith("bearer "):
            return JSONResponse(
                status_code=401,
                content={"detail": "Authorization 은 Bearer 형식이어야 합니다."},
            )

        token = auth.split(" ", 1)[1].strip()
        try:
            request.state.user_id = jwt_service.decode_token(token)
        except jwt_service.JWTError as e:
            # 만료·서명오류·sub 누락 모두 클라이언트에게 알려 토큰 폐기 유도.
            return JSONResponse(
                status_code=401,
                content={"detail": str(e)},
            )
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    모든 응답에 보안 헤더를 추가한다.

    noVNC 프록시 경로(/sandbox/browse/)는 KasmVNC HTML·JS를 그대로 서빙하므로
    CSP와 X-Frame-Options를 적용하지 않는다. 이 헤더들을 적용하면
    WebView가 noVNC JavaScript 실행과 WebSocket 연결을 차단한다.

    noVNC 정적 자산(JS·CSS·이미지)은 민감 데이터가 없으므로 캐싱을 허용한다.
    매 요청마다 재다운로드하면 초기 로딩이 10초 이상 걸리기 때문이다.
    """
    _NOVNC_PREFIX = "/sandbox/browse/"
    # 캐시를 허용하는 noVNC 정적 자산 확장자 (세션 데이터는 WS이므로 HTTP에 없음)
    _CACHEABLE_EXTS = frozenset({
        ".js", ".css", ".png", ".ico", ".gif",
        ".woff", ".woff2", ".ttf", ".svg", ".map",
    })

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"]        = "1; mode=block"
        response.headers["Referrer-Policy"]          = "no-referrer"

        path = request.url.path
        # noVNC 정적 자산은 캐시 허용 — JS/CSS는 동일 파일이 반복 요청되므로
        # no-store 를 적용하면 매번 재다운로드해 로딩 시간이 10s 이상 증가한다.
        is_novnc_static = path.startswith(self._NOVNC_PREFIX) and any(
            path.endswith(ext) for ext in self._CACHEABLE_EXTS
        )
        if not is_novnc_static:
            response.headers["Cache-Control"] = "no-store"   # NF-12

        if not path.startswith(self._NOVNC_PREFIX):
            response.headers["X-Frame-Options"]          = "DENY"
            response.headers["Content-Security-Policy"]  = "default-src 'none'"
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    NF-24: IP 기반 요청 속도 제한.
    - POST /analyze          : 10회/분
    - POST /sandbox/browse   : 5회/분 (컨테이너 생성)
    - POST /sandbox/auto-test: 5회/분
    - POST /sandbox/votes    : 20회/분 (P0-7, 보고서 M-3)
    - POST /auth/kakao       : 5회/분 (AUTH-01) — 카카오 API 무차별 호출
                                                    채널화 방지. 자연인은
                                                    분당 5 회 로그인하지
                                                    않는다.
    초과 시 HTTP 429 + Retry-After 반환.
    """
    _LIMITS: dict[str, tuple[int, int]] = {
        "/analyze":           (10, 60),
        "/sandbox/browse":    (5,  60),
        "/sandbox/auto-test": (5,  60),
        "/sandbox/votes":     (20, 60),
        "/auth/kakao":        (5,  60),
    }

    def __init__(self, app):
        super().__init__(app)
        # IP:endpoint → 요청 타임스탬프 리스트
        self._counters: dict[str, list[float]] = defaultdict(list)

    def _client_ip(self, request: Request) -> str:
        # Cloudflare Tunnel은 CF-Connecting-IP 헤더로 실제 클라이언트 IP를 전달한다.
        for header in ("cf-connecting-ip", "x-real-ip", "x-forwarded-for"):
            val = request.headers.get(header)
            if val:
                return val.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    async def dispatch(self, request: Request, call_next):
        if request.method != "POST":
            return await call_next(request)

        path = request.url.path
        matched: tuple[int, int] | None = None
        for prefix, limits in self._LIMITS.items():
            if path == prefix or path == prefix + "/":
                matched = limits
                break

        if matched is None:
            return await call_next(request)

        max_req, window = matched
        ip = self._client_ip(request)
        key = f"{ip}:{path}"
        now = time.monotonic()

        # 윈도우 밖 타임스탬프 제거.
        # P0-7 (보고서 M-2): 윈도우 밖 타임스탬프만 비우고 빈 리스트 키를
        # 그대로 두면 IP×endpoint 조합 수만큼 dict 키가 영구 누적된다.
        # defaultdict 의 자동 생성 동작을 우회하기 위해 .get() 으로 읽고,
        # 비어있으면 키를 만들지 않고 종료한다.
        fresh = [t for t in self._counters.get(key, ()) if now - t < window]

        if len(fresh) >= max_req:
            logger.warning(
                "[RateLimit] %s %s 초과: IP=%s (%d/%d per %ds)",
                request.method, path, ip, len(fresh), max_req, window,
            )
            return JSONResponse(
                status_code=429,
                content={"detail": f"요청 한도를 초과했습니다. {window}초 후 다시 시도하세요."},
                headers={"Retry-After": str(window)},
            )

        fresh.append(now)
        self._counters[key] = fresh
        return await call_next(request)


# =============================================================================
# 앱 생명주기
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    앱 생명주기 관리.
    시작 시: DB 초기화, 만료 평판 캐시 정리
    종료 시: browse 세션 정리
    """
    logger.info("[앱 시작] DB 초기화 중...")
    init_db()
    logger.info("[앱 시작] 만료 평판 캐시 정리 중...")
    purge_expired()
    logger.info("[앱 시작] 고아 Docker 네트워크 정리 중...")
    await cleanup_stale_networks()
    logger.info("[앱 시작] 샌드박스 풀 워밍 시작 (백그라운드)...")
    await initialize_pool()
    logger.info("[앱 시작] 초기화 완료")
    yield
    logger.info("[앱 종료] browse 세션 정리 중...")
    await shutdown_all_sessions()
    logger.info("[앱 종료] 완료")


# =============================================================================
# FastAPI 앱
# =============================================================================

# NF-25: 프로덕션에서 API 문서 비활성화
_DISABLE_DOCS = os.environ.get("DISABLE_DOCS", "").lower() in ("1", "true", "yes")

app = FastAPI(
    title="피싱 탐지 API",
    description="블랙리스트 DB + 휴리스틱 기반 피싱·스미싱 탐지 서비스",
    version="0.5.0",
    lifespan=lifespan,
    docs_url=None if _DISABLE_DOCS else "/docs",
    redoc_url=None if _DISABLE_DOCS else "/redoc",
    openapi_url=None if _DISABLE_DOCS else "/openapi.json",
)

# ── 미들웨어 등록 순서 (Starlette: add_middleware는 맨 앞에 삽입 → 나중 등록이 바깥) ──
# 실제 요청 처리 순서:
#   CORS → Security → RateLimit → DeviceUUID → OptionalAuth → Block → handler
#
# 1. 위험 메서드 차단 (가장 안쪽 — handler 직전에 실행)
app.add_middleware(BlockDangerousMethodsMiddleware)

# 2. AUTH-01: Authorization Bearer 토큰이 있으면 검증해 request.state.user_id
#    에 채운다. 없으면 익명 통과. 무효 토큰은 401.
app.add_middleware(OptionalAuthMiddleware)

# 3. NF-30: 기기 UUID 검증 (없으면 401, 잘못된 형식이면 400)
app.add_middleware(DeviceUUIDMiddleware)

# 4. NF-24: IP 기반 요청 속도 제한
app.add_middleware(RateLimitMiddleware)

# 5. 보안 헤더 (모든 응답에 추가)
app.add_middleware(SecurityHeadersMiddleware)

# 6. CORS (OPTIONS preflight를 가장 먼저 처리 — 바깥)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],   # TRACE/CONNECT/TRACK 명시 제외
    allow_headers=["*"],
)


# =============================================================================
# 전역 예외 핸들러
# =============================================================================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    처리되지 않은 예외를 500으로 변환한다.
    스택 트레이스는 로그에만 기록하고 클라이언트에 노출하지 않는다.
    """
    logger.exception("[전역 예외] %s %s", request.method, request.url)
    return JSONResponse(
        status_code=500,
        content={"detail": "서버 내부 오류가 발생했습니다. 잠시 후 다시 시도해 주세요."},
    )


# =============================================================================
# 라우터 등록
# =============================================================================

app.include_router(analyze.router)
app.include_router(sandbox.router)
app.include_router(auth_router.router)
