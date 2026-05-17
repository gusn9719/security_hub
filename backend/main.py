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
import sys
from contextlib import asynccontextmanager

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
from routers import sandbox
from database.db_init import init_db
from services.browse_service import shutdown_all_sessions
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


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    모든 응답에 보안 헤더를 추가한다.

    noVNC 프록시 경로(/sandbox/browse/)는 KasmVNC HTML·JS를 그대로 서빙하므로
    CSP와 X-Frame-Options를 적용하지 않는다. 이 헤더들을 적용하면
    WebView가 noVNC JavaScript 실행과 WebSocket 연결을 차단한다.
    """
    _NOVNC_PREFIX = "/sandbox/browse/"

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"]        = "1; mode=block"
        response.headers["Referrer-Policy"]          = "no-referrer"
        if not request.url.path.startswith(self._NOVNC_PREFIX):
            response.headers["X-Frame-Options"]          = "DENY"
            response.headers["Content-Security-Policy"]  = "default-src 'none'"
        return response


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
    logger.info("[앱 시작] 초기화 완료")
    yield
    logger.info("[앱 종료] browse 세션 정리 중...")
    await shutdown_all_sessions()
    logger.info("[앱 종료] 완료")


# =============================================================================
# FastAPI 앱
# =============================================================================

app = FastAPI(
    title="피싱 탐지 API",
    description="블랙리스트 DB + 휴리스틱 기반 피싱·스미싱 탐지 서비스",
    version="0.5.0",
    lifespan=lifespan,
)

# ── 미들웨어 등록 순서: 바깥 → 안쪽 순으로 적용됨 ─────────────────────────
# 1. 위험 메서드 차단 (가장 먼저 — TRACE 등은 내부 처리 전 거절)
app.add_middleware(BlockDangerousMethodsMiddleware)

# 2. 보안 헤더 (모든 응답에 추가)
app.add_middleware(SecurityHeadersMiddleware)

# 3. CORS (정상 요청에만 허용)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS"],   # TRACE/CONNECT/TRACK 명시 제외
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
