# =============================================================================
# backend/main.py
# 역할: FastAPI 앱 진입점, CORS 설정, 앱 생명주기 관리
# 변경 이력:
#   - Sprint 1: 최초 작성, CORS 설정
#   - Sprint 4: lifespan으로 앱 시작 시 DB init_db() 호출 추가
# =============================================================================

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routers import analyze
from routers import sandbox
from database.db_init import init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    앱 생명주기 관리.
    시작 시: 블랙리스트 DB 초기화 (테이블 없으면 생성)
    종료 시: 추가 정리 작업 없음
    """
    logger.info("[앱 시작] 블랙리스트 DB 초기화 중...")
    init_db()
    logger.info("[앱 시작] 초기화 완료")
    yield
    logger.info("[앱 종료]")


app = FastAPI(
    title="피싱 탐지 API",
    description="블랙리스트 DB + Gemini LLM 기반 피싱 탐지 서비스",
    version="0.4.0",
    lifespan=lifespan,
)

# CORS 설정 — Android 에뮬레이터(10.0.2.2) 허용
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze.router)
app.include_router(sandbox.router)