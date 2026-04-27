# =============================================================================
# backend/routers/sandbox.py
# 역할: 샌드박스 분석 엔드포인트. Docker 기반 Browserless 컨테이너를 통해
#       URL을 격리 실행하고 결과를 반환한다.
# =============================================================================

import logging

from fastapi import APIRouter
from pydantic import BaseModel

from services.sandbox_service import run_sandbox_auto

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sandbox", tags=["sandbox"])


class SandboxRequest(BaseModel):
    """샌드박스 분석 요청 모델."""
    url: str


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
