# =============================================================================
# backend/routers/sandbox.py
# 역할: 샌드박스 분석 엔드포인트. Docker 기반 Browserless 컨테이너를 통해
#       URL을 격리 실행하고 결과를 반환한다.
# =============================================================================

import logging
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from services.sandbox_service import run_sandbox_auto
from services import browse_service
from services.browse_service import create_browse_session, terminate_browse_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sandbox", tags=["sandbox"])


class SandboxRequest(BaseModel):
    """샌드박스 분석 요청 모델."""
    url: str


class BrowseCreateRequest(BaseModel):
    """kasmweb/chromium 직접 탐방 세션 생성 요청 모델 (Sprint 7-A)."""
    url: str
    screen_width: int = 1080
    screen_height: int = 1920


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
async def browse_create(request: BrowseCreateRequest) -> dict:
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

    logger.info(
        "[/sandbox/browse POST] 요청: %s (해상도: %dx%d)",
        request.url, request.screen_width, request.screen_height,
    )
    result = await create_browse_session(request.url, request.screen_width, request.screen_height)

    if "error" in result:
        logger.error("[/sandbox/browse POST] 생성 실패: %s", result["error"])
        raise HTTPException(status_code=503, detail=result["error"])

    logger.info("[/sandbox/browse POST] 생성 완료: %s", result.get("container_id", "")[:12])
    return result


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
