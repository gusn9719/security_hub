# =============================================================================
# routers/analyze.py
# 역할: POST /analyze 엔드포인트 정의
# 책임 분리 원칙: HTTP 처리만 담당하고 분석 로직은 AnalysisService에 위임한다.
# =============================================================================

from fastapi import APIRouter
from schemas.analysis import AnalyzeRequest, AnalyzeResponse
from services.analysis_service import analysis_service

router = APIRouter(
    prefix="/analyze",
    tags=["analyze"],
)


@router.post(
    "",
    response_model=AnalyzeResponse,
    summary="피싱 의심 텍스트 분석",
    description="입력된 문자/URL을 분석하여 safe / suspicious / danger 상태와 상세 설명을 반환합니다.",
)
async def analyze_text(request: AnalyzeRequest) -> AnalyzeResponse:
    """
    피싱 의심 텍스트 분석 엔드포인트.

    Args:
        request: 분석할 텍스트를 담은 요청 바디

    Returns:
        분석 결과 (위험 상태, 제목, 설명, 액션 레이블)
    """
    return await analysis_service.analyze(request)