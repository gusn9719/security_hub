# =============================================================================
# schemas/analysis.py
# 역할: POST /analyze 엔드포인트의 요청(Request)과 응답(Response) 스키마 정의
# Pydantic v2 기반 — FastAPI가 자동으로 JSON 직렬화/역직렬화에 사용한다.
# =============================================================================

from pydantic import BaseModel, Field
from enum import Enum


class RiskStatus(str, Enum):
    """
    분석 결과의 위험 상태 열거형.
    Flutter 클라이언트의 RiskStatus enum과 값이 일치해야 한다.
    """
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGER = "danger"


class AnalyzeRequest(BaseModel):
    """
    POST /analyze 요청 바디 스키마.

    Attributes:
        text: 사용자가 입력한 피싱 의심 문자 내용 (URL, 메시지 등)
    """
    text: str = Field(
        ...,
        min_length=1,
        max_length=5000,
        description="분석할 피싱 의심 문자 내용",
        examples=["[국민은행] 고객님의 계정이 정지되었습니다. 지금 확인하세요: http://kb-secure.xyz"],
    )


class AnalyzeResponse(BaseModel):
    """
    POST /analyze 응답 바디 스키마.
    Flutter의 AnalysisResult 모델과 필드명 및 타입을 일치시킨다.

    Attributes:
        status:       위험 상태 (safe / suspicious / danger)
        title:        결과 요약 제목 (Flutter UI 상단 표시용)
        description:  위험 사유 상세 설명 (일상 언어)
        action_label: 하단 액션 버튼 텍스트
    """
    status: RiskStatus
    title: str
    description: str
    action_label: str