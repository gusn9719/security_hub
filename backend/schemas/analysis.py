# =============================================================================
# schemas/analysis.py
# 역할: POST /analyze 엔드포인트의 요청(Request)과 응답(Response) 스키마 정의
# Pydantic v2 기반 — FastAPI가 자동으로 JSON 직렬화/역직렬화에 사용한다.
#
# 변경 이력:
#   - Sprint 5A: 최초 작성
#   - Sprint 5E: DC-25 — ExplanationCard 모델 추가, AnalyzeResponse.cards 필드 추가.
#                description(str) 은 Flutter 호환성을 위해 유지.
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


class ExplanationCard(BaseModel):
    """
    단일 설명 카드 스키마.

    explanation_service.EXPLANATION_DICT 의 카드 형식과 1:1 대응.
    Flutter 클라이언트는 이 카드 리스트를 개별 UI 카드로 렌더링한다.

    Attributes:
        icon:  이모지 아이콘 (예: '🚫', '⚠️')
        title: 카드 제목 (예: '악성 URL 데이터베이스에 등록된 주소')
        desc:  카드 상세 설명 (1~2 문장)
    """
    icon: str
    title: str
    desc: str


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
        description:  설명 카드를 합친 텍스트 (구버전 Flutter 호환용)
        action_label: 하단 액션 버튼 텍스트
        cards:        설명 카드 리스트 (Flutter 카드 UI 렌더링용, DC-25 신규)
                      빈 리스트면 클라이언트는 description 을 fallback 으로 사용한다.
    """
    status: RiskStatus
    title: str
    description: str
    action_label: str
    cards: list[ExplanationCard] = Field(default_factory=list)


class VoteRequest(BaseModel):
    """POST /sandbox/votes 요청 스키마."""

    url: str
    session_id: str
    vote: str = Field(..., pattern=r"^(safe|danger|spam|unsure)$")
    device_uuid: str = Field(default="")


class VoteResponse(BaseModel):
    """POST /sandbox/votes 응답 스키마."""

    success: bool
    message: str


class SandboxAutoTestRequest(BaseModel):
    """POST /sandbox/auto-test 요청 스키마."""

    url: str


class SandboxAutoTestResponse(BaseModel):
    """
    POST /sandbox/auto-test 응답 스키마.

    Attributes:
        session_id:     분석 세션 UUID (hex)
        url:            분석 대상 URL
        sandbox_score:  룰 기반 위험 점수 (0~100)
        findings:       탐지된 항목 목록
        summary:        Gemini 생성 한국어 요약 (폴백 시 findings 나열)
        screenshots:    base64 JPEG 스크린샷 목록 (최대 3장)
        final_url:      모든 리다이렉트 후 최종 랜딩 URL
        redirect_count: 301/302 응답 횟수
        error:          오류 메시지 (정상 시 None)
        cached:         캐시에서 반환된 경우 True
    """

    session_id: str
    url: str
    sandbox_score: int
    findings: list[str]
    summary: str
    screenshots: list[str]
    final_url: str
    redirect_count: int
    error: str | None
    cached: bool = False
