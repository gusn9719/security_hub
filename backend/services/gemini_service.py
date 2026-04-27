# =============================================================================
# backend/services/gemini_service.py
# 역할: Gemini 호출 캡슐화 (DANGER/SUSPICIOUS 사유 설명 생성 전용)
# 설계 원칙:
#   - Gemini는 판정자가 아니라 설명자(DC-04). 판정 변경 절대 없음.
#   - 호출 실패 시 템플릿 폴백으로 서비스 중단 없음.
# 변경 이력:
#   - Sprint 5A: analysis_service.py 에서 분리 신설
# =============================================================================

import os
import logging
from google import genai
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

_MODEL = "gemini-2.5-flash"


# =============================================================================
# 폴백 템플릿
# =============================================================================
DANGER_TEMPLATES: dict[str, str] = {
    "공공기관": "이 URL은 공공기관을 사칭한 스미싱으로, KISA C-TAS에 신고된 전적이 있습니다.",
    "택배":     "이 URL은 택배사를 사칭한 스미싱으로, KISA C-TAS에 신고된 전적이 있습니다.",
    "금융":     "이 URL은 금융기관을 사칭한 스미싱으로, KISA C-TAS에 신고된 전적이 있습니다.",
    "기타":     "이 URL은 KISA C-TAS에 악성 URL로 신고된 전적이 있습니다.",
}

SUSPICIOUS_FALLBACK = (
    "입력하신 URL에서 파악하기 어려운 요소가 발견되었습니다. "
    "가상 환경에서 안전하게 확인해 보시길 권장합니다."
)


# =============================================================================
# Gemini 서비스
# =============================================================================

class GeminiService:
    """
    Gemini 호출 싱글턴.

    공개 메서드 두 개 모두 "설명만" 생성한다 — 판정 결과(safe/suspicious/danger)는
    호출자(analysis_service)가 책임진다.
    """

    def __init__(self) -> None:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            logger.warning("[Gemini] GEMINI_API_KEY 환경 변수 미설정 — 폴백 모드만 동작")
            self._client = None
        else:
            self._client = genai.Client(api_key=api_key)

    # -------------------------------------------------------------------------
    # DANGER: 블랙리스트 히트 시 위험 사유 설명
    # -------------------------------------------------------------------------
    def generate_danger_explanation(self, sms_text: str, category: str | None) -> str:
        """
        블랙리스트 히트 문자에 대해 "왜 위험한지" 한국어 설명을 생성한다.

        [sms_text]: 사용자 입력 문자 원문
        [category]: 블랙리스트 카테고리 (공공기관/택배/금융/기타 또는 None)
        반환값: 한국어 설명 문자열 (Gemini 실패 시 카테고리 템플릿 폴백)
        """
        fallback = DANGER_TEMPLATES.get(category or "", DANGER_TEMPLATES["기타"])

        if self._client is None:
            return fallback

        prompt = f"""
당신은 사이버 보안 전문가입니다.
다음 텍스트는 KISA C-TAS에 악성 피싱(스미싱)으로 이미 신고된 문자입니다.
사용자가 이해하기 쉽게 이 문자가 왜 위험한지, 어떤 수법인지 2~3문장으로 설명해주세요.
판정 결과(안전/의심/위험)는 절대 언급하지 말고, 설명만 작성하세요.

[문자 내용]
{sms_text}
""".strip()

        try:
            response = self._client.models.generate_content(
                model=_MODEL,
                contents=prompt,
            )
            text = (response.text or "").strip()
            return text if text else fallback
        except Exception as e:
            logger.error(f"[Gemini] DANGER 설명 생성 실패 — {e}")
            return fallback

    # -------------------------------------------------------------------------
    # SUSPICIOUS: 블랙·화이트 모두 미스 시 의심 사유 설명 (DC-06)
    # -------------------------------------------------------------------------
    def generate_suspicious_explanation(self, url: str, sms_text: str) -> str:
        """
        미확인 URL 에 대해 "왜 의심스러운지" 한국어 설명을 생성한다.

        [url]: 분석 대상 URL (대표 1건)
        [sms_text]: 사용자 입력 문자 원문 (맥락 제공용)
        반환값: 한국어 설명 문자열 (Gemini 실패 시 SUSPICIOUS_FALLBACK)
        """
        if self._client is None:
            return SUSPICIOUS_FALLBACK

        prompt = f"""
당신은 사이버 보안 전문가입니다.
아래 문자 메시지와 URL이 왜 의심스러운지 사용자가 이해하기 쉽게 2~3문장으로 설명해주세요.
긴급함 유도, 사칭, 비정상적인 도메인 등 구체적인 근거를 포함하세요.
판정 결과(안전/의심/위험)는 절대 언급하지 말고, 설명만 작성하세요.

[입력 텍스트]
{sms_text}

[대상 URL]
{url}
""".strip()

        try:
            response = self._client.models.generate_content(
                model=_MODEL,
                contents=prompt,
            )
            text = (response.text or "").strip()
            return text if text else SUSPICIOUS_FALLBACK
        except Exception as e:
            logger.error(f"[Gemini] SUSPICIOUS 설명 생성 실패 — {e}")
            return SUSPICIOUS_FALLBACK


# 싱글턴 인스턴스
gemini_service = GeminiService()
