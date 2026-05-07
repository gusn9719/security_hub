# =============================================================================
# backend/services/gemini_service.py
# 역할: Gemini 호출 캡슐화 — 7-B 샌드박스 결과 요약 전용 (DC-25)
#
# 변경 이력:
#   - Sprint 5A: analysis_service.py 에서 분리 신설
#   - Sprint 5E: DC-25 — /analyze 파이프라인에서 Gemini 제거.
#                generate_danger_explanation / generate_suspicious_explanation 삭제.
#                역할을 7-B Browserless/Playwright 결과 요약으로 한정.
#                /analyze 판정 설명은 explanation_service.py 가 담당.
#
# 설계 원칙:
#   - Gemini는 판정자가 아니라 요약자. 판정 결과(safe/suspicious/danger)는
#     호출자가 이미 결정한 후 전달한다.
#   - 호출 실패 시 템플릿 폴백으로 서비스 중단 없음.
# =============================================================================

import os
import logging
from google import genai
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

_MODEL = "gemini-2.5-flash"

# 7-B 요약 실패 시 폴백 메시지
_FINDINGS_FALLBACK = "샌드박스 분석이 완료되었습니다. 상세 내역은 탐지 항목을 확인하세요."


class GeminiService:
    """
    Gemini 호출 싱글턴.

    역할: 7-B 자동 분석(Browserless/Playwright) 탐지 결과 → 한국어 요약문 생성.
    /analyze 파이프라인 판정 설명은 explanation_service.py 가 담당한다 (DC-25).
    """

    def __init__(self) -> None:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            logger.warning("[Gemini] GEMINI_API_KEY 환경 변수 미설정 — 폴백 모드만 동작")
            self._client = None
        else:
            self._client = genai.Client(api_key=api_key)

    def generate_findings_summary(
        self,
        url: str,
        findings: list[str],
    ) -> str:
        """
        7-B 샌드박스 분석 탐지 항목을 한국어 요약문으로 변환한다.

        Browserless/Playwright 가 실제 브라우저로 URL 을 방문하고 수집한
        findings(예: ["팝업 3회 감지", "외부 스크립트 로드 2건"]) 를 받아
        사용자가 이해하기 쉬운 2~3문장 요약을 생성한다.

        판정 결과(안전/의심/위험)는 포함하지 않는다.

        [url]     : 분석 대상 URL
        [findings]: 샌드박스 탐지 항목 목록
        반환값: 한국어 요약 문자열 (Gemini 실패 시 _FINDINGS_FALLBACK)
        """
        if not findings:
            return _FINDINGS_FALLBACK

        fallback = (
            f"샌드박스에서 {len(findings)}개 항목이 탐지되었습니다: "
            + ", ".join(findings[:3])
            + ("..." if len(findings) > 3 else "")
            + "."
        )

        if self._client is None:
            return fallback

        findings_text = "\n".join(f"- {f}" for f in findings)
        prompt = f"""
당신은 사이버 보안 전문가입니다.
아래는 가상 브라우저로 URL을 방문했을 때 자동으로 탐지된 항목들입니다.
사용자가 이해하기 쉽게 이 탐지 결과가 무엇을 의미하는지 2~3문장으로 요약해 주세요.
판정 결과(안전/의심/위험)는 절대 언급하지 말고, 탐지 내용 설명만 작성하세요.

[분석 URL]
{url}

[탐지 항목]
{findings_text}
""".strip()

        try:
            response = self._client.models.generate_content(
                model=_MODEL,
                contents=prompt,
            )
            text = (response.text or "").strip()
            return text if text else fallback
        except Exception as e:
            logger.error("[Gemini] 7-B 요약 생성 실패 — %s", e)
            return fallback


# 싱글턴 인스턴스
gemini_service = GeminiService()
