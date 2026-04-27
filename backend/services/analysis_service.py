# =============================================================================
# backend/services/analysis_service.py
# 역할: 분석 파이프라인 오케스트레이터 (Early Return)
# 설계 원칙 (Sprint 5A):
#   1. 단축 URL 해제 → 블랙리스트 → 화이트리스트 → SUSPICIOUS 폴백
#   2. Gemini 는 판정자가 아니라 설명자 (DC-04). 판정 변경 없음.
#   3. 블랙·화이트 미스 → 무조건 SUSPICIOUS + Gemini 의심사유 설명 (DC-06).
# 변경 이력:
#   - Sprint 5A: TEMP_WHITELIST 제거, gemini/url_expander/whitelist 모듈 분리,
#                데드코드(_parse_gemini_response) 제거
# =============================================================================

import logging

from schemas.analysis import AnalyzeRequest, AnalyzeResponse, RiskStatus
from database.blacklist_service import extract_urls, check_blacklist
from database.whitelist_service import whitelist_service
from services.url_expander import expand_url, is_short_url
from services.gemini_service import gemini_service

logger = logging.getLogger(__name__)


class AnalysisService:
    """
    분석 파이프라인 오케스트레이터.
    실제 판정/설명/조회는 모두 하위 모듈에 위임하고, 흐름만 관리한다.
    """

    async def analyze(self, request: AnalyzeRequest) -> AnalyzeResponse:
        text = request.text

        # ── 0단계: URL 추출 ────────────────────────────────────────────────
        raw_urls = extract_urls(text)

        if not raw_urls:
            # URL 자체가 없으면 판정 보류 — SUSPICIOUS + 안내
            logger.info("[파이프라인] URL 없음 — SUSPICIOUS 반환")
            return AnalyzeResponse(
                status=RiskStatus.SUSPICIOUS,
                title="URL을 찾을 수 없습니다",
                description=(
                    "입력하신 텍스트에서 분석 가능한 URL을 찾지 못했습니다. "
                    "URL이 포함된 문자 전체를 다시 입력해 주세요."
                ),
                action_label="다시 입력",
            )

        # ── 1단계: 단축 URL 해제 ───────────────────────────────────────────
        expanded_urls: list[str] = []
        for url in raw_urls:
            if is_short_url(url):
                expanded_urls.append(expand_url(url))
            else:
                expanded_urls.append(url)

        # ── 2단계: 블랙리스트 매칭 ─────────────────────────────────────────
        try:
            hit = check_blacklist(expanded_urls)
        except Exception as e:
            logger.error(f"[블랙리스트] 조회 오류 — {e}")
            hit = None

        if hit:
            return self._build_danger_response(hit, text)

        # ── 3단계: 화이트리스트 매칭 ───────────────────────────────────────
        # 대표 URL = 첫 번째 (확장 후) URL — 다중 URL 입력의 경우에도 1건 기준
        primary_url = expanded_urls[0]
        wl = whitelist_service.is_whitelisted(primary_url)

        if wl.hit and not wl.open_redirect:
            return self._build_safe_response(wl.risk_level)

        if wl.hit and wl.open_redirect:
            logger.warning(f"[화이트리스트] Open Redirect 감지 — {primary_url}")
            return self._build_open_redirect_response(primary_url, text)

        # ── 4단계: 둘 다 미스 → SUSPICIOUS + Gemini 사유 설명 ─────────────
        return self._build_suspicious_response(primary_url, text)

    # =========================================================================
    # 응답 빌더 — 각 분기별로 하나씩
    # =========================================================================

    def _build_danger_response(self, hit: dict, sms_text: str) -> AnalyzeResponse:
        """블랙리스트 히트 → DANGER + Gemini 위험사유 설명."""
        category = hit.get("category")
        description = gemini_service.generate_danger_explanation(sms_text, category)
        return AnalyzeResponse(
            status=RiskStatus.DANGER,
            title="위험한 링크입니다",
            description=description,
            action_label="발신번호 차단하기",
        )

    def _build_safe_response(self, risk_level: str = "normal") -> AnalyzeResponse:
        """화이트리스트 히트 → SAFE. Gemini 미호출.
        risk_level='high_risk' 이면 경고 문구 추가 (사칭 빈도 극상위 기관).
        """
        if risk_level == "high_risk":
            description = (
                "화이트리스트에 등록된 검증된 도메인입니다.\n\n"
                "⚠️ 이 기관은 스미싱 사칭 빈도가 매우 높습니다. "
                "도메인 철자를 한 번 더 확인하세요."
            )
        else:
            description = "화이트리스트에 등록된 검증된 도메인입니다."
        return AnalyzeResponse(
            status=RiskStatus.SAFE,
            title="안전한 링크입니다",
            description=description,
            action_label="원본 URL 열기",
        )

    def _build_open_redirect_response(self, url: str, sms_text: str) -> AnalyzeResponse:
        """화이트리스트 도메인이지만 Open Redirect 감지 → SUSPICIOUS."""
        description = gemini_service.generate_suspicious_explanation(url, sms_text)
        return AnalyzeResponse(
            status=RiskStatus.SUSPICIOUS,
            title="의심스러운 링크입니다",
            description=(
                "신뢰 도메인이지만 외부로 우회시키는 리다이렉트 파라미터가 포함되어 있어 "
                "안전을 보장할 수 없습니다.\n\n" + description
            ),
            action_label="가상환경에서 테스트",
        )

    def _build_suspicious_response(self, url: str, sms_text: str) -> AnalyzeResponse:
        """블랙·화이트 모두 미스 → SUSPICIOUS + Gemini 의심사유 설명 (DC-06)."""
        description = gemini_service.generate_suspicious_explanation(url, sms_text)
        return AnalyzeResponse(
            status=RiskStatus.SUSPICIOUS,
            title="의심스러운 링크입니다",
            description=description,
            action_label="가상환경에서 테스트",
        )


# 싱글턴 인스턴스
analysis_service = AnalysisService()
