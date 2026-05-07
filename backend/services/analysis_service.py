# =============================================================================
# backend/services/analysis_service.py
# 역할: 분석 파이프라인 오케스트레이터 (Early Return)
#
# 파이프라인 (DC-25 반영, Gemini /analyze 완전 제거):
#   0. URL 추출           (URL 없음 → SUSPICIOUS 안내)
#   1. 위험 스킴 체크      (javascript:/data:/vbscript:/file:/ → DANGER)
#   2. 단축 URL 해제       (최대 3-hop, SSRF 방어)
#   3. 블랙리스트 매칭     (→ DANGER + 카테고리별 설명 카드)
#   4. 화이트리스트 매칭   (→ SAFE | SUSPICIOUS Open Redirect)
#   5. 도메인 평판 캐시    (domain_reputation_cache, 7일 TTL)
#   6. 도메인 평판 조회    (캐시 미스 시 WHOIS/SSL → 캐시 저장)
#   7. 휴리스틱 스코어링   (13 시그널 + 도메인 평판 시그널, 가중합)
#   8. 판정 설명 생성      (explanation_service → cards_to_text)
#
# 판정 기준 (DC-06: 화이트리스트 미스 = 기본 SUSPICIOUS):
#   - 블랙리스트 히트              → DANGER
#   - 화이트리스트 히트 (리다이렉트 없음) → SAFE  ← SAFE 가능한 유일한 경로
#   - 화이트리스트 히트 + 리다이렉트  → SUSPICIOUS
#   - 휴리스틱 score ≥ 60         → DANGER  (휴리스틱은 DANGER 상향만 가능)
#   - 그 외 (score < 60)          → SUSPICIOUS  (알 수 없음 = 의심)
#
# 변경 이력:
#   - Sprint 5A: TEMP_WHITELIST 제거, gemini/url_expander/whitelist 모듈 분리
#   - Sprint 5E: DC-25 — Gemini /analyze 완전 제거, explanation_service 대체.
#                0단계 위험 스킴, 5~6단계 평판 캐시, 7단계 휴리스틱 추가.
# =============================================================================

import logging

from schemas.analysis import AnalyzeRequest, AnalyzeResponse, RiskStatus
from database.blacklist_service import extract_urls, check_blacklist
from database.whitelist_service import whitelist_service
from services.url_validator import check_dangerous_scheme, get_registered_domain
from services.url_expander import expand_url, is_short_url
from services.heuristic_scorer import score_url
from services.explanation_service import (
    build_explanation_cards,
    build_blacklist_cards,
    build_safe_cards,
    cards_to_text,
)
from services.reputation_cache_service import get_cached_reputation, save_reputation
from services.domain_reputation_service import analyze_domain_reputation

logger = logging.getLogger(__name__)


class AnalysisService:
    """
    분석 파이프라인 오케스트레이터.
    판정·설명·조회는 모두 하위 모듈에 위임하고, 흐름만 관리한다.

    DC-25: /analyze 파이프라인에서 Gemini 완전 제거.
    판정 설명은 explanation_service.py 가 담당한다.
    """

    async def analyze(self, request: AnalyzeRequest) -> AnalyzeResponse:
        text = request.text

        # ── 0단계: URL 추출 ────────────────────────────────────────────────
        raw_urls = extract_urls(text)

        if not raw_urls:
            logger.info("[파이프라인] URL 없음 — SUSPICIOUS 반환")
            return AnalyzeResponse(
                status=RiskStatus.SUSPICIOUS,
                title="URL을 찾을 수 없습니다",
                description=(
                    "입력하신 텍스트에서 분석 가능한 URL을 찾지 못했습니다. "
                    "URL이 포함된 문자 전체를 다시 입력해 주세요."
                ),
                action_label="다시 입력",
                cards=[],
            )

        # ── 1단계: 위험 스킴 체크 ─────────────────────────────────────────
        # javascript:/data:/vbscript:/file:/ 등 비표준 스킴 → 즉시 DANGER
        for url in raw_urls:
            if check_dangerous_scheme(url):
                logger.warning("[파이프라인] 위험 스킴 감지 — %s", url)
                cards = build_explanation_cards(
                    {}, verdict="DANGER", extra_keys=["dangerous_scheme"]
                )
                return AnalyzeResponse(
                    status=RiskStatus.DANGER,
                    title="위험한 링크입니다",
                    description=cards_to_text(cards),
                    action_label="발신번호 차단하기",
                    cards=cards,
                )

        # ── 2단계: 단축 URL 해제 ──────────────────────────────────────────
        # 최대 3-hop 추적, SSRF 방어(사설 IP 차단), 실패 시 원본 유지
        expanded_urls: list[str] = []
        for url in raw_urls:
            expanded = expand_url(url) if is_short_url(url) else url
            expanded_urls.append(expanded)

        # ── 3단계: 블랙리스트 매칭 ────────────────────────────────────────
        try:
            hit = check_blacklist(expanded_urls)
        except Exception as e:
            logger.error("[블랙리스트] 조회 오류 — %s", e)
            hit = None

        if hit:
            category = hit.get("category")
            cards = build_blacklist_cards(category)
            logger.warning("[파이프라인] 블랙리스트 DANGER — category=%s", category)
            return AnalyzeResponse(
                status=RiskStatus.DANGER,
                title="위험한 링크입니다",
                description=cards_to_text(cards),
                action_label="발신번호 차단하기",
                cards=cards,
            )

        # ── 4단계: 화이트리스트 매칭 ──────────────────────────────────────
        # 대표 URL = 첫 번째 확장 URL (다중 URL 입력 시에도 1건 기준)
        primary_url = expanded_urls[0]
        wl = whitelist_service.is_whitelisted(primary_url)

        if wl.hit and not wl.open_redirect:
            cards = build_safe_cards(wl.risk_level)
            logger.info(
                "[파이프라인] 화이트리스트 SAFE — mode=%s risk=%s",
                wl.match_mode, wl.risk_level,
            )
            return AnalyzeResponse(
                status=RiskStatus.SAFE,
                title="안전한 링크입니다",
                description=cards_to_text(cards),
                action_label="원본 URL 열기",
                cards=cards,
            )

        if wl.hit and wl.open_redirect:
            logger.warning(
                "[파이프라인] 화이트리스트 Open Redirect — %s (categories=%s)",
                primary_url, wl.suspicious_categories,
            )
            cards = build_explanation_cards(
                {}, verdict="SUSPICIOUS", extra_keys=["open_redirect"]
            )
            return AnalyzeResponse(
                status=RiskStatus.SUSPICIOUS,
                title="의심스러운 링크입니다",
                description=cards_to_text(cards),
                action_label="가상환경에서 테스트",
                cards=cards,
            )

        # ── 5단계: 도메인 평판 캐시 조회 ──────────────────────────────────
        registered = get_registered_domain(primary_url)
        domain_evidence: dict | None = None

        if registered:
            domain_evidence = get_cached_reputation(registered)
            logger.debug(
                "[파이프라인] 평판 캐시 %s — %s",
                "히트" if domain_evidence else "미스",
                registered,
            )

        # ── 6단계: 도메인 평판 조회 (캐시 미스 시) ────────────────────────
        # WHOIS 등록일 + SSL 인증서 조회 (외부 I/O — graceful 처리)
        # save_reputation 내부에서 skipped 항목(IP 등)은 자동으로 캐시 제외
        if domain_evidence is None:
            try:
                domain_evidence = analyze_domain_reputation(primary_url)
                if registered and domain_evidence:
                    save_reputation(registered, domain_evidence)
            except Exception as e:
                logger.warning("[도메인평판] 조회 실패 (무시): %s", e)
                domain_evidence = None

        # ── 7단계: 휴리스틱 스코어링 ──────────────────────────────────────
        # 13 시그널 가중합. domain_evidence 는 선택적 — 없어도 동작.
        heuristic = score_url(primary_url, domain_evidence=domain_evidence)

        # ── 8단계: 판정 및 설명 카드 생성 (DC-25: Gemini 미호출) ───────────
        if heuristic.verdict == "DANGER":
            cards = build_explanation_cards(heuristic.triggered, verdict="DANGER")
            return AnalyzeResponse(
                status=RiskStatus.DANGER,
                title="위험한 링크입니다",
                description=cards_to_text(cards),
                action_label="발신번호 차단하기",
                cards=cards,
            )

        # 휴리스틱 score < 60 — DC-06: 화이트리스트 미스 = 기본 SUSPICIOUS
        # 점수가 낮아도 "알 수 없음"이지 "안전"이 아니다.
        # SAFE 판정은 화이트리스트 히트(4단계)만 가능.
        logger.info(
            "[파이프라인] 휴리스틱 SUSPICIOUS — score=%d registered=%s",
            heuristic.score, registered,
        )
        cards = build_explanation_cards(heuristic.triggered, verdict="SUSPICIOUS")
        return AnalyzeResponse(
            status=RiskStatus.SUSPICIOUS,
            title="의심스러운 링크입니다",
            description=cards_to_text(cards),
            action_label="가상환경에서 테스트",
            cards=cards,
        )


# 싱글턴 인스턴스
analysis_service = AnalysisService()
