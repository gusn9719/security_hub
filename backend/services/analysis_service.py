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
#   7. 휴리스틱 스코어링   (13 시그널 + 투표 + sandbox 시그널, 가중합)
#   8. 판정 설명 생성      (explanation_service → cards_to_text)
#
# 판정 기준 (DC-06: 화이트리스트 미스 = 기본 SUSPICIOUS):
#   - 블랙리스트 히트              → DANGER
#   - 화이트리스트 히트 (리다이렉트 없음) → SAFE  ← SAFE 가능한 유일한 경로
#   - 화이트리스트 히트 + 리다이렉트  → SUSPICIOUS
#   - 휴리스틱 score ≥ 70         → DANGER  (휴리스틱은 DANGER 상향만 가능)
#   - 그 외 (score < 70)          → SUSPICIOUS  (알 수 없음 = 의심)
#
# 변경 이력:
#   - Sprint 5A: TEMP_WHITELIST 제거, gemini/url_expander/whitelist 모듈 분리
#   - Sprint 5E: DC-25 — Gemini /analyze 완전 제거, explanation_service 대체.
#                0단계 위험 스킴, 5~6단계 평판 캐시, 7단계 휴리스틱 추가.
#   - Sprint 7 PROMPT-5: vote_counts 시그널 연결 (prior_danger_vote_high/low)
#   - Sprint 7 PROMPT-6: sandbox_score 시그널 연결 (ANL-11)
#   - Sprint 7 PROMPT-7: DAT-06 — analysis_history 비동기 INSERT (BackgroundTasks)
# =============================================================================

import asyncio
import logging
import time

from fastapi import BackgroundTasks

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
from database.vote_service import get_vote_counts
from services.sandbox_service import get_latest_sandbox_score
from database.analysis_history_service import save_analysis_history

logger = logging.getLogger(__name__)


class AnalysisService:
    """
    분석 파이프라인 오케스트레이터.
    판정·설명·조회는 모두 하위 모듈에 위임하고, 흐름만 관리한다.

    DC-25: /analyze 파이프라인에서 Gemini 완전 제거.
    판정 설명은 explanation_service.py 가 담당한다.
    DAT-06: 분석 이력을 BackgroundTasks로 비동기 저장한다.
    """

    async def analyze(
        self,
        request: AnalyzeRequest,
        background_tasks: BackgroundTasks | None = None,
        device_uuid: str = "",
    ) -> AnalyzeResponse:
        start_ms = int(time.monotonic() * 1000)
        text = request.text

        def _schedule_history(
            url: str,
            verdict: str,
            registered: str | None = None,
            triggered: dict | None = None,
            score: int | None = None,
            vote_danger: int = 0,
            vote_safe: int = 0,
        ) -> None:
            if background_tasks is None:
                return
            elapsed = int(time.monotonic() * 1000) - start_ms
            background_tasks.add_task(
                save_analysis_history,
                url=url,
                verdict=verdict,
                registered_domain=registered,
                triggered_signals=triggered,
                heuristic_score=score,
                prior_vote_danger=vote_danger,
                prior_vote_safe=vote_safe,
                response_time_ms=elapsed,
                device_uuid=device_uuid,
            )

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
                _schedule_history(
                    url=url, verdict="danger",
                    registered=get_registered_domain(url),
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
        # P0-3 (보고서 D-2): expand_url 은 requests.head() 동기 I/O (hop 당
        # 최대 5초). asyncio.to_thread 로 분리하지 않으면 단축 URL 1건만으로
        # 이벤트 루프가 최대 15초 점유 → 다른 모든 요청 마비.
        expanded_urls: list[str] = []
        for url in raw_urls:
            if is_short_url(url):
                expanded = await asyncio.to_thread(expand_url, url)
            else:
                expanded = url
            expanded_urls.append(expanded)

        # 대표 URL과 등록 도메인 — 이후 모든 단계에서 공유
        primary_url = expanded_urls[0]
        registered = get_registered_domain(primary_url)

        # ── 3a단계: url_hash 전용 블랙리스트 매칭 ───────────────────────
        # 정확 일치(1순위)만 먼저 체크. domain/registered_domain(2·3순위) 매칭은
        # 화이트리스트 체크(4단계) 이후 3b단계에서 수행한다.
        # Fix: whitelisted_safe DANGER 오판 방지 — naver.com/kakao.com 등
        # 등록 도메인이 블랙리스트에 있어도 화이트리스트 도메인이 먼저 보호됨.
        # P0-3: SQLite I/O 도 동기 — to_thread 로 분리.
        try:
            hit = await asyncio.to_thread(check_blacklist, expanded_urls, True)
        except Exception as e:
            logger.error("[블랙리스트] url_hash 조회 오류 — %s", e)
            hit = None

        if hit:
            category = hit.get("category")
            cards = build_blacklist_cards(category)
            logger.warning("[파이프라인] 블랙리스트 DANGER (url_hash) — category=%s", category)
            _schedule_history(
                url=primary_url, verdict="danger", registered=registered,
            )
            return AnalyzeResponse(
                status=RiskStatus.DANGER,
                title="위험한 링크입니다",
                description=cards_to_text(cards),
                action_label="발신번호 차단하기",
                cards=cards,
            )

        # ── 4단계: 화이트리스트 매칭 ──────────────────────────────────────
        # P0-2 (보고서 D-1): 다중 URL 입력 시 primary_url 만 SAFE 검사하던
        # 기존 동작은 "kakao.com 공지 + kb-secure.xyz 인증" 같이 합법 도메인을
        # 앞에 둔 입력에서 피싱 URL 분석을 통째로 건너뛰는 결함이 있었다.
        # 보수적 처리: SAFE 반환은 expanded_urls 전부가 화이트리스트에
        # (open_redirect 없이) 히트할 때만 허용. 하나라도 미히트면 DC-06 에
        # 따라 SUSPICIOUS 분기로 떨어진다 (3단계에서 블랙리스트는 이미 전수
        # 검사 완료 상태).
        # P0-3: 화이트리스트는 매 요청마다 전수 fetchall + 파이썬 루프(H-1) →
        # 동기 I/O. to_thread 로 분리.
        wl = await asyncio.to_thread(whitelist_service.is_whitelisted, primary_url)

        if wl.hit and not wl.open_redirect:
            # 다른 URL 도 모두 화이트리스트 히트인지 확인
            other_urls = expanded_urls[1:]
            non_whitelisted: list[str] = []
            for ou in other_urls:
                ou_wl = await asyncio.to_thread(whitelist_service.is_whitelisted, ou)
                if not (ou_wl.hit and not ou_wl.open_redirect):
                    non_whitelisted.append(ou)

            if not non_whitelisted:
                cards = build_safe_cards(wl.risk_level)
                logger.info(
                    "[파이프라인] 화이트리스트 SAFE — mode=%s risk=%s (검사 URL=%d)",
                    wl.match_mode, wl.risk_level, len(expanded_urls),
                )
                _schedule_history(
                    url=primary_url, verdict="safe", registered=registered,
                )
                return AnalyzeResponse(
                    status=RiskStatus.SAFE,
                    title="안전한 링크입니다",
                    description=cards_to_text(cards),
                    action_label="원본 URL 열기",
                    cards=cards,
                )

            # 다른 URL 중 화이트리스트 미히트 — SAFE 승격 차단, 미히트 URL 로
            # primary 를 교체하여 이후 휴리스틱이 진짜 의심 대상을 평가하도록 한다.
            logger.warning(
                "[파이프라인] 다중 URL — 화이트리스트 SAFE 차단 (미히트 %d건). "
                "primary 를 첫 미히트 URL 로 교체: %s",
                len(non_whitelisted), non_whitelisted[0],
            )
            primary_url = non_whitelisted[0]
            registered = get_registered_domain(primary_url)
            wl = await asyncio.to_thread(whitelist_service.is_whitelisted, primary_url)

        if wl.hit and wl.open_redirect:
            logger.warning(
                "[파이프라인] 화이트리스트 Open Redirect — %s (categories=%s)",
                primary_url, wl.suspicious_categories,
            )
            cards = build_explanation_cards(
                {}, verdict="SUSPICIOUS", extra_keys=["open_redirect"]
            )
            _schedule_history(
                url=primary_url, verdict="suspicious", registered=registered,
            )
            return AnalyzeResponse(
                status=RiskStatus.SUSPICIOUS,
                title="의심스러운 링크입니다",
                description=cards_to_text(cards),
                action_label="가상환경에서 테스트",
                cards=cards,
            )

        # ── 3b단계: domain/registered_domain 블랙리스트 매칭 ────────────
        # 화이트리스트 미히트(또는 open_redirect) URL에 대해 2·3순위 매칭 수행.
        # 화이트리스트 통과 후 실행되므로 whitelisted_safe DANGER 오판 없음.
        try:
            hit = await asyncio.to_thread(check_blacklist, expanded_urls)
        except Exception as e:
            logger.error("[블랙리스트] domain/reg_domain 조회 오류 — %s", e)
            hit = None

        if hit:
            category = hit.get("category")
            cards = build_blacklist_cards(category)
            logger.warning("[파이프라인] 블랙리스트 DANGER (domain/reg) — category=%s", category)
            _schedule_history(
                url=primary_url, verdict="danger", registered=registered,
            )
            return AnalyzeResponse(
                status=RiskStatus.DANGER,
                title="위험한 링크입니다",
                description=cards_to_text(cards),
                action_label="발신번호 차단하기",
                cards=cards,
            )

        # ── 5단계: 도메인 평판 캐시 조회 ──────────────────────────────────
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
        # asyncio.to_thread: 블로킹 I/O(WHOIS/SSL)가 이벤트 루프를 점유하지 않도록 분리
        # save_reputation 내부에서 skipped 항목(IP 등)은 자동으로 캐시 제외
        if domain_evidence is None:
            try:
                domain_evidence = await asyncio.to_thread(
                    analyze_domain_reputation, primary_url
                )
                if registered and domain_evidence:
                    save_reputation(registered, domain_evidence)
            except Exception as e:
                logger.warning("[도메인평판] 조회 실패 (무시): %s", e)
                domain_evidence = None

        # ── 7단계 직전: 사용자 투표 이력 조회 ────────────────────────────
        # P0-3: SQLite I/O — to_thread 로 분리.
        try:
            vote_counts = await asyncio.to_thread(get_vote_counts, primary_url)
        except Exception as e:
            logger.warning("[파이프라인] 투표 조회 실패 (무시): %s", e)
            vote_counts = None

        # ── 7단계 직전: 7-B 샌드박스 점수 조회 (ANL-11) ─────────────────
        try:
            prior_sandbox_score = await asyncio.to_thread(get_latest_sandbox_score, primary_url)
        except Exception as e:
            logger.warning("[파이프라인] sandbox_score 조회 실패 (무시): %s", e)
            prior_sandbox_score = None

        # ── 7단계: 휴리스틱 스코어링 ──────────────────────────────────────
        # 13 시그널 + 투표 + sandbox 시그널 가중합. 각 인수는 선택적.
        heuristic = score_url(
            primary_url,
            domain_evidence=domain_evidence,
            vote_counts=vote_counts,
            sandbox_score=prior_sandbox_score,
        )

        # 공통 history 인수
        vote_danger = (vote_counts or {}).get("danger", 0)
        vote_safe   = (vote_counts or {}).get("safe", 0)

        # ── 8단계: 판정 및 설명 카드 생성 (DC-25: Gemini 미호출) ───────────
        if heuristic.verdict == "DANGER":
            cards = build_explanation_cards(heuristic.triggered, verdict="DANGER")
            _schedule_history(
                url=primary_url, verdict="danger", registered=registered,
                triggered=heuristic.triggered, score=heuristic.score,
                vote_danger=vote_danger, vote_safe=vote_safe,
            )
            return AnalyzeResponse(
                status=RiskStatus.DANGER,
                title="위험한 링크입니다",
                description=cards_to_text(cards),
                action_label="발신번호 차단하기",
                cards=cards,
            )

        # 휴리스틱 score < 70 — DC-06: 화이트리스트 미스 = 기본 SUSPICIOUS
        # 점수가 낮아도 "알 수 없음"이지 "안전"이 아니다.
        # SAFE 판정은 화이트리스트 히트(4단계)만 가능.
        logger.info(
            "[파이프라인] DC-06 SUSPICIOUS (화이트리스트 미히트) — 휴리스틱=%s score=%d registered=%s",
            heuristic.verdict, heuristic.score, registered,
        )
        cards = build_explanation_cards(heuristic.triggered, verdict="SUSPICIOUS")
        _schedule_history(
            url=primary_url, verdict="suspicious", registered=registered,
            triggered=heuristic.triggered, score=heuristic.score,
            vote_danger=vote_danger, vote_safe=vote_safe,
        )
        return AnalyzeResponse(
            status=RiskStatus.SUSPICIOUS,
            title="의심스러운 링크입니다",
            description=cards_to_text(cards),
            action_label="가상환경에서 테스트",
            cards=cards,
        )


# 싱글턴 인스턴스
analysis_service = AnalysisService()
