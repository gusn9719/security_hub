# =============================================================================
# backend/database/whitelist_service.py
# 역할: 화이트리스트 DB 조회 — match_mode 기반 매칭 + Open Redirect 예외 검출
# 변경 이력:
#   - Sprint 5A: 최초 작성 (TEMP_WHITELIST 대체)
#   - Sprint 5A (2차): match_mode 컬럼 반영, 서브도메인 버그 수정, seed 제거
#   - Sprint 5C: OPEN_REDIRECT_PARAMS → SUSPICIOUS_QUERY_PATTERNS (카테고리 매핑 확장),
#                _get_suspicious_categories() 신규 추가,
#                WhitelistResult.suspicious_categories 필드 추가
#   - Sprint 5E: DC-001 — pattern match_mode 제거.
#                .go.kr 형태 TLD 패턴은 신뢰도 낮음(임의 하위 도메인 허용 위험),
#                개별 도메인 등록 또는 suffix 모드로 대체해야 한다.
# =============================================================================

import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse

from database.db_init import get_ro_connection
from database.blacklist_service import extract_domain

logger = logging.getLogger(__name__)


# =============================================================================
# 위험 쿼리스트링 패턴 (카테고리 → 파라미터 목록)
# =============================================================================
SUSPICIOUS_QUERY_PATTERNS: dict[str, list[str]] = {
    "리다이렉트":   ["redirect=", "goto=", "url=", "next=", "return=", "continue="],
    "자격증명":     ["token=", "auth=", "access_token=", "refresh_token=", "passwd=", "password="],
    "파일다운로드": ["download=", "file=", "attachment=", "apk="],
    "로그인우회":   ["login_redirect=", "autologin=", "session="],
}


# =============================================================================
# 결과 타입
# =============================================================================
@dataclass
class WhitelistResult:
    """
    is_whitelisted() 반환 타입.

    hit                 : 화이트리스트 히트 여부
    open_redirect       : Open Redirect 파라미터 감지 여부 (히트여도 SUSPICIOUS 처리)
    suspicious_categories: 감지된 위험 카테고리 목록 (예: ["리다이렉트", "자격증명"])
                          open_redirect=True 일 때 항상 1개 이상 존재
    risk_level          : 'normal' | 'high_risk' (사칭 빈도 극상위 기관)
    match_mode          : 'exact' | 'suffix' | 'pattern' (히트한 규칙, 미스 시 None)
    matched_domain      : 히트한 DB 도메인 엔트리 (디버깅용)
    """
    hit: bool
    open_redirect: bool = False
    suspicious_categories: list[str] = field(default_factory=list)
    risk_level: str = "normal"
    match_mode: str | None = None
    matched_domain: str | None = None


# =============================================================================
# 화이트리스트 조회 서비스
# =============================================================================

class WhitelistService:
    """
    화이트리스트 조회 싱글턴.

    match_mode 별 동작:
      - 'exact'  : domain 컬럼 값과 입력 도메인이 완전 일치할 때만 SAFE
                   (tistory.com → evil.tistory.com 은 SAFE 불가)
      - 'suffix' : 등록 도메인이 입력 도메인과 일치하거나 서브도메인일 때 SAFE
                   (naver.com → login.naver.com, mail.naver.com 도 SAFE)
      - 'pattern': DC-001 에 의해 제거됨. 해당 행은 조회에서 무시한다.
                   사유: .go.kr 형태는 임의 하위 도메인을 전부 허용해 위험.
                   대안: 개별 도메인을 exact/suffix 모드로 등록할 것.
    """

    def is_whitelisted(self, url: str) -> WhitelistResult:
        """
        URL이 화이트리스트에 등록되어 있는지 확인한다.

        [url]: 분석 대상 URL
        반환값: WhitelistResult
        """
        domain = extract_domain(url)
        if not domain:
            return WhitelistResult(hit=False)

        suspicious_categories = self._get_suspicious_categories(url)
        open_redirect = bool(suspicious_categories)

        try:
            with get_ro_connection() as conn:
                # exact 우선, suffix 후순 — pattern 은 DC-001 로 제거되어 무시
                rows = conn.execute(
                    """
                    SELECT domain, match_mode, risk_level
                    FROM whitelist
                    WHERE match_mode IN ('exact', 'suffix')
                    ORDER BY CASE match_mode
                        WHEN 'exact'  THEN 1
                        WHEN 'suffix' THEN 2
                        ELSE 3
                    END
                    """
                ).fetchall()
        except Exception as e:
            logger.error(f"[화이트리스트] DB 조회 오류 — {e}")
            return WhitelistResult(hit=False)

        for row in rows:
            entry_domain = row["domain"]
            mode = row["match_mode"]
            risk = row["risk_level"]

            if mode == "suffix":
                # 정확 일치 or 서브도메인 (e.g. login.naver.com → naver.com)
                matched = (domain == entry_domain) or domain.endswith("." + entry_domain)

            else:  # exact
                # 정확 일치만 — 서브도메인 절대 불가
                matched = (domain == entry_domain)

            if matched:
                logger.info(
                    f"[화이트리스트] 히트 — domain={domain}, "
                    f"entry={entry_domain}, mode={mode}, risk={risk}"
                )
                return WhitelistResult(
                    hit=True,
                    open_redirect=open_redirect,
                    suspicious_categories=suspicious_categories,
                    risk_level=risk,
                    match_mode=mode,
                    matched_domain=entry_domain,
                )

        return WhitelistResult(hit=False)

    def _get_suspicious_categories(self, url: str) -> list[str]:
        """
        URL 쿼리스트링에서 위험 패턴을 검사하여 감지된 카테고리 목록을 반환한다.
        파라미터명 자체가 아닌 카테고리만 반환해 사용자 노출 정보를 최소화한다.

        쿼리스트링 외 경로·프래그먼트는 검사하지 않는다.
        각 패턴 앞에 '&'를 붙여 파라미터 경계를 강제함으로써
        image_url= 이 url= 로 오탐되거나, oauth= 가 auth= 로 오탐되는 경우를 방지한다.

        [url]: 분석 대상 URL
        반환값: 감지된 카테고리 문자열 리스트 (미감지 시 빈 리스트)
        """
        try:
            query = urlparse(url).query.lower()
        except Exception:
            return []
        if not query:
            return []
        # 첫 번째 파라미터도 '&param=' 형태로 통일하여 경계 검사를 단순화한다.
        delimited = "&" + query
        return [
            category
            for category, patterns in SUSPICIOUS_QUERY_PATTERNS.items()
            if any(("&" + pat) in delimited for pat in patterns)
        ]


# 싱글턴 인스턴스
whitelist_service = WhitelistService()
