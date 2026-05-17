# =============================================================================
# backend/services/heuristic_scorer.py
# 역할: 5단계 — 다중 시그널 가중합 휴리스틱 스코어링
#
# 설계 원칙:
#   - 판정은 score 임계값만으로 결정. 개별 시그널이 직접 판정하지 않음.
#   - domain_evidence(도메인 평판)는 선택적 입력 — 없어도 동작.
#   - KISA 웹 취약점 가이드 EP·IL·SF·FD·WM·SI 항목 매핑 반영.
#
# 임계값:
#   DANGER_THRESHOLD     = 70  → RiskStatus.DANGER
#   SUSPICIOUS_THRESHOLD = 30  → RiskStatus.SUSPICIOUS
#   미만                       → RiskStatus.SAFE (추가 확인 불요)
# =============================================================================

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from services.url_validator import (
    get_registered_domain,
    normalize_idn_hostname,
    has_double_encoding,
)

logger = logging.getLogger(__name__)


# =============================================================================
# 임계값
# =============================================================================

DANGER_THRESHOLD:     int = 70
SUSPICIOUS_THRESHOLD: int = 30


# =============================================================================
# 시그널별 가중치 (KISA 근거 항목 주석 포함)
# =============================================================================

_WEIGHTS: dict[str, int] = {
    # SI (서버 정보 노출): IP 주소 직접 사용 — 추적 회피 목적
    "ip_in_url":              35,

    # WM (워터마크/브랜드): 서브도메인이 'naver.com.evil.kr' 형태로 도메인 위장
    "subdomain_spoofing":     30,

    # WM: 브랜드 키워드가 URL에 있으나 등록 도메인이 해당 브랜드 소유가 아님
    "brand_keyword_mismatch": 20,

    # SF (특수 형식): 유니코드 혼동 문자(키릴/그리스 등) 사용한 homograph 공격
    "homograph_idn":          25,

    # EP (인코딩 우회): %252F 등 이중 인코딩으로 보안 필터 우회 시도
    "double_encoding":        15,

    # FD (파일 다운로드): .apk/.exe 등 악성 파일 직링크 — 단독으로도 SUSPICIOUS 충분
    "dangerous_extension":    35,

    # 일반: 피싱에 대량 사용되는 저가 TLD
    "suspicious_tld":         10,

    # IL (입력 길이): 서브도메인 4레벨 이상 — 추적 혼란 목적
    "excessive_subdomains":   15,

    # 일반: 비표준 포트 사용
    "port_in_url":            10,

    # IL: URL 전체 길이 100자 초과
    "url_too_long":            5,

    # 도메인 평판 시그널 (domain_evidence 에서 전달됨)
    "new_domain":             20,   # 등록 30일 이내
    "fresh_infrastructure":   15,   # 도메인 + SSL 모두 최신 (단기 피싱 인프라)
    "whois_no_record":        20,   # WHOIS 레코드 없음 (익명 등록)

    # 사용자 투표 시그널 (vote_counts 에서 전달됨)
    "prior_danger_vote_high": 35,   # danger≥10 & danger>safe
    "prior_danger_vote_low":  20,   # danger≥3  & danger>safe

    # 7-B 샌드박스 점수 시그널 (ANL-11)
    "sandbox_danger_score":   30,   # 7-B sandbox_score ≥ 70
}


# =============================================================================
# 탐지 기준 상수
# =============================================================================

# KISA FD 항목: 악성 앱·실행파일 확장자
_DANGEROUS_EXTENSIONS: frozenset[str] = frozenset({
    ".apk", ".exe", ".bat", ".cmd", ".scr",
    ".vbs", ".ps1", ".jar", ".msi", ".dmg",
})

# 피싱에 자주 사용되는 TLD (저가 대량구매 가능)
_SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    ".xyz", ".top", ".club", ".shop", ".site", ".online",
    ".live", ".click", ".link", ".store", ".cyou", ".icu",
    ".uno", ".sbs", ".mom", ".lol", ".bar", ".pw", ".fun",
    ".world", ".space", ".website", ".stream", ".press",
})

# 서브도메인 위장 탐지: 유명 TLD 가 서브도메인 레벨에 포함된 경우
_COMMON_TLDS_IN_SUBDOMAINS: frozenset[str] = frozenset({
    "com", "net", "org", "co", "kr", "jp", "us",
})

# WM 항목: 사칭 빈도 높은 브랜드 키워드
# 단어 경계 매칭으로 오탐 방지 (kb → okb 오탐 방지)
_BRAND_KEYWORDS: list[str] = [
    "naver", "kakao", "daum", "toss", "kbank",
    "shinhan", "woori", "hana", "ibk", "keb",
    "coupang", "baemin", "gmarket", "paypal",
    "samsung", "apple", "google", "microsoft", "amazon", "netflix",
    "nhis",   # 국민건강보험
    "hometax", "wetax", "irs",   # 국세청·지방세
]

# 각 브랜드의 공식 등록 도메인 (부분 일치 허용)
_BRAND_OFFICIAL_DOMAINS: dict[str, frozenset[str]] = {
    "naver":     frozenset({"naver.com", "naver.net", "navercorp.com"}),
    "kakao":     frozenset({"kakao.com", "kakaobank.com", "kakaopay.com", "daum.net"}),
    "daum":      frozenset({"daum.net", "kakao.com"}),
    "toss":      frozenset({"toss.im", "toss.securities", "viva.com"}),
    "kbank":     frozenset({"kbanknow.com"}),
    "shinhan":   frozenset({"shinhan.com", "shinhancard.com", "shinhanlife.co.kr"}),
    "woori":     frozenset({"wooribank.com", "wooricard.com"}),
    "hana":      frozenset({"hanabank.com", "hanacard.co.kr", "kebhana.com"}),
    "ibk":       frozenset({"ibk.co.kr"}),
    "keb":       frozenset({"kebhana.com"}),
    "coupang":   frozenset({"coupang.com"}),
    "baemin":    frozenset({"baemin.com", "baedalui.com"}),
    "gmarket":   frozenset({"gmarket.co.kr"}),
    "paypal":    frozenset({"paypal.com"}),
    "samsung":   frozenset({"samsung.com", "samsung.co.kr"}),
    "apple":     frozenset({"apple.com"}),
    "google":    frozenset({"google.com", "googleapis.com", "gstatic.com"}),
    "microsoft": frozenset({"microsoft.com", "microsoftonline.com", "live.com"}),
    "amazon":    frozenset({"amazon.com", "amazonaws.com", "amazon.co.kr"}),
    "netflix":   frozenset({"netflix.com"}),
    "nhis":      frozenset({"nhis.or.kr"}),
    "hometax":   frozenset({"hometax.go.kr"}),
    "wetax":     frozenset({"wetax.go.kr"}),
    "irs":       frozenset({"irs.gov"}),
}


# =============================================================================
# 결과 타입
# =============================================================================

@dataclass
class HeuristicResult:
    """
    score_url() 반환 타입.

    score    : 합산 점수 (0 이상, 상한 없음)
    verdict  : 'DANGER' | 'SUSPICIOUS' | 'SAFE'
    triggered: 발화된 시그널 → 점수 기여분 딕셔너리
               (설명 카드 생성 및 로그에 활용)
    """
    score:     int
    verdict:   str
    triggered: dict[str, int] = field(default_factory=dict)


# =============================================================================
# 내부 시그널 함수
# =============================================================================

def _signal_ip_in_url(hostname: str) -> bool:
    """URL 호스트가 IP 주소인지 확인한다 (KISA SI)."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _signal_subdomain_spoofing(hostname: str, registered_domain: str | None) -> bool:
    """
    서브도메인 부분에 유명 TLD 가 포함된 도메인 위장 패턴을 탐지한다.

    예: naver.com.evil.kr
        hostname = 'naver.com.evil.kr', registered_domain = 'evil.kr'
        subdomain_part = 'naver.com' → parts = ['naver', 'com']
        'com' ∈ _COMMON_TLDS_IN_SUBDOMAINS → True
    """
    if not registered_domain:
        return False
    # 등록 도메인 앞의 서브도메인 부분만 추출
    if not hostname.endswith("." + registered_domain):
        return False
    subdomain_part = hostname[: -(len(registered_domain) + 1)]
    if not subdomain_part:
        return False
    parts = subdomain_part.split(".")
    return any(p in _COMMON_TLDS_IN_SUBDOMAINS for p in parts)


def _signal_brand_keyword_mismatch(hostname: str, registered_domain: str | None) -> bool:
    """
    브랜드 키워드가 URL 에 포함됐지만 등록 도메인이 해당 브랜드 공식 도메인이 아닌 경우 탐지.

    단어 경계(\b)로 'kb' → 'okb' 오탐 방지.
    """
    host_lower = hostname.lower()
    rd = (registered_domain or "").lower()

    for keyword in _BRAND_KEYWORDS:
        # 단어 경계 매칭: -·. 으로 구분된 키워드 포함 여부
        pattern = r"(?<![a-z0-9])" + re.escape(keyword) + r"(?![a-z0-9])"
        if not re.search(pattern, host_lower):
            continue
        # 키워드 발견 — 공식 도메인 여부 확인
        official = _BRAND_OFFICIAL_DOMAINS.get(keyword, frozenset())
        if official and rd not in official:
            return True  # 키워드 있음 + 공식 도메인 아님 → 사칭 의심

    return False


def _signal_homograph(hostname: str) -> bool:
    """
    IDN homograph: 호스트명에 비ASCII 문자 포함 여부 (KISA SF).
    normalize_idn_hostname 의 is_idn 반환값을 재사용.
    """
    _, is_idn = normalize_idn_hostname(hostname)
    return is_idn


def _signal_dangerous_extension(path: str) -> bool:
    """
    URL 경로가 악성 파일 확장자로 끝나는지 확인 (KISA FD).
    쿼리스트링 이전 경로만 검사한다.
    """
    path_lower = path.lower().split("?")[0]
    return any(path_lower.endswith(ext) for ext in _DANGEROUS_EXTENSIONS)


def _signal_suspicious_tld(registered_domain: str | None) -> bool:
    """등록 도메인의 TLD 가 피싱 다빈도 TLD 인지 확인."""
    if not registered_domain:
        return False
    parts = registered_domain.rsplit(".", 1)
    tld = f".{parts[1]}" if len(parts) == 2 else ""
    return tld in _SUSPICIOUS_TLDS


def _signal_excessive_subdomains(hostname: str, registered_domain: str | None) -> bool:
    """
    서브도메인 레벨이 3개 이상인지 확인 (KISA IL).

    a.b.c.naver.com  → subdomain_part='a.b.c', 점 2개 → True  (3레벨)
    a.b.naver.com    → subdomain_part='a.b',   점 1개 → False (2레벨)
    login.naver.com  → subdomain_part='login', 점 0개 → False (1레벨)
    """
    if not registered_domain:
        # registered_domain 미확인 시 전체 파트 수로 보수적 판단 (tldextract 폴백)
        # 5파트 이상 = 3+ 서브도메인 + 2파트 도메인(최소) 가정
        return hostname.count(".") >= 4
    subdomain_part = hostname[: -(len(registered_domain) + 1)] if hostname.endswith("." + registered_domain) else ""
    if not subdomain_part:
        return False
    return subdomain_part.count(".") >= 2  # 점 2개 = 3레벨 서브도메인 (a.b.c)


def _signal_port_in_url(netloc: str) -> bool:
    """URL 에 비표준 포트 번호가 명시되어 있는지 확인."""
    if ":" not in netloc:
        return False
    port_str = netloc.rsplit(":", 1)[-1]
    if not port_str.isdigit():
        return False
    port = int(port_str)
    return port not in (80, 443)


# =============================================================================
# 공개 인터페이스
# =============================================================================

def score_url(
    url: str,
    domain_evidence: dict | None = None,
    vote_counts: dict | None = None,
    sandbox_score: int | None = None,
) -> HeuristicResult:
    """
    URL 에 대해 다중 시그널 가중합 휴리스틱 점수를 계산한다.

    판정을 직접 내리지 않고 점수와 발화 시그널을 반환한다.
    판정(DANGER/SUSPICIOUS/SAFE)은 임계값 비교로 결정한다.

    [url]            : 분석 대상 URL (정규화 완료된 것을 권장)
    [domain_evidence]: analyze_domain_reputation() 반환값 (선택적)
    [vote_counts]    : get_vote_counts() 반환값 {"danger": int, "safe": int} (선택적)
    [sandbox_score]  : 7-B 자동탐지 sandbox_score (선택적, ANL-11)
    반환값: HeuristicResult
    """
    triggered: dict[str, int] = {}

    # ── URL 파싱 ─────────────────────────────────────────────────────────────
    try:
        parsed = urlparse(url if "://" in url else f"https://{url}")
    except Exception:
        logger.warning("[휴리스틱] URL 파싱 실패: %s", url)
        return HeuristicResult(score=0, verdict="SAFE", triggered={})

    # parsed.hostname: 포트·IPv6 괄호를 자동 제거, 소문자 반환
    # netloc.split(":")[0] 는 IPv6 [::1]:8080 에서 "[::1" 반환하는 버그 있음
    hostname     = (parsed.hostname or "").lower()
    netloc       = parsed.netloc.lower()
    path         = parsed.path or ""
    registered   = get_registered_domain(url)

    # ── 시그널 평가 ───────────────────────────────────────────────────────────

    if _signal_ip_in_url(hostname):
        triggered["ip_in_url"] = _WEIGHTS["ip_in_url"]

    if _signal_subdomain_spoofing(hostname, registered):
        triggered["subdomain_spoofing"] = _WEIGHTS["subdomain_spoofing"]

    if _signal_brand_keyword_mismatch(hostname, registered):
        triggered["brand_keyword_mismatch"] = _WEIGHTS["brand_keyword_mismatch"]

    if _signal_homograph(hostname):
        triggered["homograph_idn"] = _WEIGHTS["homograph_idn"]

    if has_double_encoding(url):
        triggered["double_encoding"] = _WEIGHTS["double_encoding"]

    if _signal_dangerous_extension(path):
        triggered["dangerous_extension"] = _WEIGHTS["dangerous_extension"]

    if _signal_suspicious_tld(registered):
        triggered["suspicious_tld"] = _WEIGHTS["suspicious_tld"]

    if _signal_excessive_subdomains(hostname, registered):
        triggered["excessive_subdomains"] = _WEIGHTS["excessive_subdomains"]

    if _signal_port_in_url(netloc):
        triggered["port_in_url"] = _WEIGHTS["port_in_url"]

    if len(url) > 100:
        triggered["url_too_long"] = _WEIGHTS["url_too_long"]

    # ── 도메인 평판 시그널 (선택적) ───────────────────────────────────────────
    if domain_evidence and not domain_evidence.get("skipped"):
        if domain_evidence.get("new_domain"):
            triggered["new_domain"] = _WEIGHTS["new_domain"]
        if domain_evidence.get("fresh_infrastructure"):
            triggered["fresh_infrastructure"] = _WEIGHTS["fresh_infrastructure"]
        if domain_evidence.get("whois_no_record"):
            triggered["whois_no_record"] = _WEIGHTS["whois_no_record"]

    # ── 사용자 투표 시그널 (선택적) ───────────────────────────────────────────
    if vote_counts:
        danger_count = vote_counts.get("danger", 0)
        safe_count   = vote_counts.get("safe", 0)
        if danger_count > safe_count:
            if danger_count >= 10:
                triggered["prior_danger_vote_high"] = _WEIGHTS["prior_danger_vote_high"]
            elif danger_count >= 3:
                triggered["prior_danger_vote_low"] = _WEIGHTS["prior_danger_vote_low"]

    # ── 7-B 샌드박스 점수 시그널 (선택적, ANL-11) ────────────────────────────
    if sandbox_score is not None and sandbox_score >= 70:
        triggered["sandbox_danger_score"] = _WEIGHTS["sandbox_danger_score"]

    # ── 점수 합산 및 판정 ─────────────────────────────────────────────────────
    score = sum(triggered.values())

    if score >= DANGER_THRESHOLD:
        verdict = "DANGER"
    elif score >= SUSPICIOUS_THRESHOLD:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    logger.info(
        "[휴리스틱] %s | score=%d verdict=%s triggered=%s",
        registered or hostname, score, verdict, list(triggered.keys()),
    )

    return HeuristicResult(score=score, verdict=verdict, triggered=triggered)
