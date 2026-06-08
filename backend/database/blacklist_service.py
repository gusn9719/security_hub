# =============================================================================
# backend/database/blacklist_service.py
# 역할: blacklist DB 조회 + URL 정규화 유틸리티
# 변경 이력:
#   - Sprint 4: 최초 작성
#   - Sprint 5A: extract_urls 정규식 강화 — 프로토콜 없는 도메인도 추출,
#                check_blacklist 시그니처를 urls 리스트 기반으로 분리
#   - Sprint 5E: normalize_url 이중 디코딩 추가 (EP 항목 대응),
#                check_blacklist 3순위 registered_domain 매칭 추가
# =============================================================================

import re
import hashlib
import logging
from urllib.parse import unquote, urlparse

from database.db_init import get_ro_connection
from services.url_validator import get_registered_domain

logger = logging.getLogger(__name__)


# =============================================================================
# 단축 URL 서비스 도메인 (BL-FP-001)
# - domain / registered_domain 2·3순위 매칭에서 이 도메인은 건너뛴다.
# - url_hash(1순위) 매칭은 그대로 적용된다 — 정확한 경로가 등재된 경우 차단 유지.
# - url_expander.SHORT_URL_DOMAINS 와 동기화 유지. 추가 서비스(forms.gle, naver.me)는
#   C-TAS 등재 이력이 확인되어 도메인 레벨 FP 위험이 있는 것만 포함한다.
# =============================================================================
_SHORT_URL_PROVIDERS: frozenset[str] = frozenset({
    # url_expander.SHORT_URL_DOMAINS 동기화 목록
    "bit.ly",
    "w0q.de",
    "ph.link",
    "alie.kr",
    "t.ly",
    "l1nq.com",
    "qrco.de",
    "han.gl",
    "me2.do",
    "url.kr",
    "is.gd",
    "tinyurl.com",
    "ow.ly",
    "rebrand.ly",
    # C-TAS 등재 이력 확인된 추가 서비스
    "forms.gle",
    "naver.me",
    "goo.gl",
})

# 단축 URL 서비스 도메인의 registered_domain 집합 — 3순위 매칭 보호용
# (예: forms.gle → 등록 도메인도 forms.gle 자체이므로 포함)
# get_registered_domain 은 파일 상단에서 이미 임포트됨.
_SHORT_URL_PROVIDER_REG_DOMAINS: frozenset[str] = frozenset(filter(None, (
    get_registered_domain(f"https://{d}/")
    for d in _SHORT_URL_PROVIDERS
)))


# =============================================================================
# 알려진 TLD 목록
# - 합법 TLD + C-TAS 블랙리스트에 자주 등장하는 신규 gTLD를 포함한다.
# - 프로토콜 없는 도메인을 추출할 때 false positive를 최소화하는 화이트리스트 역할.
# =============================================================================
KNOWN_TLDS: set[str] = {
    # 일반
    "com", "net", "org", "info", "biz", "co", "io",
    # 국가
    "kr", "jp", "cn", "us", "uk", "de", "fr", "ru", "in", "tw", "vn", "th",
    # 단축 URL 서비스
    "ly", "to", "cc", "me", "gl", "be", "ws", "gd",
    # 신규 gTLD (스미싱·스팸에 자주 사용)
    "xyz", "top", "club", "shop", "site", "online", "live", "click",
    "link", "store", "tech", "page", "best", "app", "dev", "stream",
    "one", "art", "yachts", "bar", "boats", "golf", "digital",
    "mom", "lol", "icu", "press", "my", "makeup", "pro", "cyou",
    "uno", "sbs", "email", "pw", "tv", "fun", "world", "life",
    "today", "space", "website", "blog", "news", "wiki",
}


# =============================================================================
# 정규식 (Pre-compiled)
# =============================================================================

# 1단계: 프로토콜 있는 URL
_PROTO_URL_RE = re.compile(
    r'https?://[^\s\]\[()<>"\'\u3000]+',
    re.ASCII,
)

# 2단계: 프로토콜 없는 도메인
# - (?<![@\w.]) : 앞에 @(이메일), 영숫자, . 가 없어야 함 (재매칭/이메일/단어 일부 방지)
# - re.ASCII   : \w 를 ASCII 범위로 제한 → 한글 인접 시에도 정상 매칭
# - 도메인 본문: ([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}
# - 선택적 path: (/[^...]*)?
_BARE_DOMAIN_RE = re.compile(
    r'(?<![@\w.])((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(/[^\s\]\[()<>"\']*)?',
    re.ASCII,
)

# URL 끝부분에서 제거할 구두점 (영문/한글 공통)
_TRAILING_PUNCT = '.,;:!?)\u3002\u3001'


# =============================================================================
# URL 추출 (Sprint 5A 강화)
# =============================================================================

def extract_urls(text: str) -> list[str]:
    """
    입력 텍스트에서 URL 후보를 추출한다.

    추출 규칙:
      1. http(s):// 로 시작하는 URL은 그대로 추출
      2. 프로토콜이 없는 도메인은 KNOWN_TLDS 로 끝나는 경우만 추출 후 https:// 부착
      3. 이메일 주소(user@domain) 내 도메인은 제외
      4. 추출한 URL의 끝부분 구두점/마침표는 제거
      5. 중복 제거 (입력 등장 순서 유지)

    [text]: 사용자 입력 문자 전문
    반환값: 정규화된 URL 문자열 리스트
    """
    results: list[str] = []
    seen: set[str] = set()

    # ── 1단계: 프로토콜 URL 추출 ────────────────────────────────────────────
    for raw in _PROTO_URL_RE.findall(text):
        cleaned = raw.rstrip(_TRAILING_PUNCT)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            results.append(cleaned)

    # 1단계에서 추출된 URL을 텍스트에서 제거 — 2단계에서 재매칭되는 것을 방지
    remaining = _PROTO_URL_RE.sub(' ', text)

    # ── 2단계: 프로토콜 없는 도메인 추출 ────────────────────────────────────
    for match in _BARE_DOMAIN_RE.finditer(remaining):
        domain_part = match.group(1)
        path_part = match.group(2) or ''

        # TLD 검증 (KNOWN_TLDS 에 있는 경우만 통과)
        tld = domain_part.rsplit('.', 1)[-1].lower()
        if tld not in KNOWN_TLDS:
            continue

        full = (domain_part + path_part).rstrip(_TRAILING_PUNCT)
        if not full:
            continue
        normalized = f"https://{full}"
        if normalized not in seen:
            seen.add(normalized)
            results.append(normalized)

    return results


# =============================================================================
# URL 정규화 유틸리티
# =============================================================================

def normalize_url(url: str) -> str:
    """
    URL을 정규화한다.

    순서:
      1. 이중 URL 디코딩 (%252F → %2F → /) — KISA EP 항목: 인코딩 우회 방지
      2. 소문자 변환
      3. 트레일링 슬래시 제거

    [url]: 원본 URL 문자열
    반환값: 정규화된 URL 문자열
    """
    url = url.strip()
    # 1. 이중 디코딩: 필터 우회를 위한 %25xx 패턴 해제
    url = unquote(unquote(url))
    # 2. 소문자 + 3. 트레일링 슬래시 제거
    return url.lower().rstrip("/")


def extract_domain(url: str) -> str:
    """
    URL에서 호스트(도메인)를 추출한다.

    [url]: 원본 또는 정규화된 URL 문자열
    반환값: 도메인 문자열 (예: "ccr.dtyh.best")
    """
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return ""


def compute_url_hash(url: str) -> str:
    """
    정규화된 URL의 SHA256 해시를 반환한다. (중복 제거 기준키)

    [url]: 정규화된 URL 문자열
    반환값: SHA256 hex digest 문자열
    """
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


# =============================================================================
# 블랙리스트 조회 서비스
# =============================================================================

def check_blacklist(urls: list[str], hash_only: bool = False) -> dict | None:
    """
    URL 리스트를 블랙리스트 DB와 대조한다.

    조회 전략 (우선순위 순):
      1. url_hash 정확 일치 — 동일 URL 재방문 즉시 차단
      2. domain 일치 — 하위 경로가 달라도 같은 도메인 차단
      3. registered_domain 일치 — 서브도메인만 다른 동일 악성 도메인 차단
         (예: ccr.dtyh.best 블랙리스트 → other.dtyh.best 도 차단)
      첫 번째 히트 발생 시 즉시 반환

    [urls]: extract_urls() 결과 (또는 단축 URL 해제 후 정규화된 URL 리스트)
    [hash_only]: True이면 1순위(url_hash) 매칭만 수행 — 화이트리스트 체크 전
                 3a단계에서 사용. Fix: whitelisted_safe DANGER 오판 방지.
    반환값: 히트된 row 딕셔너리 | None (미스 시)
    """
    if not urls:
        logger.debug("[블랙리스트] 조회할 URL 없음")
        return None

    logger.info(f"[블랙리스트] {len(urls)}개 URL 조회 시작")

    with get_ro_connection() as conn:
        for raw_url in urls:
            normalized = normalize_url(raw_url)
            url_hash = compute_url_hash(normalized)
            domain = extract_domain(normalized)
            reg_domain = get_registered_domain(normalized)

            # ── 1순위: url_hash 정확 일치 ────────────────────────────────
            row = conn.execute(
                "SELECT * FROM blacklist WHERE url_hash = ?",
                (url_hash,),
            ).fetchone()
            if row:
                logger.warning(f"[블랙리스트] url_hash 히트 — {normalized}")
                return dict(row)

            # ── 2순위: domain 일치 ────────────────────────────────────────
            # hash_only=True 시 생략 — 화이트리스트 체크 전 3a단계에서 호출될 때.
            # Fix BL-FP-001: 단축 URL 서비스 도메인은 domain 레벨 매칭 제외.
            # url_hash(1순위) 히트는 이미 위에서 처리됨 — 정확한 경로 차단은 유지.
            if not hash_only and domain and domain not in _SHORT_URL_PROVIDERS:
                row = conn.execute(
                    "SELECT * FROM blacklist WHERE domain = ? LIMIT 1",
                    (domain,),
                ).fetchone()
                if row:
                    logger.warning(f"[블랙리스트] domain 히트 — {domain}")
                    return dict(row)

            # ── 3순위: registered_domain 일치 ────────────────────────────
            # hash_only=True 시 생략 — 화이트리스트 체크 전 3a단계에서 호출될 때.
            # 피싱 도메인은 서브도메인만 바꿔 재사용하는 경우가 많으므로
            # 등록 도메인 단위로 차단. domain 과 중복 체크 방지.
            # Fix BL-FP-001: 단축 URL 서비스의 registered_domain도 제외
            # (예: forms.gle → google.com 이 블랙리스트에 있어도 전체 Google 차단 방지).
            if not hash_only and reg_domain and reg_domain != domain and reg_domain not in _SHORT_URL_PROVIDER_REG_DOMAINS:
                row = conn.execute(
                    "SELECT * FROM blacklist WHERE registered_domain = ? LIMIT 1",
                    (reg_domain,),
                ).fetchone()
                if row:
                    logger.warning(f"[블랙리스트] registered_domain 히트 — {reg_domain}")
                    return dict(row)

    logger.info("[블랙리스트] 미스")
    return None
