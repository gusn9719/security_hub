# =============================================================================
# backend/services/url_validator.py
# 역할: 0단계 위험스킴 검사 + URL 정규화 유틸리티
#
# 설계 원칙:
#   - 판정을 내리지 않는다. 분류 전 URL 보강/검사 전용.
#   - 모든 함수는 순수함수(side-effect 없음).
#   - tldextract 미설치 시 폴백 로직으로 graceful 처리.
# =============================================================================

import ipaddress
import logging
import re
from urllib.parse import unquote, urlparse

logger = logging.getLogger(__name__)

try:
    import tldextract as _tldextract
    _TLDEXTRACT_AVAILABLE = True
except ImportError:
    _TLDEXTRACT_AVAILABLE = False
    logger.warning("[URL검증] tldextract 미설치 — registered_domain 폴백 사용")


# =============================================================================
# 0단계: 위험 스킴 검사
# =============================================================================

# KISA 취약점 가이드 EP(인코딩 우회) / SI(서버정보) 항목 대응
# javascript:, data:, vbscript: → 스크립트 직접 실행
# file: → 로컬 파일 접근
# blob: → ANL-00: Blob URL은 로컬 blob 객체를 가리키며 외부 탐지가 불가능하다
DANGEROUS_SCHEMES: frozenset[str] = frozenset({
    "javascript",
    "data",
    "vbscript",
    "file",
    "blob",
})


def check_dangerous_scheme(url: str) -> bool:
    """
    URL 스킴이 위험 스킴인지 확인한다 (0단계).

    javascript:alert(1), data:text/html,<script>... 등을 감지한다.
    http/https 가 아닌 모든 DANGEROUS_SCHEMES 스킴을 위험으로 판정.

    [url]: 검사 대상 URL
    반환값: True = 위험 스킴 감지
    """
    try:
        scheme = urlparse(url).scheme.lower()
    except Exception:
        return False
    return scheme in DANGEROUS_SCHEMES


# =============================================================================
# 1단계: URL 정규화 — 이중 인코딩 / IDN
# =============================================================================

# 이중 인코딩 패턴: %25 뒤에 두 자리 hex → %2F, %3C 등으로 해제됨
_DOUBLE_ENCODING_RE = re.compile(r"%25[0-9a-fA-F]{2}")


def has_double_encoding(url: str) -> bool:
    """
    URL에 이중 인코딩(%25xx) 이 존재하는지 확인한다 (KISA EP 항목).

    %252F  →  %25 + 2F  →  실제 해석 시 /  → 보안 필터 우회에 사용됨.

    [url]: 검사 대상 URL
    반환값: True = 이중 인코딩 패턴 감지
    """
    return bool(_DOUBLE_ENCODING_RE.search(url))


def double_decode(url: str) -> str:
    """
    URL을 두 번 디코딩한다.

    %252F → (1회) %2F → (2회) /
    피싱 URL이 필터 우회를 위해 의도적으로 이중 인코딩한 경우를 정규화한다.

    [url]: 원본 URL
    반환값: 이중 디코딩된 URL
    """
    return unquote(unquote(url))


def normalize_idn_hostname(hostname: str) -> tuple[str, bool]:
    """
    IDN(국제 도메인) 호스트명을 ASCII Punycode 로 정규화한다.

    예: 'раурal.com' (키릴 문자) → 'xn--aypal-uya.com', is_idn=True
    ASCII 전용 호스트는 그대로 반환하고 is_idn=False.

    homograph 공격 탐지에 사용된다 (KISA SF 항목).

    [hostname]: 호스트명 문자열
    반환값: (ascii_hostname, is_idn_detected)
    """
    if hostname.isascii():
        return hostname, False

    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
        return ascii_hostname, True
    except UnicodeError:
        # 변환 실패해도 IDN 감지 플래그는 설정 (UnicodeDecodeError 는 UnicodeError 서브클래스)
        return hostname, True


# =============================================================================
# SSRF 방어: 사설 IP 검사
# =============================================================================

def is_private_ip(hostname: str) -> bool:
    """
    호스트명이 사설/루프백/링크로컬 IP 주소인지 확인한다 (SSRF 방어).

    단축 URL 해제 전 목적지가 내부 IP 인 경우 요청을 차단하기 위해 사용.
    도메인명 입력 시 False 반환 (DNS 조회 없음 — 경량 체크).

    [hostname]: IP 또는 도메인명 문자열
    반환값: True = 사설/루프백/링크로컬 IP
    """
    try:
        addr = ipaddress.ip_address(hostname)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False  # 도메인명이면 False


# =============================================================================
# 등록 도메인 추출 유틸리티
# =============================================================================

def get_registered_domain(url: str) -> str | None:
    """
    URL 에서 등록 도메인(registered domain)을 추출한다.

    서브도메인을 포함한 URL 에서 'domain.tld' 형식만 반환.
    tldextract 미설치 시 netloc 끝에서 2개 파트 추출 폴백 사용.

    [url]: 원본 URL (프로토콜 있음/없음 모두 허용)
    반환값: 등록 도메인 문자열 ('naver.com') | None
    """
    if _TLDEXTRACT_AVAILABLE:
        extracted = _tldextract.extract(url)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
        return None

    # 폴백: netloc 끝 2개 파트
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.netloc.split(":")[0]
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host or None
