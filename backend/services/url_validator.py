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

# 위험 URL 스킴 — 0단계 즉시 DANGER 처리 대상.
#
# javascript:, data:, vbscript: → 스크립트 직접 실행 (DOM XSS 유사 위협)
# file:                          → 로컬 파일 접근
# blob:                          → ANL-00: Blob URL 은 메모리 객체를 가리키므로
#                                  외부 탐지 불가. 첨부 메시지에 등장 시 위험 신호.
#
# 출처: [KISA-PDF] Web Application 가이드의 CI(코드 인젝션) 항목은 LDAP/OS
#       Command/SSI 인젝션 등을 다루지만 URL 스킴은 직접 매핑되지 않음.
#       본 정책은 OWASP "URL Schema Whitelisting" 가이드와 일반적인 안전 브라우징
#       관행을 근거로 한다.
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
    URL에 이중 인코딩(%25xx) 이 존재하는지 확인한다.

    %252F  →  %25 + 2F  →  실제 해석 시 /  → 보안 필터(WAF) 우회에 사용.

    출처: [OWASP] "Double Encoding" 공격 카탈로그.
          [KISA-PDF] X장 15절(파일 다운로드 FD)의 '우회 방안 예시' 표에
          이중 URL 인코딩 (.%252e, /%252f, \\%255c)이 명시되어 있음.

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

    homograph 공격 탐지에 사용된다.

    출처: [UTS39] Unicode Technical Standard #39 "Security Mechanisms" —
          mixed-script confusables 정의.
          [KISA-IDN] KISA 동형이의자 공격 분석 자료.
    (KISA 취약점 가이드 본책의 SF 항목은 SSRF 로, 본 함수와 직접 매핑되지 않음.)

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
# userinfo(@) 인젝션 검사 — 호스트 위장 패턴
# =============================================================================

def check_userinfo_injection(url: str) -> bool:
    """
    URL 에 userinfo(@ 앞부분) 가 포함되어 호스트 위장이 가능한지 확인.

    예: https://naver.com@evil.kr/login
        urlparse 결과 → username='naver.com', hostname='evil.kr'
        브라우저는 @ 앞을 인증 사용자명으로 무시하고 실제로 evil.kr 에 접속.
        모바일에서 화면이 좁으면 @ 뒤가 잘려 사용자가 정상 도메인으로 오인.

    설계 결정:
        - parsed.username 이 비어 있지 않으면 무조건 True.
        - HTTP(S) 에 합법적 userinfo 가 필요한 정상 케이스는 사실상 없음
          (FTP 등 다른 스킴에서만 합법). 현대 브라우저도 경고 표시.
        - 잠재적 false positive 보다 false negative 회피가 우선.

    출처: [RFC3986] §3.2.1 userinfo 컴포넌트 — 본래 ftp://user@host 의
          인증 정보 전달용. HTTP(S) 에서는 사칭 도구로 악용.

    [url]: 검사 대상 URL
    반환값: True = userinfo 컴포넌트 감지 (사칭 의심)
    """
    try:
        # Fix: decode %40 → @ before parsing so percent-encoded userinfo is detected
        parsed = urlparse(unquote(url))
        return bool(parsed.username)
    except Exception:
        return False


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
