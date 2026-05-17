# =============================================================================
# backend/services/domain_reputation_service.py
# 역할: 도메인 평판 분석 (ANL-05 Sprint 5D)
#
# 설계 원칙:
#   - 판정을 변경하지 않는다. evidence dict 보강용 보조 지표만 반환한다.
#   - 모든 예외는 graceful 처리 — 서비스 중단 없음.
#   - IP 주소 및 SKIP_WHOIS_TLDS 도메인은 조회 없이 스킵한다.
# =============================================================================

import ipaddress
import logging
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from config import NEW_DOMAIN_THRESHOLD_DAYS, SKIP_WHOIS_TLDS, SSL_FRESH_THRESHOLD_DAYS

logger = logging.getLogger(__name__)

try:
    import whois as _whois_lib
    _WHOIS_AVAILABLE = True
except Exception as _whois_err:
    _WHOIS_AVAILABLE = False
    logger.warning("[도메인평판] python-whois import 실패: %s", _whois_err)

try:
    import tldextract as _tldextract
    _TLDEXTRACT_AVAILABLE = True
except Exception as _tld_err:
    _TLDEXTRACT_AVAILABLE = False
    logger.warning("[도메인평판] tldextract import 실패: %s", _tld_err)


# =============================================================================
# 내부 헬퍼
# =============================================================================

def _is_ip_address(host: str) -> bool:
    """호스트가 IP 주소인지 확인한다 (TC-ANL-08)."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _get_registered_domain(url: str) -> str | None:
    """
    URL에서 등록 도메인(registered domain)을 추출한다 (TC-ANL-07).

    서브도메인을 포함한 URL에서 'domain.tld' 형식만 반환한다.
    tldextract 미설치 시 netloc 끝에서 2개 파트만 추출하는 폴백을 사용한다.
    """
    if _TLDEXTRACT_AVAILABLE:
        extracted = _tldextract.extract(url)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
        return None

    # 폴백: netloc에서 마지막 2개 파트
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.netloc.split(":")[0]
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host or None


def _get_tld(domain: str) -> str:
    """도메인에서 TLD를 반환한다 (예: 'naver.com' → '.com')."""
    parts = domain.rsplit(".", 1)
    return f".{parts[1]}" if len(parts) == 2 else ""


def _check_ssl(hostname: str) -> tuple[bool | None, int | None]:
    """
    호스트의 SSL 인증서를 조회한다.

    Returns:
        (ssl_valid, ssl_issued_days)
        (True,  days) — 유효한 SSL 인증서
        (False, None) — 연결 성공했지만 SSL 없음 또는 SSL 오류 (TC-ANL-10)
        (None,  None) — 서버 자체에 도달 불가
    """
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=5) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=hostname) as ssl_sock:
                cert = ssl_sock.getpeercert()
                not_before_str = cert.get("notBefore")
                if not_before_str:
                    # 날짜 포맷: 'Nov  9 00:00:00 2023 GMT' — 공백 정규화
                    normalized = re.sub(r"\s+", " ", not_before_str.strip())
                    not_before = datetime.strptime(normalized, "%b %d %H:%M:%S %Y %Z")
                    not_before = not_before.replace(tzinfo=timezone.utc)
                    issued_days = (datetime.now(timezone.utc) - not_before).days
                else:
                    issued_days = None
                return True, issued_days
    except ssl.SSLError:
        # 포트 443 연결은 됐으나 SSL 핸드셰이크 실패 → SSL 오류
        return False, None
    except (socket.timeout, ConnectionRefusedError, OSError):
        # 포트 443 불가 → 포트 80으로 서버 생존 확인 (TC-ANL-10)
        try:
            with socket.create_connection((hostname, 80), timeout=5):
                return False, None  # HTTP 서버 살아있음, SSL 없음
        except Exception:
            return None, None  # 서버 자체 도달 불가


# =============================================================================
# 공개 인터페이스
# =============================================================================

def analyze_domain_reputation(url: str) -> dict:
    """
    도메인 평판 분석 — WHOIS 등록일, SSL 인증서 조회.

    판정을 변경하지 않는다. evidence dict 보강용 보조 지표만 반환한다.
    모든 외부 조회 실패는 graceful 처리하여 서비스 중단을 방지한다.

    Args:
        url: 분석 대상 URL (http/https 또는 프로토콜 없는 도메인)

    Returns:
        dict:
            domain_age_days  (int | None)  — 도메인 등록 후 경과일. 조회 실패 시 None
            new_domain       (bool)        — domain_age_days ≤ NEW_DOMAIN_THRESHOLD_DAYS
            ssl_valid        (bool | None) — True: 유효 SSL, False: SSL 없음/오류,
                                             None: 서버 도달 불가
            ssl_issued_days  (int | None)  — SSL 인증서 발급 후 경과일
            fresh_infrastructure (bool)   — domain_age ≤ 30 AND ssl_issued ≤ 7
            whois_no_record  (bool)        — WHOIS 레코드 자체가 없는 경우 (TC-ANL-06)
            skipped          (bool)        — IP 주소 또는 SKIP_WHOIS_TLDS로 조회 생략
    """
    result: dict = {
        "domain_age_days": None,
        "new_domain": False,
        "ssl_valid": None,
        "ssl_issued_days": None,
        "fresh_infrastructure": False,
        "whois_no_record": False,
        "skipped": False,
    }

    # ── URL 파싱 ──────────────────────────────────────────────────────────────
    parsed = urlparse(url if "://" in url else f"https://{url}")
    hostname = parsed.netloc.split(":")[0]

    if not hostname:
        result["skipped"] = True
        return result

    # ── IP 주소 스킵 (TC-ANL-08) ──────────────────────────────────────────────
    if _is_ip_address(hostname):
        logger.info("[도메인평판] IP 주소 스킵: %s", hostname)
        result["skipped"] = True
        return result

    # ── 등록 도메인 추출 (TC-ANL-07) ─────────────────────────────────────────
    registered_domain = _get_registered_domain(url)
    if not registered_domain:
        result["skipped"] = True
        return result

    # ── SKIP_WHOIS_TLDS 스킵 (TC-ANL-09) ─────────────────────────────────────
    tld = _get_tld(registered_domain)
    if tld in SKIP_WHOIS_TLDS:
        logger.info("[도메인평판] SKIP_WHOIS_TLDS 스킵: %s (%s)", registered_domain, tld)
        result["skipped"] = True
        return result

    # ── WHOIS 조회 ────────────────────────────────────────────────────────────
    domain_age_days: int | None = None
    whois_no_record = False

    if _WHOIS_AVAILABLE:
        try:
            w = _whois_lib.whois(registered_domain)
            creation_date = w.creation_date

            if creation_date is None:
                # domain_name 필드도 없으면 레코드 미존재로 판단 (TC-ANL-06)
                if not w.domain_name:
                    whois_no_record = True
                # domain_age_days = None 유지 (조회는 됐지만 날짜 불명)
            else:
                # python-whois 가 리스트로 반환하는 경우 첫 번째 값 사용
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]

                # python-whois 가 일부 ccTLD(.gg 등) 에서 datetime 대신
                # 문자열을 그대로 반환하는 경우 직접 파싱
                if isinstance(creation_date, str):
                    _DATE_FMTS = (
                        "%Y-%m-%d",
                        "%Y-%m-%dT%H:%M:%SZ",
                        "%Y-%m-%d %H:%M:%S",
                        "%d-%b-%Y",
                        "%d %b %Y",
                    )
                    for _fmt in _DATE_FMTS:
                        try:
                            creation_date = datetime.strptime(
                                creation_date.strip(), _fmt
                            ).replace(tzinfo=timezone.utc)
                            break
                        except ValueError:
                            continue
                    else:
                        # 알 수 없는 형식 → 날짜 없음 처리
                        logger.debug(
                            "[도메인평판] creation_date 파싱 실패 (문자열): %r", creation_date
                        )
                        creation_date = None

                # datetime 타입이 아닌 경우(예상치 못한 타입) 무시
                if creation_date is not None and not isinstance(creation_date, datetime):
                    logger.debug(
                        "[도메인평판] creation_date 타입 미지원: %s", type(creation_date)
                    )
                    creation_date = None

                if creation_date is not None:
                    if creation_date.tzinfo is None:
                        creation_date = creation_date.replace(tzinfo=timezone.utc)
                    domain_age_days = (datetime.now(timezone.utc) - creation_date).days

        except Exception as e:
            # WHOIS + rdap 모두 실패해도 graceful (TC-ANL-05)
            logger.warning("[도메인평판] WHOIS 조회 실패 (graceful): %s — %s", registered_domain, e)

    new_domain = (
        domain_age_days is not None and domain_age_days <= NEW_DOMAIN_THRESHOLD_DAYS
    )

    # ── SSL 조회 ──────────────────────────────────────────────────────────────
    # http:// URL은 처음부터 SSL 없음 (TC-ANL-03)
    if parsed.scheme == "http":
        ssl_valid: bool | None = False
        ssl_issued_days: int | None = None
    else:
        try:
            ssl_valid, ssl_issued_days = _check_ssl(hostname)
        except Exception as e:
            logger.warning("[도메인평판] SSL 조회 실패 (graceful): %s — %s", hostname, e)
            ssl_valid, ssl_issued_days = None, None

    # ── fresh_infrastructure 플래그 (TC-ANL-04) ───────────────────────────────
    # domain_age ≤ 30 AND ssl_issued ≤ 7 양쪽 모두 충족 시에만 True
    fresh_infrastructure = (
        domain_age_days is not None
        and domain_age_days <= NEW_DOMAIN_THRESHOLD_DAYS
        and ssl_issued_days is not None
        and ssl_issued_days <= SSL_FRESH_THRESHOLD_DAYS
    )

    result.update({
        "domain_age_days": domain_age_days,
        "new_domain": new_domain,
        "ssl_valid": ssl_valid,
        "ssl_issued_days": ssl_issued_days,
        "fresh_infrastructure": fresh_infrastructure,
        "whois_no_record": whois_no_record,
        "skipped": False,
    })
    return result
