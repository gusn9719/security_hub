# =============================================================================
# backend/services/url_expander.py
# 역할: 단축 URL 해제 모듈 (HTTP HEAD 기반, 외부 API 미사용)
# 변경 이력:
#   - Sprint 5A: 최초 작성
# =============================================================================

import logging
import requests
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# =============================================================================
# 단축 URL 도메인 (C-TAS 데이터 기준 + 일반 단축 서비스)
# =============================================================================
SHORT_URL_DOMAINS: set[str] = {
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
}

# Android 모바일 User-Agent — 일부 단축 서비스가 봇 차단을 우회하기 위해 필요
_USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
)

_REDIRECT_STATUS = (301, 302, 303, 307, 308)


def is_short_url(url: str) -> bool:
    """
    URL이 알려진 단축 서비스 도메인을 사용하는지 판별한다.

    [url]: 검사 대상 URL
    반환값: 단축 URL 여부 (True/False)
    """
    try:
        host = urlparse(url).netloc.lower()
    except Exception:
        return False
    if not host:
        return False
    # www. 접두사 제거 후 비교
    if host.startswith("www."):
        host = host[4:]
    return host in SHORT_URL_DOMAINS


def expand_url(url: str, timeout: int = 5) -> str:
    """
    단축 URL을 1회 해제한다. HTTP HEAD → 3xx → Location.

    설계 원칙:
      - 외부 API 미사용 (비용 0)
      - 최대 1회만 해제 (체인 리다이렉트는 1단계까지만 — 무한 루프 방지)
      - 실패 시 원본 URL 그대로 반환 (서비스 중단 없음)

    [url]: 단축 URL
    [timeout]: HTTP 요청 타임아웃(초)
    반환값: 해제된 URL (실패 시 원본)
    """
    headers = {"User-Agent": _USER_AGENT}
    try:
        resp = requests.head(
            url,
            allow_redirects=False,
            timeout=timeout,
            headers=headers,
        )
        if resp.status_code in _REDIRECT_STATUS:
            location = resp.headers.get("Location")
            if location:
                logger.info(f"[URL해제] {url} → {location}")
                return location
        logger.debug(f"[URL해제] 리다이렉트 없음 — {url} (status {resp.status_code})")
    except Exception as e:
        logger.warning(f"[URL해제] 실패 — {url} | {e}")
    return url
