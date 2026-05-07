# =============================================================================
# backend/services/url_expander.py
# 역할: 단축 URL 해제 모듈 (HTTP HEAD 기반, 외부 API 미사용)
# 변경 이력:
#   - Sprint 5A: 최초 작성
#   - Sprint 5E: 최대 3-hop 체인 추적 추가, SSRF 방어(사설 IP 사전 차단)
# =============================================================================

import logging
import requests
from urllib.parse import urlparse

from services.url_validator import is_private_ip

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

_REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})

# 체인 리다이렉트 최대 허용 횟수 (무한 루프 방지)
_MAX_HOPS: int = 3


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


def _is_safe_to_request(url: str) -> bool:
    """
    HTTP 요청을 보내기 전 SSRF 방어 검사를 수행한다.

    목적지가 사설/루프백/링크로컬 IP 인 경우 차단.
    DNS 조회 없이 URL 파싱만으로 판단 (경량 체크).

    [url]: 요청 대상 URL
    반환값: True = 요청 안전, False = SSRF 위험
    """
    try:
        hostname = urlparse(url).hostname or ""
    except Exception:
        return True  # 파싱 실패는 requests 단계에서 처리
    return not is_private_ip(hostname)


def expand_url(url: str, timeout: int = 5) -> str:
    """
    단축 URL을 최대 3-hop 까지 추적하여 최종 목적지 URL 을 반환한다.

    설계 원칙:
      - 외부 API 미사용 (비용 0)
      - SSRF 방어: 사설 IP 목적지는 요청하지 않고 원본 URL 반환
      - 루프 탐지: 이미 방문한 URL 재방문 시 즉시 중단
      - 실패 시 원본 URL 그대로 반환 (서비스 중단 없음)

    [url]: 단축 URL
    [timeout]: HTTP 요청 타임아웃(초)
    반환값: 해제된 URL (실패 또는 SSRF 차단 시 원본)
    """
    headers = {"User-Agent": _USER_AGENT}
    current = url
    visited: set[str] = {url}

    for hop in range(_MAX_HOPS):
        # SSRF 방어: 사설 IP 목적지 차단
        if not _is_safe_to_request(current):
            logger.warning(
                "[URL해제] SSRF 차단 — 사설 IP 목적지 감지 (hop %d): %s", hop, current
            )
            return url  # 원본 반환

        try:
            resp = requests.head(
                current,
                allow_redirects=False,
                timeout=timeout,
                headers=headers,
            )
        except Exception as e:
            logger.warning("[URL해제] 요청 실패 (hop %d) — %s | %s", hop, current, e)
            return url  # 실패 시 원본 반환

        if resp.status_code not in _REDIRECT_STATUS:
            # 리다이렉트 없음 → 현재 URL이 최종 목적지
            logger.debug("[URL해제] 리다이렉트 없음 (hop %d) — %s (status %d)", hop, current, resp.status_code)
            break

        location = resp.headers.get("Location", "").strip()
        if not location:
            logger.debug("[URL해제] Location 헤더 없음 (hop %d) — %s", hop, current)
            break

        # 상대 경로 Location 처리 (예: /new-path → https://origin.com/new-path)
        if location.startswith("/"):
            parsed = urlparse(current)
            location = f"{parsed.scheme}://{parsed.netloc}{location}"

        # 루프 탐지
        if location in visited:
            logger.warning("[URL해제] 리다이렉트 루프 감지 — %s", location)
            break

        logger.info("[URL해제] hop %d: %s → %s", hop + 1, current, location)
        visited.add(location)
        current = location

    # 최종 URL이 원본과 같으면 해제 실패 (단축 서비스가 HEAD 를 지원 안 하는 경우 등)
    if current == url:
        logger.debug("[URL해제] 해제 결과 원본과 동일 — %s", url)
    return current
