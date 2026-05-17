# =============================================================================
# backend/config.py
# 역할: 분석 파이프라인 전역 상수 관리
# =============================================================================

import os

# ── 서버 환경 설정 ─────────────────────────────────────────────────────────────

# Cloudflare Tunnel / 프로덕션 외부 URL.
# 예: BASE_URL=https://your-tunnel.trycloudflare.com
# 미설정 시 요청의 Host 헤더에서 자동 추론한다.
BASE_URL: str | None = os.environ.get("BASE_URL")

# 리버스 프록시 뒤에서 HTTPS를 강제한다.
# Cloudflare Tunnel 사용 시 X-Forwarded-Proto 헤더로 자동 감지하지만,
# 헤더가 없는 환경에서는 이 플래그로 강제 설정한다.
FORCE_HTTPS: bool = os.environ.get("FORCE_HTTPS", "").lower() in ("1", "true", "yes")

# 프로덕션 환경에서 /docs, /redoc, /openapi.json 을 비활성화한다 (NF-25).
DISABLE_DOCS: bool = os.environ.get("DISABLE_DOCS", "").lower() in ("1", "true", "yes")

# ── ANL-05: 도메인 평판 분석 상수 ─────────────────────────────────────────────

# WHOIS/SSL 조회를 건너뛸 TLD 목록.
# 이 TLD는 WHOIS 데이터가 제한적이거나 불안정하므로 조회 생략.
SKIP_WHOIS_TLDS: frozenset[str] = frozenset({
    ".kr",
    ".mil",
    ".gov",
    ".edu",
})

# 신규 도메인 판정 임계값 (단위: 일).
# 등록 후 30일 이내 도메인을 새로운 도메인으로 간주한다.
# 근거: 피싱 사이트는 대부분 탐지·신고 후 폐기되므로 단명 도메인이 다수.
NEW_DOMAIN_THRESHOLD_DAYS: int = 30

# SSL 신규 발급 임계값 (단위: 일).
# fresh_infrastructure 플래그 조건 중 하나.
# 도메인과 SSL 인증서가 모두 최근 생성된 경우 단기 피싱 인프라로 의심.
SSL_FRESH_THRESHOLD_DAYS: int = 7
