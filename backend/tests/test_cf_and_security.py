# =============================================================================
# backend/tests/test_cf_and_security.py
# Cloudflare Tunnel 호환성 + 보안 기능 단위 테스트
#
# TC-CF-01 ~ TC-CF-10
# 실행: cd backend && python -m pytest tests/test_cf_and_security.py -v
# =============================================================================

import sys
import os
import time
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# =============================================================================
# TC-CF-01 ~ TC-CF-03 : ANL-00 — blob: 스킴 위험 판정
# =============================================================================

class TestBlobScheme:
    """ANL-00: blob: 스킴이 DANGER로 판정되는지 확인."""

    def test_blob_in_dangerous_schemes(self):
        """TC-CF-01: DANGEROUS_SCHEMES에 'blob'이 포함된다."""
        from services.url_validator import DANGEROUS_SCHEMES
        assert "blob" in DANGEROUS_SCHEMES

    def test_blob_url_detected(self):
        """TC-CF-02: blob: URL이 위험 스킴으로 감지된다."""
        from services.url_validator import check_dangerous_scheme
        assert check_dangerous_scheme("blob:https://example.com/file") is True
        assert check_dangerous_scheme("blob:null") is True

    def test_https_not_detected(self):
        """TC-CF-03: https: URL은 위험 스킴이 아니다."""
        from services.url_validator import check_dangerous_scheme
        assert check_dangerous_scheme("https://example.com") is False


# =============================================================================
# TC-CF-04 ~ TC-CF-06 : NF-12 — Cache-Control 헤더
# =============================================================================

class TestCacheControlHeader:
    """NF-12: SecurityHeadersMiddleware가 Cache-Control: no-store를 주입한다."""

    def _make_mock_response(self):
        headers: dict[str, str] = {}
        mock_resp = MagicMock()
        mock_resp.headers = headers
        return mock_resp

    @pytest.mark.asyncio
    async def test_cache_control_added(self):
        """TC-CF-04: 일반 요청 응답에 Cache-Control: no-store가 추가된다."""
        from main import SecurityHeadersMiddleware

        mock_app = AsyncMock()
        mw = SecurityHeadersMiddleware(mock_app)

        mock_request = MagicMock()
        mock_request.url.path = "/analyze"

        mock_resp = self._make_mock_response()

        async def call_next(req):
            return mock_resp

        result = await mw.dispatch(mock_request, call_next)
        assert result.headers.get("Cache-Control") == "no-store"

    @pytest.mark.asyncio
    async def test_cache_control_added_on_novnc_path(self):
        """TC-CF-05: noVNC 경로도 Cache-Control: no-store가 추가된다."""
        from main import SecurityHeadersMiddleware

        mock_app = AsyncMock()
        mw = SecurityHeadersMiddleware(mock_app)

        mock_request = MagicMock()
        mock_request.url.path = "/sandbox/browse/abc123/novnc/"

        mock_resp = self._make_mock_response()

        async def call_next(req):
            return mock_resp

        result = await mw.dispatch(mock_request, call_next)
        assert result.headers.get("Cache-Control") == "no-store"
        # noVNC 경로는 X-Frame-Options / CSP 없어야 함
        assert "X-Frame-Options" not in result.headers
        assert "Content-Security-Policy" not in result.headers


# =============================================================================
# TC-CF-07 ~ TC-CF-09 : NF-24 — Rate Limiting
# =============================================================================

class TestRateLimiting:
    """NF-24: POST /analyze IP당 10회/분 초과 시 429 반환."""

    def _make_request(self, path: str, ip: str = "1.2.3.4") -> MagicMock:
        mock_request = MagicMock()
        mock_request.method = "POST"
        mock_request.url.path = path
        mock_request.headers = {}
        mock_client = MagicMock()
        mock_client.host = ip
        mock_request.client = mock_client
        return mock_request

    @pytest.mark.asyncio
    async def test_under_limit_passes(self):
        """TC-CF-07: 한도 미만 요청은 정상 통과한다."""
        from main import RateLimitMiddleware

        mock_app = AsyncMock()
        mw = RateLimitMiddleware(mock_app)
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        async def call_next(req):
            return mock_resp

        req = self._make_request("/analyze", ip="10.0.0.1")
        result = await mw.dispatch(req, call_next)
        assert result.status_code == 200

    @pytest.mark.asyncio
    async def test_exceeds_limit_returns_429(self):
        """TC-CF-08: /analyze 11회째 요청은 429를 반환한다."""
        from main import RateLimitMiddleware
        from fastapi.responses import JSONResponse

        mock_app = AsyncMock()
        mw = RateLimitMiddleware(mock_app)
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        async def call_next(req):
            return mock_resp

        ip = "10.0.0.99"
        # 10회는 통과
        for _ in range(10):
            req = self._make_request("/analyze", ip=ip)
            await mw.dispatch(req, call_next)

        # 11회째는 429
        req = self._make_request("/analyze", ip=ip)
        result = await mw.dispatch(req, call_next)
        assert result.status_code == 429

    @pytest.mark.asyncio
    async def test_get_not_rate_limited(self):
        """TC-CF-09: GET 메서드는 속도 제한을 받지 않는다."""
        from main import RateLimitMiddleware

        mock_app = AsyncMock()
        mw = RateLimitMiddleware(mock_app)
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        async def call_next(req):
            return mock_resp

        mock_request = MagicMock()
        mock_request.method = "GET"
        mock_request.url.path = "/sandbox/browse/id/novnc/"
        result = await mw.dispatch(mock_request, call_next)
        assert result.status_code == 200


# =============================================================================
# TC-CF-10 : DC-27 — browse_service에 VNC_PW 고정값 없음
# =============================================================================

class TestDC27NoPwConstant:
    """DC-27: browse_service 모듈 레벨에 VNC_PW 고정 상수가 없다."""

    def test_no_module_level_vnc_pw(self):
        """TC-CF-10: browse_service.VNC_PW 속성이 존재하지 않는다."""
        import services.browse_service as bs
        assert not hasattr(bs, "VNC_PW"), (
            "VNC_PW는 세션별로 생성해야 하며 모듈 레벨에 존재해선 안 된다 (DC-27)."
        )
