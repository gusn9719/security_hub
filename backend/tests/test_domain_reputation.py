# =============================================================================
# backend/tests/test_domain_reputation.py
# TC-ANL-01 ~ TC-ANL-10 : 도메인 평판 분석 테스트 (ANL-05 Sprint 5D)
# 실행: cd backend && python -m pytest tests/test_domain_reputation.py -v
# =============================================================================

import sys
import os
import socket
import ssl
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

# backend/ 를 sys.path에 추가 (uvicorn 실행 환경과 동일하게)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.domain_reputation_service import analyze_domain_reputation


# =============================================================================
# 헬퍼 — WHOIS mock 객체 생성
# =============================================================================

def _make_whois(creation_date=None, domain_name="example.com"):
    w = MagicMock()
    w.creation_date = creation_date
    w.domain_name = domain_name
    return w


# =============================================================================
# TC-ANL-01: 등록 15일 된 신규 도메인
# 기대: domain_age_days=15, new_domain=True, 판정 변경 없음 (evidence만 보강)
# =============================================================================

@patch("services.domain_reputation_service._check_ssl", return_value=(True, 5))
@patch("services.domain_reputation_service._WHOIS_AVAILABLE", True)
@patch("services.domain_reputation_service._whois_lib")
def test_anl_01_new_domain_15_days(mock_whois_lib, mock_ssl):
    creation = datetime.now(timezone.utc) - timedelta(days=15)
    mock_whois_lib.whois.return_value = _make_whois(creation_date=creation)

    result = analyze_domain_reputation("https://new-phishing-site.com/login")

    assert result["domain_age_days"] == 15
    assert result["new_domain"] is True
    assert result["skipped"] is False


# =============================================================================
# TC-ANL-02: 등록 365일 이상 도메인
# 기대: domain_age_days >= 365, new_domain=False
# =============================================================================

@patch("services.domain_reputation_service._check_ssl", return_value=(True, 300))
@patch("services.domain_reputation_service._WHOIS_AVAILABLE", True)
@patch("services.domain_reputation_service._whois_lib")
def test_anl_02_old_domain_365_days(mock_whois_lib, mock_ssl):
    creation = datetime.now(timezone.utc) - timedelta(days=400)
    mock_whois_lib.whois.return_value = _make_whois(creation_date=creation)

    result = analyze_domain_reputation("https://established-site.com")

    assert result["domain_age_days"] >= 365
    assert result["new_domain"] is False


# =============================================================================
# TC-ANL-03: http:// 도메인 → ssl_valid=False (SSL 조회 없음)
# =============================================================================

@patch("services.domain_reputation_service._WHOIS_AVAILABLE", True)
@patch("services.domain_reputation_service._whois_lib")
def test_anl_03_http_scheme_ssl_false(mock_whois_lib):
    creation = datetime.now(timezone.utc) - timedelta(days=100)
    mock_whois_lib.whois.return_value = _make_whois(creation_date=creation)

    result = analyze_domain_reputation("http://no-ssl-site.com/page")

    assert result["ssl_valid"] is False
    assert result["ssl_issued_days"] is None


# =============================================================================
# TC-ANL-04: domain_age<=30 AND ssl_issued<=7 → fresh_infrastructure=True
# =============================================================================

@patch("services.domain_reputation_service._check_ssl", return_value=(True, 3))
@patch("services.domain_reputation_service._WHOIS_AVAILABLE", True)
@patch("services.domain_reputation_service._whois_lib")
def test_anl_04_fresh_infrastructure(mock_whois_lib, mock_ssl):
    creation = datetime.now(timezone.utc) - timedelta(days=10)
    mock_whois_lib.whois.return_value = _make_whois(creation_date=creation)

    result = analyze_domain_reputation("https://brand-new-phish.com")

    assert result["fresh_infrastructure"] is True
    assert result["domain_age_days"] == 10
    assert result["ssl_issued_days"] == 3


# =============================================================================
# TC-ANL-05: WHOIS + SSL 모두 실패 → domain_age_days=None, 서비스 중단 없음
# =============================================================================

@patch(
    "services.domain_reputation_service._check_ssl",
    side_effect=Exception("SSL timeout"),
)
@patch("services.domain_reputation_service._WHOIS_AVAILABLE", True)
@patch("services.domain_reputation_service._whois_lib")
def test_anl_05_whois_and_ssl_both_fail(mock_whois_lib, mock_ssl):
    mock_whois_lib.whois.side_effect = Exception("WHOIS server unreachable")

    result = analyze_domain_reputation("https://unreachable-domain.com")

    assert result["domain_age_days"] is None
    assert result["skipped"] is False  # 스킵이 아니라 조회 실패
    assert result["fresh_infrastructure"] is False  # None이므로 False 유지


# =============================================================================
# TC-ANL-06: WHOIS 레코드 없는 도메인 → whois_no_record=True, domain_age_days=None
# None(조회 실패)과 레코드 없음을 구분한다.
# =============================================================================

@patch("services.domain_reputation_service._check_ssl", return_value=(True, 10))
@patch("services.domain_reputation_service._WHOIS_AVAILABLE", True)
@patch("services.domain_reputation_service._whois_lib")
def test_anl_06_whois_no_record(mock_whois_lib, mock_ssl):
    # creation_date=None, domain_name=None → 레코드 없음
    mock_whois_lib.whois.return_value = _make_whois(creation_date=None, domain_name=None)

    result = analyze_domain_reputation("https://ghost-domain.com")

    assert result["whois_no_record"] is True
    assert result["domain_age_days"] is None


# =============================================================================
# TC-ANL-07: 서브도메인 포함 URL → registered domain 추출 후 WHOIS 조회
# 서브도메인째 WHOIS 호출 안 함 — whois.whois() 인자 확인
# =============================================================================

@patch("services.domain_reputation_service._check_ssl", return_value=(True, 20))
@patch("services.domain_reputation_service._WHOIS_AVAILABLE", True)
@patch("services.domain_reputation_service._whois_lib")
def test_anl_07_subdomain_uses_registered_domain(mock_whois_lib, mock_ssl):
    creation = datetime.now(timezone.utc) - timedelta(days=50)
    mock_whois_lib.whois.return_value = _make_whois(creation_date=creation)

    analyze_domain_reputation("https://sub.evil-domain.com/path?q=1")

    called_domain = mock_whois_lib.whois.call_args[0][0]
    # 서브도메인 'sub'가 포함되면 안 됨
    assert called_domain == "evil-domain.com", (
        f"WHOIS 호출 인자에 서브도메인이 포함됨: {called_domain}"
    )


# =============================================================================
# TC-ANL-08: IP 주소 URL → WHOIS/SSL 호출 없이 스킵
# =============================================================================

@patch("services.domain_reputation_service._check_ssl")
@patch("services.domain_reputation_service._WHOIS_AVAILABLE", True)
@patch("services.domain_reputation_service._whois_lib")
def test_anl_08_ip_address_skipped(mock_whois_lib, mock_ssl):
    result = analyze_domain_reputation("http://123.45.67.89/login")

    assert result["skipped"] is True
    mock_whois_lib.whois.assert_not_called()
    mock_ssl.assert_not_called()


# =============================================================================
# TC-ANL-09: .kr 도메인 → WHOIS/SSL 조회 스킵 (SKIP_WHOIS_TLDS)
# =============================================================================

@patch("services.domain_reputation_service._check_ssl")
@patch("services.domain_reputation_service._WHOIS_AVAILABLE", True)
@patch("services.domain_reputation_service._whois_lib")
def test_anl_09_kr_domain_skipped(mock_whois_lib, mock_ssl):
    result = analyze_domain_reputation("https://government.kr/notice")

    assert result["skipped"] is True
    mock_whois_lib.whois.assert_not_called()
    mock_ssl.assert_not_called()


# =============================================================================
# TC-ANL-10: 서버 연결 성공 + SSL 없음 → ssl_valid=False (None 아님)
# 포트 80이 열려 있어 서버는 살아있지만 443 포트(SSL) 없음
# =============================================================================

@patch("services.domain_reputation_service._WHOIS_AVAILABLE", True)
@patch("services.domain_reputation_service._whois_lib")
def test_anl_10_http_only_server_ssl_false_not_none(mock_whois_lib):
    creation = datetime.now(timezone.utc) - timedelta(days=200)
    mock_whois_lib.whois.return_value = _make_whois(creation_date=creation)

    # _check_ssl 내부를 직접 패치: 443 실패 + 80 성공 → (False, None)
    with patch(
        "services.domain_reputation_service._check_ssl",
        return_value=(False, None),
    ):
        result = analyze_domain_reputation("https://http-only-server.com")

    assert result["ssl_valid"] is False, (
        f"ssl_valid가 None이면 안 됨 (서버는 살아있음): {result['ssl_valid']}"
    )
    assert result["ssl_issued_days"] is None
