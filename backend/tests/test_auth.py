# =============================================================================
# backend/tests/test_auth.py
# AUTH-01 ~ 03 + DC-45 ~ 48 단위 테스트
#
# 실행: cd backend && python -m pytest tests/test_auth.py -v
# =============================================================================

import os
import sys
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# 모든 jwt_service 호출 전에 환경변수 셋업.
# 실제 운영 시크릿이 들어와도 본 테스트는 monkey-patch 한 더미 시크릿 사용.
os.environ.setdefault("JWT_SECRET", "a" * 64)
os.environ.setdefault("JWT_ALG", "HS256")
os.environ.setdefault("JWT_EXPIRE_HOURS", "1")

_VALID_UUID = "00000000-0000-4000-8000-000000000000"


# =============================================================================
# TC-AUTH-01 ~ 05 : jwt_service 단위 (DC-47 시크릿 강도 포함)
# =============================================================================

class TestJWTService:
    """jwt_service: 발급/검증 round-trip + 시크릿 강도 검증."""

    def test_issue_and_decode_round_trip(self):
        """TC-AUTH-01: issue → decode 라운드트립이 user_id 보존."""
        from services import jwt_service
        token, expires_in = jwt_service.issue_token(42)
        assert isinstance(token, str) and len(token) > 0
        assert expires_in > 0
        assert jwt_service.decode_token(token) == 42

    def test_short_secret_rejected(self):
        """TC-AUTH-02 (DC-47): 32 자 미만 시크릿은 ValueError 거부."""
        from services import jwt_service
        with patch.dict(os.environ, {"JWT_SECRET": "short"}, clear=False):
            with pytest.raises(ValueError, match="너무 짧"):
                jwt_service.issue_token(1)

    def test_missing_secret_rejected(self):
        """TC-AUTH-03 (DC-47): 시크릿 미설정은 ValueError 거부."""
        from services import jwt_service
        env = {k: v for k, v in os.environ.items() if k != "JWT_SECRET"}
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValueError, match="설정되지 않았"):
                jwt_service.issue_token(1)

    def test_tampered_token_rejected(self):
        """TC-AUTH-04: 변조된 토큰은 JWTError."""
        from services import jwt_service
        token, _ = jwt_service.issue_token(7)
        tampered = token[:-2] + ("AA" if token[-2:] != "AA" else "BB")
        with pytest.raises(jwt_service.JWTError):
            jwt_service.decode_token(tampered)

    def test_empty_token_rejected(self):
        """TC-AUTH-05: 빈 토큰 거부."""
        from services import jwt_service
        with pytest.raises(jwt_service.JWTError):
            jwt_service.decode_token("")


# =============================================================================
# TC-AUTH-06 ~ 10 : user_service + kakao_id 마스킹 (DC-47)
# =============================================================================

class TestUserService:
    """database/user_service: upsert / get + kakao_id 마스킹."""

    def test_mask_kakao_id_normal(self):
        """TC-AUTH-06 (DC-47): 평범한 길이 kakao_id 는 앞 4 자만 노출."""
        from database.user_service import _mask_kakao_id
        assert _mask_kakao_id("1234567890") == "1234******"

    def test_mask_kakao_id_short(self):
        """TC-AUTH-07: 4 자 이하는 전체 별표."""
        from database.user_service import _mask_kakao_id
        assert _mask_kakao_id("12") == "****"
        assert _mask_kakao_id("") == "****"

    def test_upsert_insert_then_update(self, tmp_path, monkeypatch):
        """TC-AUTH-08: 신규 INSERT 후 같은 kakao_id 재호출은 UPDATE."""
        # 임시 DB 로 격리
        db_path = tmp_path / "test_auth.db"
        monkeypatch.setattr(
            "database.db_init.DB_PATH", db_path
        )
        from database.db_init import init_db
        init_db()

        from database.user_service import upsert_by_kakao_id, get_by_id

        user_id_1 = upsert_by_kakao_id(
            kakao_id="111", nickname="alice", email="a@example.com"
        )
        assert user_id_1 is not None
        user_id_2 = upsert_by_kakao_id(
            kakao_id="111", nickname="alice-renamed", email=None
        )
        assert user_id_2 == user_id_1, "같은 kakao_id 면 같은 user_id"

        profile = get_by_id(user_id_1)
        assert profile["kakao_id"] == "111"
        # nickname 은 COALESCE — 신규 값으로 갱신됨
        assert profile["nickname"] == "alice-renamed"
        # email 은 NEW 우선 — 동의 철회 시 None 으로 즉시 반영 (DC-47)
        assert profile["email"] is None

    def test_upsert_rejects_empty_kakao_id(self):
        """TC-AUTH-09: 빈 kakao_id 는 None 반환."""
        from database.user_service import upsert_by_kakao_id
        assert upsert_by_kakao_id(kakao_id="") is None
        assert upsert_by_kakao_id(kakao_id=None) is None  # type: ignore


# =============================================================================
# TC-AUTH-10 ~ 14 : OptionalAuthMiddleware (DC-46)
# =============================================================================

@pytest.fixture
def client():
    """TestClient — main.app 한 번 import."""
    from main import app
    return TestClient(app)


class TestOptionalAuthMiddleware:
    """DC-46: 미들웨어가 토큰 검증을 일원화. 무효 토큰 401."""

    def test_anonymous_request_passes_through(self, client):
        """TC-AUTH-10: Authorization 헤더 없으면 익명으로 통과 (200)."""
        # /sandbox/votes 가 익명 OK 라 흐름 검증에 적당.
        resp = client.post(
            "/sandbox/votes",
            headers={"X-Device-UUID": _VALID_UUID},
            json={
                "url": "https://example.com/anon",
                "session_id": "tc-auth-10",
                "vote": "safe",
                "device_uuid": _VALID_UUID,
            },
        )
        assert resp.status_code == 200, resp.text

    def test_valid_jwt_passes_with_user_id(self, client):
        """TC-AUTH-11: 유효 JWT 부착 시 user_id 가 라우터에 전달되어 정상 처리."""
        from services import jwt_service
        token, _ = jwt_service.issue_token(99)
        resp = client.post(
            "/sandbox/votes",
            headers={
                "X-Device-UUID": _VALID_UUID,
                "Authorization": f"Bearer {token}",
            },
            json={
                "url": "https://example.com/user",
                "session_id": "tc-auth-11",
                "vote": "danger",
                "device_uuid": _VALID_UUID,
            },
        )
        assert resp.status_code == 200, resp.text

    def test_invalid_jwt_rejected_401(self, client):
        """TC-AUTH-12 (DC-46): 무효 토큰은 silent pass-through 가 아니라 401."""
        resp = client.post(
            "/sandbox/votes",
            headers={
                "X-Device-UUID": _VALID_UUID,
                "Authorization": "Bearer not.a.real.token",
            },
            json={
                "url": "https://example.com/x",
                "session_id": "tc-auth-12",
                "vote": "safe",
                "device_uuid": _VALID_UUID,
            },
        )
        assert resp.status_code == 401

    def test_non_bearer_auth_rejected_401(self, client):
        """TC-AUTH-13 (DC-46): Basic 등 비-Bearer 는 401."""
        resp = client.post(
            "/sandbox/votes",
            headers={
                "X-Device-UUID": _VALID_UUID,
                "Authorization": "Basic dXNlcjpwYXNz",
            },
            json={
                "url": "https://example.com/x",
                "session_id": "tc-auth-13",
                "vote": "safe",
                "device_uuid": _VALID_UUID,
            },
        )
        assert resp.status_code == 401

    def test_auth_me_without_token_401(self, client):
        """TC-AUTH-14: /auth/me 는 가입자 전용. 토큰 없으면 401."""
        resp = client.get("/auth/me", headers={"X-Device-UUID": _VALID_UUID})
        assert resp.status_code == 401


# =============================================================================
# TC-AUTH-15 ~ 17 : /auth/kakao 라우터 (mock 카카오)
# =============================================================================

class TestAuthKakaoRouter:
    """POST /auth/kakao 정상/실패 흐름."""

    def test_kakao_login_invalid_token_returns_401(self, client):
        """TC-AUTH-15: 카카오가 무효 토큰을 거부하면 401 응답."""
        from services import kakao_service
        async def _raise(_t):
            raise kakao_service.KakaoAuthError("invalid kakao token")
        with patch.object(kakao_service, "fetch_user_info", AsyncMock(side_effect=_raise)):
            resp = client.post(
                "/auth/kakao",
                headers={"X-Device-UUID": _VALID_UUID},
                json={"access_token": "bad"},
            )
        assert resp.status_code == 401

    def test_kakao_login_success_issues_jwt(self, client):
        """TC-AUTH-16: 카카오 검증 성공 → JWT + user 동봉 응답."""
        from services import kakao_service
        from database import user_service

        async def _ok(_t):
            return {"kakao_id": "abc123", "nickname": "tester", "email": None}

        # user_service.upsert 와 get_by_id 도 mock — 실 DB 의존 제거.
        with patch.object(kakao_service, "fetch_user_info", AsyncMock(side_effect=_ok)), \
             patch.object(user_service, "upsert_by_kakao_id", return_value=777), \
             patch.object(user_service, "get_by_id", return_value={
                 "id": 777, "kakao_id": "abc123", "nickname": "tester",
                 "email": None,
                 "created_at": "2026-01-01T00:00:00",
                 "last_login_at": "2026-01-01T00:00:00",
             }):
            resp = client.post(
                "/auth/kakao",
                headers={"X-Device-UUID": _VALID_UUID},
                json={"access_token": "good"},
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["token_type"] == "Bearer"
        assert body["expires_in"] > 0
        assert body["access_token"]
        assert body["user"]["id"] == 777
        assert body["user"]["kakao_id"] == "abc123"

        # 발급된 JWT 가 user_id 777 을 sub 로 가짐
        from services import jwt_service
        assert jwt_service.decode_token(body["access_token"]) == 777

    def test_logout_returns_204(self, client):
        """TC-AUTH-17: /auth/logout 은 stateless 204."""
        resp = client.post(
            "/auth/logout",
            headers={"X-Device-UUID": _VALID_UUID},
        )
        assert resp.status_code == 204


# =============================================================================
# TC-AUTH-18 ~ 23 : 가입자/익명 표 분리 임계값 (DC-45)
# =============================================================================

class TestUserVsAnonVoteSignal:
    """heuristic_scorer: prior_*_vote 의 가입자/익명 분리 임계값."""

    _CLEAN_URL = "https://test-signal-only.example.com/path"

    def _base(self, **counts):
        """0 값으로 채운 기본 dict 위에 인자만 갱신."""
        zero = {
            "safe": 0, "danger": 0, "spam": 0, "unsure": 0,
            "anon_safe": 0, "anon_danger": 0, "anon_spam": 0,
            "user_safe": 0, "user_danger": 0, "user_spam": 0,
            "total": 0,
        }
        zero.update(counts)
        # 합계 키 자동 산출 (안 넘긴 경우만 보완)
        zero["safe"] = zero["anon_safe"] + zero["user_safe"]
        zero["danger"] = zero["anon_danger"] + zero["user_danger"]
        zero["spam"] = zero["anon_spam"] + zero["user_spam"]
        zero["total"] = zero["safe"] + zero["danger"] + zero["spam"]
        return zero

    def test_user_danger_1_triggers_low(self):
        """TC-AUTH-18 (DC-45): 가입자 danger 1 → prior_danger_vote_low 발동."""
        from services.heuristic_scorer import score_url
        result = score_url(
            self._CLEAN_URL,
            vote_counts=self._base(user_danger=1),
        )
        assert "prior_danger_vote_low" in result.triggered
        assert "prior_danger_vote_high" not in result.triggered

    def test_user_danger_3_triggers_high(self):
        """TC-AUTH-19 (DC-45): 가입자 danger 3 → prior_danger_vote_high 발동."""
        from services.heuristic_scorer import score_url
        result = score_url(
            self._CLEAN_URL,
            vote_counts=self._base(user_danger=3),
        )
        assert "prior_danger_vote_high" in result.triggered
        assert "prior_danger_vote_low" not in result.triggered

    def test_anon_danger_2_does_not_trigger(self):
        """TC-AUTH-20: 익명 danger 2 + 가입자 0 → 시그널 없음 (anon<3)."""
        from services.heuristic_scorer import score_url
        result = score_url(
            self._CLEAN_URL,
            vote_counts=self._base(anon_danger=2),
        )
        assert "prior_danger_vote_low" not in result.triggered
        assert "prior_danger_vote_high" not in result.triggered

    def test_user_safe_1_triggers_negative_low(self):
        """TC-AUTH-21 (DC-45): 가입자 safe 1 → prior_safe_vote_low (-5)."""
        from services.heuristic_scorer import score_url
        result = score_url(
            self._CLEAN_URL,
            vote_counts=self._base(user_safe=1),
        )
        assert "prior_safe_vote_low" in result.triggered
        # 0 클램프로 score 는 max(0, -5) = 0
        assert result.score == 0

    def test_dominant_direction_guard(self):
        """TC-AUTH-22: 합계 기준 우세 방향 가드 — safe>=danger 면 prior_danger 미발동."""
        from services.heuristic_scorer import score_url
        # 가입자 danger 1 만 보면 발동인데, 익명 safe 5 가 합계로는 더 큼.
        # → 합계 비교에서 danger<safe 라 danger 시그널 미발동.
        result = score_url(
            self._CLEAN_URL,
            vote_counts=self._base(user_danger=1, anon_safe=5),
        )
        assert "prior_danger_vote_low" not in result.triggered
        assert "prior_danger_vote_high" not in result.triggered
        # safe 우세는 발동
        assert "prior_safe_vote_low" in result.triggered

    def test_user_spam_3_triggers_high(self):
        """TC-AUTH-23 (DC-45): 가입자 spam 3 → prior_spam_vote_high."""
        from services.heuristic_scorer import score_url
        result = score_url(
            self._CLEAN_URL,
            vote_counts=self._base(user_spam=3),
        )
        assert "prior_spam_vote_high" in result.triggered


# =============================================================================
# TC-AUTH-24 ~ 26 : vote_service 가입자/익명 저장·집계
# =============================================================================

class TestVoteServiceUserIdSplit:
    """vote_service: user_id 인자 저장 + anon_*/user_* 키 집계."""

    def test_save_vote_with_user_id(self, tmp_path, monkeypatch):
        """TC-AUTH-24: save_vote(user_id=99) → DB 행에 user_id=99 기록."""
        db_path = tmp_path / "test_votes.db"
        monkeypatch.setattr("database.db_init.DB_PATH", db_path)
        from database.db_init import init_db, get_ro_connection
        init_db()

        from database.vote_service import save_vote
        ok = save_vote(
            url="https://x.example.com/p",
            session_id="tc-auth-24",
            vote="danger",
            device_uuid=_VALID_UUID,
            user_id=99,
        )
        assert ok is True

        with get_ro_connection() as conn:
            row = conn.execute(
                "SELECT user_id, vote FROM url_votes WHERE session_id = ?",
                ("tc-auth-24",),
            ).fetchone()
            assert row is not None
            assert row["vote"] == "danger"
            assert row["user_id"] == 99

    def test_save_vote_anonymous_user_id_null(self, tmp_path, monkeypatch):
        """TC-AUTH-25: user_id 안 주면 NULL 저장 (익명 분류)."""
        db_path = tmp_path / "test_votes2.db"
        monkeypatch.setattr("database.db_init.DB_PATH", db_path)
        from database.db_init import init_db, get_ro_connection
        init_db()

        from database.vote_service import save_vote
        save_vote(
            url="https://y.example.com/p",
            session_id="tc-auth-25",
            vote="safe",
            device_uuid=_VALID_UUID,
        )
        with get_ro_connection() as conn:
            row = conn.execute(
                "SELECT user_id FROM url_votes WHERE session_id = ?",
                ("tc-auth-25",),
            ).fetchone()
            assert row["user_id"] is None

    def test_get_vote_counts_splits_anon_and_user(self, tmp_path, monkeypatch):
        """TC-AUTH-26: get_vote_counts 가 anon_*/user_* 키를 정확히 분리."""
        db_path = tmp_path / "test_votes3.db"
        monkeypatch.setattr("database.db_init.DB_PATH", db_path)
        from database.db_init import init_db
        init_db()

        from database.vote_service import save_vote, get_vote_counts
        url = "https://split.example.com/p"
        # 가입자 1 명 danger
        save_vote(url, "tc26-u1", "danger", "11111111-1111-4111-8111-111111111111", user_id=1)
        # 익명 1 명 danger (다른 device_uuid)
        save_vote(url, "tc26-a1", "danger", "22222222-2222-4222-8222-222222222222")

        counts = get_vote_counts(url)
        assert counts["user_danger"] == 1
        assert counts["anon_danger"] == 1
        assert counts["danger"] == 2   # 합계 (후방 호환)
        assert counts["total"] == 2
        assert counts["unsure"] == 0   # v0527 정책 — 항상 0
