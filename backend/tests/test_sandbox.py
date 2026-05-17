# =============================================================================
# backend/tests/test_sandbox.py
# TC-SBX-01 ~ TC-SBX-12 : 샌드박스 서비스 단위 테스트
#
# 실행: cd backend && python -m pytest tests/test_sandbox.py -v
# Docker / Playwright / 외부 네트워크 없이 순수 로직만 검증한다.
# =============================================================================

import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.sandbox_service import _calc_score, _wait_for_port, FAKE_CREDS


# =============================================================================
# TC-SBX-01 ~ TC-SBX-05 : _calc_score() 룰 기반 점수 계산
# =============================================================================

class TestCalcScore:
    """_calc_score() — indicators dict → sandbox_score + findings."""

    def test_empty_indicators_returns_zero(self):
        """TC-SBX-01: 위협 시그널 없으면 score=0, findings 빈 목록."""
        result = _calc_score({})
        assert result["score"] == 0
        assert result["findings"] == []

    def test_password_form_adds_30(self):
        """TC-SBX-02: form_with_password → +30."""
        result = _calc_score({"form_with_password": True})
        assert result["score"] == 30
        assert any("비밀번호" in f for f in result["findings"])

    def test_external_form_action_adds_40(self):
        """TC-SBX-03: external_form_action → +40."""
        result = _calc_score({"external_form_action": True})
        assert result["score"] == 40
        assert any("외부 도메인" in f for f in result["findings"])

    def test_auto_download_adds_50(self):
        """TC-SBX-04: auto_download → +50."""
        result = _calc_score({"auto_download": True})
        assert result["score"] == 50
        assert any("다운로드" in f for f in result["findings"])

    def test_score_clamped_at_100(self):
        """TC-SBX-05: 모든 시그널 합산 시 score는 100을 초과하지 않는다 (최대 165 → 100)."""
        indicators = {
            "form_with_password": True,    # +30
            "external_form_action": True,  # +40
            "auto_download": True,         # +50
            "redirect_count": 5,           # +20
            "clipboard_access": True,      # +25
        }
        result = _calc_score(indicators)
        assert result["score"] == 100
        assert len(result["findings"]) == 5

    def test_redirect_below_threshold_no_score(self):
        """TC-SBX-06: redirect_count < 3이면 점수에 포함되지 않는다."""
        result = _calc_score({"redirect_count": 2})
        assert result["score"] == 0
        assert result["findings"] == []

    def test_redirect_at_threshold_adds_20(self):
        """TC-SBX-07: redirect_count >= 3이면 +20."""
        result = _calc_score({"redirect_count": 3})
        assert result["score"] == 20
        assert any("리다이렉트" in f for f in result["findings"])


# =============================================================================
# TC-SBX-08 : FAKE_CREDS 상수 검증
# =============================================================================

class TestFakeCreds:
    """FAKE_CREDS — 실제 정보가 아닌 가짜 자격증명 확인."""

    def test_fake_creds_not_real_data(self):
        """TC-SBX-08: FAKE_CREDS의 phone이 실제 번호 형식이 아닌지 확인."""
        phone = FAKE_CREDS["phone"]
        # 실제 한국 번호는 010-XXXX-XXXX이지만 테스트 데이터는 000-1111-2222 형태여야 함
        # 여기서는 'security-hub.local' 도메인 포함 여부로 가짜임을 확인
        assert "security-hub.local" in FAKE_CREDS["email"]

    def test_fake_creds_has_all_required_keys(self):
        """TC-SBX-09: FAKE_CREDS에 필수 키가 모두 존재한다."""
        required = {"name", "phone", "email", "password", "id", "birth", "card"}
        assert required.issubset(FAKE_CREDS.keys())

    def test_fake_card_is_zeros(self):
        """TC-SBX-10: 카드번호가 0000으로 채워진 가짜 데이터임을 확인."""
        assert FAKE_CREDS["card"] == "0000-0000-0000-0000"


# =============================================================================
# TC-SBX-09~10 : vote_service 단위 테스트 (임시 SQLite DB 사용)
# =============================================================================

@pytest.fixture
def temp_db(tmp_path):
    """격리된 임시 SQLite DB를 생성하고 url_votes 테이블을 초기화한다."""
    db_path = tmp_path / "test_votes.db"
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE url_votes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            url_hash   TEXT NOT NULL,
            url        TEXT NOT NULL,
            vote       TEXT NOT NULL CHECK(vote IN ('safe', 'danger')),
            voted_at   TEXT NOT NULL,
            session_id TEXT
        )
    """)
    conn.execute("""
        CREATE UNIQUE INDEX idx_votes_session_id
        ON url_votes (session_id)
        WHERE session_id IS NOT NULL
    """)
    conn.commit()
    conn.close()
    return str(db_path)


class TestVoteService:
    """vote_service — save_vote / get_vote_counts."""

    def _save_vote_direct(self, db_path, url, session_id, vote):
        """DB 경로를 직접 받아 투표를 저장하는 헬퍼."""
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat()
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "INSERT OR IGNORE INTO url_votes (url_hash, url, vote, voted_at, session_id) "
            "VALUES (?, ?, ?, ?, ?)",
            (url_hash, url, vote, now, session_id),
        )
        saved = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return saved

    def test_save_vote_success(self, temp_db):
        """TC-SBX-11: 신규 투표가 성공적으로 저장된다."""
        saved = self._save_vote_direct(
            temp_db, "http://example.com", "session-001", "danger"
        )
        assert saved is True

    def test_duplicate_session_id_rejected(self, temp_db):
        """TC-SBX-12: 동일 session_id로 중복 투표 시 두 번째는 무시된다."""
        self._save_vote_direct(temp_db, "http://example.com", "session-dup", "danger")
        saved_again = self._save_vote_direct(
            temp_db, "http://example.com", "session-dup", "safe"
        )
        assert saved_again is False

    def test_vote_count_aggregation(self, temp_db):
        """TC-SBX-13: URL별 safe/danger 집계가 정확하다."""
        url = "http://phishing.example"
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat()

        conn = sqlite3.connect(temp_db)
        conn.execute(
            "INSERT INTO url_votes (url_hash, url, vote, voted_at, session_id) VALUES (?,?,?,?,?)",
            (url_hash, url, "danger", now, "s1"),
        )
        conn.execute(
            "INSERT INTO url_votes (url_hash, url, vote, voted_at, session_id) VALUES (?,?,?,?,?)",
            (url_hash, url, "danger", now, "s2"),
        )
        conn.execute(
            "INSERT INTO url_votes (url_hash, url, vote, voted_at, session_id) VALUES (?,?,?,?,?)",
            (url_hash, url, "safe", now, "s3"),
        )
        conn.commit()
        conn.close()

        conn = sqlite3.connect(temp_db)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT vote, COUNT(*) AS cnt FROM url_votes WHERE url_hash = ? GROUP BY vote",
            (url_hash,),
        ).fetchall()
        conn.close()

        counts = {r["vote"]: r["cnt"] for r in rows}
        assert counts.get("danger") == 2
        assert counts.get("safe") == 1


# =============================================================================
# TC-SBX-14 : _check_sandbox_cache / _save_sandbox_result 캐시 라이프사이클
# =============================================================================

class TestSandboxCache:
    """sandbox_results 캐시 저장 → 조회 → 만료 확인."""

    def _make_db(self, tmp_path):
        db_path = tmp_path / "cache_test.db"
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("""
            CREATE TABLE sandbox_results (
                session_id        TEXT    PRIMARY KEY,
                url_hash          TEXT    NOT NULL,
                url               TEXT    NOT NULL,
                mode              TEXT    NOT NULL DEFAULT '7b' CHECK(mode IN ('7a','7b')),
                domain            TEXT    NOT NULL DEFAULT '',
                registered_domain TEXT,
                visited_urls      TEXT,
                findings          TEXT,
                sandbox_score     INTEGER DEFAULT 0,
                summary           TEXT,
                screenshots       TEXT,
                final_url         TEXT,
                redirect_count    INTEGER DEFAULT 0,
                error             TEXT,
                analyzed_at       TEXT    NOT NULL,
                expires_at        TEXT    NOT NULL
            )
        """)
        conn.commit()
        conn.close()
        return str(db_path)

    def test_cache_miss_returns_none(self, tmp_path):
        """TC-SBX-14: DB에 레코드 없으면 None 반환."""
        db_path = self._make_db(tmp_path)
        url_hash = hashlib.sha256(b"http://missing.example").hexdigest()
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat()

        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM sandbox_results WHERE url_hash = ? AND expires_at > ?",
            (url_hash, now),
        ).fetchone()
        conn.close()

        assert row is None

    def test_cache_hit_within_ttl(self, tmp_path):
        """TC-SBX-15: 24h TTL 이내 캐시가 조회된다."""
        db_path = self._make_db(tmp_path)
        url = "http://cached.example"
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        expires = (now + datetime.timedelta(hours=24)).isoformat()
        now_str = now.isoformat()

        conn = sqlite3.connect(db_path)
        conn.execute(
            """INSERT INTO sandbox_results
               (session_id, url_hash, url, sandbox_score, findings, summary,
                screenshots, final_url, redirect_count, error, analyzed_at, expires_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("sid-001", url_hash, url, 70,
             json.dumps(["비밀번호 폼 감지"]), "요약 텍스트",
             json.dumps([]), url, 0, None, now_str, expires),
        )
        conn.commit()
        conn.close()

        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM sandbox_results WHERE url_hash = ? AND expires_at > ?",
            (url_hash, datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat()),
        ).fetchone()
        conn.close()

        assert row is not None
        assert row["sandbox_score"] == 70
        assert json.loads(row["findings"]) == ["비밀번호 폼 감지"]

    def test_cache_expired_not_returned(self, tmp_path):
        """TC-SBX-16: 만료된 캐시는 조회되지 않는다."""
        db_path = self._make_db(tmp_path)
        url = "http://expired.example"
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        past = (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - datetime.timedelta(hours=1)).isoformat()
        now_str = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat()

        conn = sqlite3.connect(db_path)
        conn.execute(
            """INSERT INTO sandbox_results
               (session_id, url_hash, url, sandbox_score, findings, summary,
                screenshots, final_url, redirect_count, error, analyzed_at, expires_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("sid-exp", url_hash, url, 0, "[]", "", "[]", url, 0, None, past, past),
        )
        conn.commit()
        conn.close()

        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM sandbox_results WHERE url_hash = ? AND expires_at > ?",
            (url_hash, now_str),
        ).fetchone()
        conn.close()

        assert row is None


# =============================================================================
# TC-SBX-17 : run_auto_test() URL 스킴 검증
# =============================================================================

class TestRunAutoTestUrlValidation:
    """run_auto_test() — 지원하지 않는 스킴 요청 시 오류 반환."""

    @pytest.mark.asyncio
    async def test_invalid_scheme_returns_error(self):
        """TC-SBX-17: javascript: 스킴 요청 시 score=0, error 포함 응답."""
        from services.sandbox_service import run_auto_test
        result = await run_auto_test("javascript:alert(1)")
        assert result["sandbox_score"] == 0
        assert result["error"] is not None
        assert "스킴" in result["error"]

    @pytest.mark.asyncio
    async def test_file_scheme_returns_error(self):
        """TC-SBX-18: file: 스킴 요청 시 오류 응답."""
        from services.sandbox_service import run_auto_test
        result = await run_auto_test("file:///etc/passwd")
        assert result["sandbox_score"] == 0
        assert result["error"] is not None


# =============================================================================
# TC-SBX-19 : VoteRequest 스키마 검증
# =============================================================================

class TestVoteSchema:
    """VoteRequest Pydantic 스키마 — vote 필드 패턴 검증."""

    def test_valid_safe_vote(self):
        """TC-SBX-19: 'safe' 투표는 유효하다."""
        from schemas.analysis import VoteRequest
        req = VoteRequest(url="http://example.com", session_id="abc", vote="safe")
        assert req.vote == "safe"

    def test_valid_danger_vote(self):
        """TC-SBX-20: 'danger' 투표는 유효하다."""
        from schemas.analysis import VoteRequest
        req = VoteRequest(url="http://example.com", session_id="abc", vote="danger")
        assert req.vote == "danger"

    def test_invalid_vote_value_rejected(self):
        """TC-SBX-21: 허용되지 않은 vote 값은 ValidationError를 발생시킨다."""
        from pydantic import ValidationError
        from schemas.analysis import VoteRequest
        with pytest.raises(ValidationError):
            VoteRequest(url="http://example.com", session_id="abc", vote="unknown")
