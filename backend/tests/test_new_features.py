# =============================================================================
# backend/tests/test_new_features.py
# PROMPT-5 ~ PROMPT-8 신규 기능 단위 테스트
#
# TC-NF-01 ~ TC-NF-17
# 실행: cd backend && python -m pytest tests/test_new_features.py -v
# =============================================================================

import hashlib
import json
import os
import sqlite3
import sys
import datetime
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.heuristic_scorer import score_url, DANGER_THRESHOLD, SUSPICIOUS_THRESHOLD


# =============================================================================
# TC-NF-01 ~ TC-NF-04 : PROMPT-8 — DANGER 임계값 70
# =============================================================================

class TestDangerThreshold:
    """PROMPT-8: DANGER_THRESHOLD = 70 검증."""

    def test_threshold_constant_is_70(self):
        """TC-NF-01: DANGER_THRESHOLD 상수가 70이다."""
        assert DANGER_THRESHOLD == 70

    def test_suspicious_threshold_unchanged(self):
        """TC-NF-02: SUSPICIOUS_THRESHOLD 는 30 으로 변경되지 않았다."""
        assert SUSPICIOUS_THRESHOLD == 30

    def test_score_69_is_suspicious_not_danger(self):
        """TC-NF-03: score=69 는 SUSPICIOUS (구 임계값 60에서는 DANGER였음)."""
        # ip_in_url(35) + dangerous_extension(35) = 70점이지만
        # .apk 파일 + IP URL → 두 시그널 합이 정확히 70 → DANGER.
        # 65점 조합: subdomain_spoofing(30) + brand_keyword_mismatch(20) +
        #             suspicious_tld(10) + url_too_long(5) = 65 → SUSPICIOUS
        url = "https://naver.com.evil.xyz/" + "a" * 80
        result = score_url(url)
        # subdomain_spoofing 30 + brand_keyword_mismatch 20 + suspicious_tld 10
        # + url_too_long 5 = 65 → SUSPICIOUS (이전엔 60 초과라 DANGER 가능)
        assert result.score < DANGER_THRESHOLD
        assert result.verdict == "SUSPICIOUS"

    def test_score_70_is_danger(self):
        """TC-NF-04: score=70 은 DANGER (ip_in_url 35 + dangerous_extension 35)."""
        result = score_url("http://192.168.1.1/malware.apk")
        assert "ip_in_url" in result.triggered
        assert "dangerous_extension" in result.triggered
        assert result.score >= DANGER_THRESHOLD
        assert result.verdict == "DANGER"


# =============================================================================
# TC-NF-05 ~ TC-NF-09 : PROMPT-5 — prior_danger_vote 시그널
# =============================================================================

class TestVoteSignal:
    """PROMPT-5: vote_counts 시그널 — prior_danger_vote_high / low."""

    # 투표 시그널만 발화시키기 위해 투표 시그널 외 다른 시그널이 없는 URL 사용
    _CLEAN_URL = "https://test-signal-only.example.com/path"

    def test_no_vote_counts_no_signal(self):
        """TC-NF-05: vote_counts=None이면 투표 시그널이 발화되지 않는다."""
        result = score_url(self._CLEAN_URL, vote_counts=None)
        assert "prior_danger_vote_high" not in result.triggered
        assert "prior_danger_vote_low" not in result.triggered

    def test_danger_lt3_no_signal(self):
        """TC-NF-06: danger < 3 이면 투표 시그널 없음."""
        result = score_url(
            self._CLEAN_URL,
            vote_counts={"danger": 2, "safe": 0, "total": 2},
        )
        assert "prior_danger_vote_high" not in result.triggered
        assert "prior_danger_vote_low" not in result.triggered

    def test_danger_gte3_low_signal(self):
        """TC-NF-07: danger >= 3 and danger > safe → prior_danger_vote_low (+20)."""
        result = score_url(
            self._CLEAN_URL,
            vote_counts={"danger": 3, "safe": 0, "total": 3},
        )
        assert "prior_danger_vote_low" in result.triggered
        assert result.triggered["prior_danger_vote_low"] == 20
        assert "prior_danger_vote_high" not in result.triggered

    def test_danger_gte10_high_signal(self):
        """TC-NF-08: danger >= 10 and danger > safe → prior_danger_vote_high (+35)."""
        result = score_url(
            self._CLEAN_URL,
            vote_counts={"danger": 10, "safe": 2, "total": 12},
        )
        assert "prior_danger_vote_high" in result.triggered
        assert result.triggered["prior_danger_vote_high"] == 35
        assert "prior_danger_vote_low" not in result.triggered

    def test_danger_not_gt_safe_no_signal(self):
        """TC-NF-09: danger <= safe 이면 투표 시그널 없음 (safe가 더 많거나 같음)."""
        # danger == safe
        result = score_url(
            self._CLEAN_URL,
            vote_counts={"danger": 5, "safe": 5, "total": 10},
        )
        assert "prior_danger_vote_high" not in result.triggered
        assert "prior_danger_vote_low" not in result.triggered

        # safe > danger
        result2 = score_url(
            self._CLEAN_URL,
            vote_counts={"danger": 5, "safe": 8, "total": 13},
        )
        assert "prior_danger_vote_high" not in result2.triggered
        assert "prior_danger_vote_low" not in result2.triggered


# =============================================================================
# TC-NF-10 ~ TC-NF-13 : PROMPT-6 — sandbox_danger_score 시그널
# =============================================================================

class TestSandboxScoreSignal:
    """PROMPT-6: sandbox_score 시그널 — sandbox_danger_score (+30)."""

    _CLEAN_URL = "https://test-signal-only.example.com/path"

    def test_none_sandbox_score_no_signal(self):
        """TC-NF-10: sandbox_score=None 이면 시그널 없음."""
        result = score_url(self._CLEAN_URL, sandbox_score=None)
        assert "sandbox_danger_score" not in result.triggered

    def test_sandbox_score_below_70_no_signal(self):
        """TC-NF-11: sandbox_score=69 는 임계값 미만 — 시그널 없음."""
        result = score_url(self._CLEAN_URL, sandbox_score=69)
        assert "sandbox_danger_score" not in result.triggered

    def test_sandbox_score_exactly_70_triggers(self):
        """TC-NF-12: sandbox_score=70 정확히 임계값 — 시그널 발화 (+30)."""
        result = score_url(self._CLEAN_URL, sandbox_score=70)
        assert "sandbox_danger_score" in result.triggered
        assert result.triggered["sandbox_danger_score"] == 30

    def test_sandbox_score_100_triggers(self):
        """TC-NF-13: sandbox_score=100 → 시그널 발화 (+30)."""
        result = score_url(self._CLEAN_URL, sandbox_score=100)
        assert "sandbox_danger_score" in result.triggered


# =============================================================================
# TC-NF-14 ~ TC-NF-17 : PROMPT-7 — analysis_history_service
# =============================================================================

@pytest.fixture
def history_db(tmp_path):
    """analysis_history 테이블이 있는 격리 SQLite DB."""
    db_path = tmp_path / "test_history.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        CREATE TABLE analysis_history (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            url_hash          TEXT    NOT NULL,
            url               TEXT    NOT NULL,
            registered_domain TEXT,
            verdict           TEXT    NOT NULL CHECK(verdict IN ('danger','suspicious','safe')),
            triggered_signals TEXT,
            heuristic_score   INTEGER,
            prior_vote_danger INTEGER DEFAULT 0,
            prior_vote_safe   INTEGER DEFAULT 0,
            response_time_ms  INTEGER,
            device_uuid       TEXT,
            analyzed_at       TEXT    NOT NULL
        )
    """)
    conn.commit()
    conn.close()
    return str(db_path)


class TestAnalysisHistoryService:
    """PROMPT-7: save_analysis_history — DAT-06 분석 이력 저장."""

    def _count_rows(self, db_path: str) -> int:
        conn = sqlite3.connect(db_path)
        n = conn.execute("SELECT COUNT(*) FROM analysis_history").fetchone()[0]
        conn.close()
        return n

    def _fetch_last(self, db_path: str) -> dict:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM analysis_history ORDER BY id DESC LIMIT 1"
        ).fetchone()
        conn.close()
        return dict(row) if row else {}

    def test_full_save_persists_all_fields(self, history_db):
        """TC-NF-14: 모든 필드를 포함한 저장이 DB에 올바르게 반영된다."""
        from database.analysis_history_service import save_analysis_history

        with patch("database.db_init.DB_PATH") as mock_path:
            mock_path.__str__ = lambda _: history_db

            import database.db_init as db_init
            orig_path = db_init.DB_PATH
            db_init.DB_PATH = __import__("pathlib").Path(history_db)
            try:
                save_analysis_history(
                    url="http://phishing.example.com/fake",
                    verdict="danger",
                    registered_domain="example.com",
                    triggered_signals={"ip_in_url": 35, "dangerous_extension": 35},
                    heuristic_score=70,
                    prior_vote_danger=5,
                    prior_vote_safe=1,
                    response_time_ms=123,
                    device_uuid="test-uuid-1234",
                )
            finally:
                db_init.DB_PATH = orig_path

        row = self._fetch_last(history_db)
        assert row["verdict"] == "danger"
        assert row["heuristic_score"] == 70
        assert row["prior_vote_danger"] == 5
        assert row["prior_vote_safe"] == 1
        assert row["response_time_ms"] == 123
        assert row["device_uuid"] == "test-uuid-1234"
        assert row["registered_domain"] == "example.com"
        signals = json.loads(row["triggered_signals"])
        assert signals.get("ip_in_url") == 35

    def test_minimal_save_with_none_optionals(self, history_db):
        """TC-NF-15: 선택 필드 None 으로 저장해도 오류 없이 저장된다."""
        import database.db_init as db_init
        orig_path = db_init.DB_PATH
        db_init.DB_PATH = __import__("pathlib").Path(history_db)
        try:
            from database.analysis_history_service import save_analysis_history
            save_analysis_history(
                url="http://minimal.example",
                verdict="suspicious",
            )
        finally:
            db_init.DB_PATH = orig_path

        row = self._fetch_last(history_db)
        assert row["verdict"] == "suspicious"
        assert row["heuristic_score"] is None
        assert row["registered_domain"] is None
        assert json.loads(row["triggered_signals"]) == {}

    def test_save_does_not_raise_on_db_error(self):
        """TC-NF-16: DB 접근 실패 시 예외를 throw하지 않는다."""
        import database.db_init as db_init
        orig_path = db_init.DB_PATH
        db_init.DB_PATH = __import__("pathlib").Path("/nonexistent/path.db")
        try:
            from database.analysis_history_service import save_analysis_history
            # 예외 없이 실행되어야 한다
            save_analysis_history(url="http://fail.example", verdict="danger")
        finally:
            db_init.DB_PATH = orig_path

    def test_url_hash_is_sha256_of_url(self, history_db):
        """TC-NF-17: 저장된 url_hash 가 SHA-256(url) 이다."""
        url = "http://hash-check.example/page"
        expected_hash = hashlib.sha256(url.encode()).hexdigest()

        import database.db_init as db_init
        orig_path = db_init.DB_PATH
        db_init.DB_PATH = __import__("pathlib").Path(history_db)
        try:
            from database.analysis_history_service import save_analysis_history
            save_analysis_history(url=url, verdict="safe")
        finally:
            db_init.DB_PATH = orig_path

        row = self._fetch_last(history_db)
        assert row["url_hash"] == expected_hash


# =============================================================================
# TC-NF-18 : 설명 카드 EXPLANATION_DICT 키 존재 확인
# =============================================================================

class TestExplanationDictKeys:
    """PROMPT-5/6 신규 설명 카드가 EXPLANATION_DICT에 등록되어 있는지 확인."""

    def test_prior_danger_vote_high_card_exists(self):
        """TC-NF-18a: prior_danger_vote_high 카드가 EXPLANATION_DICT에 있다."""
        from services.explanation_service import EXPLANATION_DICT
        assert "prior_danger_vote_high" in EXPLANATION_DICT
        card = EXPLANATION_DICT["prior_danger_vote_high"]
        assert "icon" in card and "title" in card and "desc" in card

    def test_prior_danger_vote_low_card_exists(self):
        """TC-NF-18b: prior_danger_vote_low 카드가 EXPLANATION_DICT에 있다."""
        from services.explanation_service import EXPLANATION_DICT
        assert "prior_danger_vote_low" in EXPLANATION_DICT
        card = EXPLANATION_DICT["prior_danger_vote_low"]
        assert "icon" in card and "title" in card and "desc" in card

    def test_sandbox_danger_score_card_exists(self):
        """TC-NF-18c: sandbox_danger_score 카드가 EXPLANATION_DICT에 있다."""
        from services.explanation_service import EXPLANATION_DICT
        assert "sandbox_danger_score" in EXPLANATION_DICT
        card = EXPLANATION_DICT["sandbox_danger_score"]
        assert "icon" in card and "title" in card and "desc" in card

    def test_all_weight_keys_have_explanation_card(self):
        """TC-NF-18d: _WEIGHTS의 모든 키에 대응하는 카드가 EXPLANATION_DICT에 있다."""
        from services.heuristic_scorer import _WEIGHTS
        from services.explanation_service import EXPLANATION_DICT
        missing = [k for k in _WEIGHTS if k not in EXPLANATION_DICT]
        assert missing == [], f"카드 누락 시그널: {missing}"
