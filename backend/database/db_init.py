import sqlite3
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

DB_PATH = Path(__file__).resolve().parent.parent / "security_hub.db"


def get_ro_connection() -> sqlite3.Connection:
    """FastAPI 앱 런타임 전용 읽기 전용 연결.

    URI mode=ro 로 열어 실수로 INSERT/UPDATE/DELETE 가 실행되면
    즉시 OperationalError 를 발생시킨다.
    DB 파일이 존재하지 않으면 OperationalError — init_db() 가 먼저 실행되어야 한다.
    """
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def get_rw_connection() -> sqlite3.Connection:
    """적재 스크립트 / init_db 전용 WAL 쓰기 연결.

    WAL 모드: 쓰기 중에도 읽기 연결이 블로킹되지 않는다.
    synchronous=NORMAL: WAL 에서 안전하고 성능 좋은 기본값.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db() -> None:
    with get_rw_connection() as conn:
        # ── 블랙리스트 테이블 ────────────────────────────────────────────
        # registered_domain: 신규 설치 시 처음부터 포함, 기존 DB 는 migration 에서 추가
        conn.execute("""
            CREATE TABLE IF NOT EXISTS blacklist (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                url_hash          TEXT    NOT NULL UNIQUE,
                url               TEXT    NOT NULL,
                domain            TEXT    NOT NULL,
                registered_domain TEXT,
                source            TEXT    NOT NULL,
                reported_at       TEXT    NOT NULL,
                category          TEXT,
                raw_message       TEXT
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_blacklist_domain
            ON blacklist (domain)
        """)

        # ── 화이트리스트 테이블 ──────────────────────────────────────────
        conn.execute("""
            CREATE TABLE IF NOT EXISTS whitelist (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                domain            TEXT    NOT NULL UNIQUE,
                registered_domain TEXT,
                category          TEXT    NOT NULL,
                match_mode        TEXT    NOT NULL DEFAULT 'exact',
                risk_level        TEXT    NOT NULL DEFAULT 'normal',
                note              TEXT,
                source            TEXT    NOT NULL DEFAULT 'manual',
                added_at          TEXT    NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_whitelist_domain
            ON whitelist (domain)
        """)

        # ── 도메인 평판 캐시 테이블 ──────────────────────────────────────
        # domain_reputation_service 의 WHOIS/SSL 결과를 TTL 기반으로 캐시한다.
        # expires_at 이 현재 시각보다 크면 캐시 유효. 만료된 레코드는 REPLACE.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS domain_reputation_cache (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                registered_domain    TEXT    NOT NULL UNIQUE,
                domain_age_days      INTEGER,
                new_domain           INTEGER NOT NULL DEFAULT 0,
                ssl_valid            INTEGER,
                ssl_issued_days      INTEGER,
                fresh_infrastructure INTEGER NOT NULL DEFAULT 0,
                whois_no_record      INTEGER NOT NULL DEFAULT 0,
                skipped              INTEGER NOT NULL DEFAULT 0,
                cached_at            TEXT    NOT NULL,
                expires_at           TEXT    NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_rep_cache_domain
            ON domain_reputation_cache (registered_domain)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_rep_cache_expires
            ON domain_reputation_cache (expires_at)
        """)

        # ── URL 투표 테이블 ──────────────────────────────────────────────
        # 사용자 피드백 (안전/위험) 수집용. 향후 누적 데이터로 재학습 가능.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS url_votes (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                url_hash TEXT    NOT NULL,
                url      TEXT    NOT NULL,
                vote     TEXT    NOT NULL CHECK(vote IN ('safe', 'dangerous')),
                voted_at TEXT    NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_votes_url_hash
            ON url_votes (url_hash)
        """)

        # ── 샌드박스 결과 테이블 ─────────────────────────────────────────
        # 7-B Browserless/Playwright 자동 분석 결과 저장.
        # findings: JSON 배열 문자열 (예: '["팝업 감지", "리다이렉트 2회"]')
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sandbox_results (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                url_hash        TEXT    NOT NULL UNIQUE,
                url             TEXT    NOT NULL,
                findings        TEXT,
                screenshot_path TEXT,
                analyzed_at     TEXT    NOT NULL,
                expires_at      TEXT    NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_sandbox_url_hash
            ON sandbox_results (url_hash)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_sandbox_expires
            ON sandbox_results (expires_at)
        """)

        # ── sandbox_results: 7-B 자동탐지 신규 컬럼 마이그레이션 ────────
        sr_cols = {r[1] for r in conn.execute("PRAGMA table_info(sandbox_results)").fetchall()}
        sr_migrations = [
            ("session_id",     "TEXT"),
            ("sandbox_score",  "INTEGER DEFAULT 0"),
            ("summary",        "TEXT"),
            ("screenshots",    "TEXT"),
            ("final_url",      "TEXT"),
            ("redirect_count", "INTEGER DEFAULT 0"),
            ("error",          "TEXT"),
        ]
        for col, definition in sr_migrations:
            if col not in sr_cols:
                conn.execute(f"ALTER TABLE sandbox_results ADD COLUMN {col} {definition}")
                logger.info(f"[DB] sandbox_results.{col} 컬럼 추가 완료")

        # ── migration: 기존 테이블에 누락 컬럼 추가 ─────────────────────
        # 주의: registered_domain 인덱스는 컬럼 존재 확인 후 생성해야 한다.
        # CREATE INDEX IF NOT EXISTS 는 인덱스명 충돌만 무시하고,
        # 컬럼 미존재 시에는 OperationalError 를 발생시킨다.

        # (1) blacklist.registered_domain
        bl_cols = {r[1] for r in conn.execute("PRAGMA table_info(blacklist)").fetchall()}
        if "registered_domain" not in bl_cols:
            conn.execute("ALTER TABLE blacklist ADD COLUMN registered_domain TEXT")
            logger.info("[DB] blacklist.registered_domain 컬럼 추가 완료")

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_blacklist_registered_domain
            ON blacklist (registered_domain)
        """)

        # (2) whitelist: match_mode / risk_level / note / registered_domain
        wl_cols = {r[1] for r in conn.execute("PRAGMA table_info(whitelist)").fetchall()}
        wl_migrations = [
            ("match_mode",        "TEXT NOT NULL DEFAULT 'exact'"),
            ("risk_level",        "TEXT NOT NULL DEFAULT 'normal'"),
            ("note",              "TEXT"),
            ("registered_domain", "TEXT"),
        ]
        for col, definition in wl_migrations:
            if col not in wl_cols:
                conn.execute(f"ALTER TABLE whitelist ADD COLUMN {col} {definition}")
                logger.info(f"[DB] whitelist.{col} 컬럼 추가 완료")

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_whitelist_registered_domain
            ON whitelist (registered_domain)
        """)

        # 구버전 시드(15건, match_mode 없음)가 남아있으면 제거
        old_seed_count = conn.execute(
            "SELECT COUNT(*) FROM whitelist WHERE source = 'manual' OR source = 'pattern'"
        ).fetchone()[0]
        if old_seed_count > 0:
            conn.execute(
                "DELETE FROM whitelist WHERE source IN ('manual', 'pattern')"
            )
            logger.info(f"[DB] 구버전 시드 {old_seed_count}건 제거 완료 — CSV 로더로 재적재 필요")

    logger.info(f"[DB] 초기화 완료 — {DB_PATH}")
