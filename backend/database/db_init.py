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
        conn.execute("""
            CREATE TABLE IF NOT EXISTS blacklist (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                url_hash    TEXT    NOT NULL UNIQUE,
                url         TEXT    NOT NULL,
                domain      TEXT    NOT NULL,
                source      TEXT    NOT NULL,
                reported_at TEXT    NOT NULL,
                category    TEXT,
                raw_message TEXT
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_domain
            ON blacklist (domain)
        """)

        # ── 화이트리스트 테이블 ──────────────────────────────────────────
        conn.execute("""
            CREATE TABLE IF NOT EXISTS whitelist (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                domain      TEXT    NOT NULL UNIQUE,
                category    TEXT    NOT NULL,
                match_mode  TEXT    NOT NULL DEFAULT 'exact',
                risk_level  TEXT    NOT NULL DEFAULT 'normal',
                note        TEXT,
                source      TEXT    NOT NULL DEFAULT 'manual',
                added_at    TEXT    NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_whitelist_domain
            ON whitelist (domain)
        """)

        # ── migration: 구버전 whitelist 테이블에 컬럼 추가 ───────────────
        existing_cols = {
            r[1] for r in conn.execute("PRAGMA table_info(whitelist)").fetchall()
        }
        migrations = [
            ("match_mode", "TEXT NOT NULL DEFAULT 'exact'"),
            ("risk_level",  "TEXT NOT NULL DEFAULT 'normal'"),
            ("note",        "TEXT"),
        ]
        for col, definition in migrations:
            if col not in existing_cols:
                conn.execute(f"ALTER TABLE whitelist ADD COLUMN {col} {definition}")
                logger.info(f"[DB] whitelist.{col} 컬럼 추가 완료")

        # 구버전 시드(15건, match_mode 없음)가 남아있으면 제거
        old_seed_count = conn.execute(
            "SELECT COUNT(*) FROM whitelist WHERE source = 'manual' OR source = 'pattern'"
        ).fetchone()[0]
        if old_seed_count > 0:
            conn.execute(
                "DELETE FROM whitelist WHERE source IN ('manual', 'pattern')"
            )
            logger.info(f"[DB] 구버전 시드 {old_seed_count}건 제거 완료 — CSV 로더로 재적재 필요")

        conn.commit()
    logger.info(f"[DB] 초기화 완료 — {DB_PATH}")
