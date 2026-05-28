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
    busy_timeout=5000: 동시 쓰기 충돌 시 최대 5초 대기 후 실패.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
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
        # 사용자 피드백 (안전/위험) 수집용. DC-30: vote 값 'danger'로 통일.
        # UNIQUE(device_uuid, registered_domain): 기기당 도메인 1회 투표 제한.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS url_votes (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                url_hash          TEXT    NOT NULL,
                url               TEXT    NOT NULL,
                vote              TEXT    NOT NULL CHECK(vote IN ('safe', 'danger', 'spam', 'unsure')),
                voted_at          TEXT    NOT NULL,
                session_id        TEXT,
                device_uuid       TEXT    NOT NULL DEFAULT '',
                domain            TEXT    NOT NULL DEFAULT '',
                registered_domain TEXT
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_votes_url_hash
            ON url_votes (url_hash)
        """)
        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_votes_session_id
            ON url_votes (session_id)
            WHERE session_id IS NOT NULL
        """)
        # 어그로 방어 Layer 1 — 의미 있는 투표(safe/danger/spam)만 슬롯 점유.
        # v0527: WHERE 조건에 `vote IN ('safe','danger','spam')` 추가.
        # 변경 사유: 'unsure' 투표가 향후 진짜 의견(safe/danger/spam)을 막지
        #            못하도록 부분 UNIQUE 적용. (vote_service.py 는 'unsure' 를
        #            애초에 INSERT 하지 않지만, 직접 SQL INSERT 등 우회 경로
        #            대비 DB 차원에서도 동일 정책 강제.)
        # 마이그레이션: 기존 인덱스를 DROP 후 재생성. WHERE 절 변경은
        # CREATE INDEX IF NOT EXISTS 가 감지하지 못하므로 명시 DROP 필요.
        conn.execute("DROP INDEX IF EXISTS idx_votes_device_domain")
        conn.execute("""
            CREATE UNIQUE INDEX idx_votes_device_domain
            ON url_votes (device_uuid, registered_domain)
            WHERE device_uuid != ''
              AND registered_domain IS NOT NULL
              AND vote IN ('safe', 'danger', 'spam')
        """)

        # ── 샌드박스 결과 테이블 ─────────────────────────────────────────
        # DC-33: session_id를 PK로 사용. url_hash UNIQUE 제거.
        # mode: '7a'(직접탐방) / '7b'(AI자동탐지). visited_urls: CDP 내비게이션 JSON 배열.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sandbox_results (
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
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_sandbox_url_hash
            ON sandbox_results (url_hash)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_sandbox_expires
            ON sandbox_results (expires_at)
        """)

        # ── 분석 이력 테이블 ─────────────────────────────────────────────
        # DAT-06: /analyze 호출 결과를 BackgroundTasks로 비동기 저장.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analysis_history (
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
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_history_url_hash
            ON analysis_history (url_hash)
        """)

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
