# =============================================================================
# data/scripts/migrate_db.py
# 역할: DB 마이그레이션
#
# 실행 방법 (security_hub/ 루트에서):
#   python data/scripts/migrate_db.py
#
# 수행 작업 (v0513 DC-30/DC-33/DAT-06):
#   1. sandbox_results DROP & RECREATE (DC-33: session_id PK, mode/domain 컬럼 추가)
#   2. url_votes DROP & RECREATE (DC-30: vote 'danger', device_uuid/domain 컬럼 추가)
#   3. init_db() 호출 → 신규 테이블/컬럼 생성 (analysis_history 포함)
#   4. blacklist.registered_domain NULL 행 역채움
#   5. whitelist.registered_domain NULL 행 역채움
#   6. PRAGMA table_info 검증 출력
# =============================================================================

import sys
import logging
from pathlib import Path

# backend/ 폴더를 sys.path 에 추가 — database.* 임포트를 위해 필요
_BACKEND = Path(__file__).resolve().parents[2] / "backend"
sys.path.insert(0, str(_BACKEND))

from database.db_init import get_rw_connection, init_db  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# tldextract 가용 여부 확인
try:
    import tldextract as _tldextract
    _TLDEXTRACT_AVAILABLE = True
except ImportError:
    _TLDEXTRACT_AVAILABLE = False
    logger.error("[마이그레이션] tldextract 미설치 — pip install tldextract 후 재실행")
    sys.exit(1)


def _compute_registered_domain(domain: str) -> str | None:
    """
    도메인 문자열에서 등록 도메인(registered_domain)을 추출한다.

    예: 'login.naver.com' → 'naver.com'
        'evil.sub.example.xyz' → 'example.xyz'
        '.go.kr' → None  (패턴 항목은 등록 도메인 없음)
    """
    if not domain or domain.startswith("."):
        return None
    extracted = _tldextract.extract(domain)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return None


# =============================================================================
# DC-33: sandbox_results DROP & RECREATE
# =============================================================================

def _migrate_sandbox_results(conn) -> None:
    """
    sandbox_results 테이블을 DC-33 스키마로 재생성한다.
    운영 데이터 없음 — 무조건 DROP & RECREATE.
    """
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='sandbox_results'"
    ).fetchall()}

    if "sandbox_results" in tables:
        conn.execute("DROP TABLE sandbox_results")
        logger.info("[마이그레이션] sandbox_results 테이블 삭제 완료")
    else:
        logger.info("[마이그레이션] sandbox_results 테이블 없음 — 신규 생성")


# =============================================================================
# DC-30: url_votes DROP & RECREATE
# =============================================================================

def _migrate_url_votes(conn) -> None:
    """
    url_votes 테이블을 DC-30 스키마로 재생성한다.
    vote CHECK 값 변경('dangerous' → 'danger')은 ALTER 불가 — DROP & RECREATE.
    """
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='url_votes'"
    ).fetchall()}

    if "url_votes" in tables:
        conn.execute("DROP TABLE url_votes")
        logger.info("[마이그레이션] url_votes 테이블 삭제 완료")
    else:
        logger.info("[마이그레이션] url_votes 테이블 없음 — 신규 생성")


# =============================================================================
# 기존 마이그레이션: registered_domain 역채움
# =============================================================================

def _backfill_blacklist(conn) -> tuple[int, int]:
    """
    blacklist 테이블에서 registered_domain 이 NULL 인 행을 역채움한다.

    반환값: (업데이트 성공 건수, 스킵 건수)
    """
    rows = conn.execute(
        "SELECT id, domain FROM blacklist WHERE registered_domain IS NULL"
    ).fetchall()

    if not rows:
        logger.info("[마이그레이션] blacklist: registered_domain NULL 행 없음 — 스킵")
        return 0, 0

    logger.info(f"[마이그레이션] blacklist: {len(rows)}행 역채움 시작")
    updated = 0
    skipped = 0

    for row in rows:
        reg_domain = _compute_registered_domain(row["domain"])
        if reg_domain:
            conn.execute(
                "UPDATE blacklist SET registered_domain = ? WHERE id = ?",
                (reg_domain, row["id"]),
            )
            updated += 1
        else:
            skipped += 1

    logger.info(
        f"[마이그레이션] blacklist 완료 — 업데이트: {updated}, 스킵: {skipped}"
    )
    return updated, skipped


def _backfill_whitelist(conn) -> tuple[int, int]:
    """
    whitelist 테이블에서 registered_domain 이 NULL 인 행을 역채움한다.
    match_mode='pattern' 항목('.go.kr' 형태)은 건너뛴다.

    반환값: (업데이트 성공 건수, 스킵 건수)
    """
    rows = conn.execute(
        """
        SELECT id, domain, match_mode
        FROM whitelist
        WHERE registered_domain IS NULL
          AND match_mode != 'pattern'
        """
    ).fetchall()

    if not rows:
        logger.info("[마이그레이션] whitelist: registered_domain NULL 행 없음 — 스킵")
        return 0, 0

    logger.info(f"[마이그레이션] whitelist: {len(rows)}행 역채움 시작")
    updated = 0
    skipped = 0

    for row in rows:
        reg_domain = _compute_registered_domain(row["domain"])
        if reg_domain:
            conn.execute(
                "UPDATE whitelist SET registered_domain = ? WHERE id = ?",
                (reg_domain, row["id"]),
            )
            updated += 1
        else:
            skipped += 1

    logger.info(
        f"[마이그레이션] whitelist 완료 — 업데이트: {updated}, 스킵: {skipped}"
    )
    return updated, skipped


# =============================================================================
# P0-4: 구버전 화이트리스트 시드 1회성 제거
# =============================================================================

def _remove_old_whitelist_seeds(conn) -> int:
    """
    v1.0 이전 구버전 시드(source='manual' 또는 'pattern') 행을 1회 제거한다.

    원래 init_db() 안에서 매 lifespan 마다 실행되던 코드를 옮긴 것이다.
    매 재시작마다 운영용 수동 추가 화이트리스트까지 지워질 수 있어 위험.
    본 함수는 migrate_db.py 안에서만 호출되며, 정리할 행이 없으면 0 을
    반환하므로 반복 실행해도 안전(idempotent).

    반환값: 삭제된 행 수
    """
    cnt = conn.execute(
        "SELECT COUNT(*) FROM whitelist WHERE source IN ('manual', 'pattern')"
    ).fetchone()[0]
    if cnt == 0:
        logger.info("[마이그레이션] 구버전 화이트리스트 시드 없음 — 스킵")
        return 0
    conn.execute("DELETE FROM whitelist WHERE source IN ('manual', 'pattern')")
    logger.info(
        "[마이그레이션] 구버전 화이트리스트 시드 %d건 제거 — "
        "load_whitelist_csv.py 로 재적재 필요",
        cnt,
    )
    return cnt


# =============================================================================
# 검증
# =============================================================================

def _verify_schema(conn) -> None:
    """PRAGMA table_info로 변경된 테이블 컬럼을 출력해 검증한다."""
    targets = ["sandbox_results", "url_votes", "analysis_history", "users"]
    logger.info("=" * 60)
    logger.info("[검증] 테이블 스키마 확인")
    for table in targets:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        if not rows:
            logger.warning("[검증] %s: 테이블 없음!", table)
            continue
        cols = [f"{r['name']} ({r['type']})" for r in rows]
        logger.info("[검증] %s 컬럼(%d): %s", table, len(cols), ", ".join(cols))
    logger.info("=" * 60)


# =============================================================================
# 메인
# =============================================================================

def run_migration() -> None:
    """전체 마이그레이션을 실행한다."""
    logger.info("=" * 60)
    logger.info("[마이그레이션] 시작 (v0513 DC-30/DC-33/DAT-06)")

    # 1. sandbox_results / url_votes DROP (init_db가 새 스키마로 재생성)
    logger.info("[마이그레이션] 1단계: sandbox_results / url_votes DROP")
    with get_rw_connection() as conn:
        _migrate_sandbox_results(conn)
        _migrate_url_votes(conn)
        conn.commit()

    # 2. 신규 테이블/컬럼 생성 (analysis_history 포함)
    logger.info("[마이그레이션] 2단계: init_db() — 스키마 갱신")
    init_db()

    # 3. 역채움 + 구버전 시드 정리
    with get_rw_connection() as conn:
        logger.info("[마이그레이션] 3단계: blacklist.registered_domain 역채움")
        bl_upd, bl_skip = _backfill_blacklist(conn)

        logger.info("[마이그레이션] 4단계: whitelist.registered_domain 역채움")
        wl_upd, wl_skip = _backfill_whitelist(conn)

        logger.info("[마이그레이션] 5단계: 구버전 화이트리스트 시드 1회 제거 (P0-4)")
        _remove_old_whitelist_seeds(conn)

        conn.commit()

    # 4. 스키마 검증 출력
    with get_rw_connection() as conn:
        _verify_schema(conn)

    logger.info("=" * 60)
    logger.info(
        "[마이그레이션] 완료 — "
        f"blacklist 업데이트: {bl_upd} / 스킵: {bl_skip} | "
        f"whitelist 업데이트: {wl_upd} / 스킵: {wl_skip}"
    )
    logger.info("=" * 60)


if __name__ == "__main__":
    run_migration()
