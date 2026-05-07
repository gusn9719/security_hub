# =============================================================================
# data/scripts/migrate_db.py
# 역할: DB 마이그레이션 — registered_domain 컬럼 역채움(backfill)
#
# 실행 방법 (security_hub/ 루트에서):
#   python data/scripts/migrate_db.py
#
# 수행 작업:
#   1. init_db() 호출 → 신규 컬럼/테이블 없으면 자동 생성
#   2. blacklist.registered_domain NULL 행 역채움
#   3. whitelist.registered_domain NULL 행 역채움 (pattern 모드 제외)
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
            # IP 주소, 빈 도메인 등은 NULL 유지
            skipped += 1

    logger.info(
        f"[마이그레이션] blacklist 완료 — 업데이트: {updated}, 스킵: {skipped}"
    )
    return updated, skipped


def _backfill_whitelist(conn) -> tuple[int, int]:
    """
    whitelist 테이블에서 registered_domain 이 NULL 인 행을 역채움한다.
    match_mode='pattern' 항목('.go.kr' 형태)은 등록 도메인이 없으므로 건너뛴다.

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


def run_migration() -> None:
    """전체 마이그레이션을 실행한다."""
    logger.info("=" * 60)
    logger.info("[마이그레이션] 시작")

    # 1. 신규 테이블/컬럼 생성
    logger.info("[마이그레이션] 1단계: init_db() — 스키마 갱신")
    init_db()

    # 2. 역채움
    with get_rw_connection() as conn:
        logger.info("[마이그레이션] 2단계: blacklist.registered_domain 역채움")
        bl_upd, bl_skip = _backfill_blacklist(conn)

        logger.info("[마이그레이션] 3단계: whitelist.registered_domain 역채움")
        wl_upd, wl_skip = _backfill_whitelist(conn)

        conn.commit()

    logger.info("=" * 60)
    logger.info(
        f"[마이그레이션] 완료 — "
        f"blacklist 업데이트: {bl_upd} / 스킵: {bl_skip} | "
        f"whitelist 업데이트: {wl_upd} / 스킵: {wl_skip}"
    )
    logger.info("=" * 60)


if __name__ == "__main__":
    run_migration()
