# =============================================================================
# backend/scripts/load_ctas_csv.py
# 역할: C-TAS CSV 파일을 파싱하여 blacklist DB에 적재한다.
# 실행 방법:
#   cd backend
#   python scripts/load_ctas_csv.py --dir data/
# 변경 이력:
#   - Sprint 4: 최초 작성
# =============================================================================

import sys
import csv
import logging
import argparse
from pathlib import Path

# backend/ 폴더를 sys.path에 추가 — 모듈 임포트를 위해 필요
sys.path.insert(0, str(Path(__file__).parent.parent))

from database.db_init import get_rw_connection, init_db
from database.blacklist_service import (
    normalize_url,
    extract_domain,
    compute_url_hash,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# C-TAS smType → 카테고리 매핑 테이블
SMTYPE_MAP: dict[str, str] = {
    "공공기관": "공공기관",
    "택배": "택배",
    "금융": "금융",
    "기타": "기타",
}


def parse_ctas_row(row: dict) -> dict | None:
    """
    C-TAS CSV 한 행을 파싱하여 DB 삽입용 딕셔너리로 변환한다.

    [row]: csv.DictReader가 반환한 행 딕셔너리
    반환값: DB 삽입용 딕셔너리 | None (firstURL 누락 시 스킵)
    """
    raw_url = row.get("firstURL", "").strip()
    if not raw_url:
        return None  # 방어적 프로그래밍: URL 없는 행 스킵

    normalized = normalize_url(raw_url)
    domain = extract_domain(normalized)
    if not domain:
        return None  # 방어적 프로그래밍: 도메인 추출 실패 시 스킵

    url_hash = compute_url_hash(normalized)

    # smType → category 매핑 (알 수 없는 값은 "기타"로 처리)
    sm_type = row.get("smType", "").strip()
    category = SMTYPE_MAP.get(sm_type, "기타" if sm_type else None)

    return {
        "url_hash": url_hash,
        "url": normalized,
        "domain": domain,
        "source": "c-tas",
        "reported_at": row.get("datetime", "").strip(),
        "category": category,
        "raw_message": row.get("smsMsg", "").strip() or None,
    }


def load_csv_file(csv_path: Path) -> tuple[int, int]:
    """
    단일 CSV 파일을 파싱하고 blacklist DB에 upsert한다.

    충돌 처리: url_hash UNIQUE 충돌 시 INSERT OR IGNORE (덮어쓰지 않음)

    [csv_path]: C-TAS CSV 파일 경로
    반환값: (삽입 성공 건수, 스킵 건수) 튜플
    """
    inserted = 0
    skipped = 0

    # C-TAS CSV는 UTF-8-sig (BOM 포함) 인코딩
    with open(csv_path, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    logger.info(f"[로더] {csv_path.name} — 총 {len(rows)}행 파싱 시작")

    with get_rw_connection() as conn:
        for row in rows:
            record = parse_ctas_row(row)
            if record is None:
                skipped += 1
                continue

            try:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO blacklist
                        (url_hash, url, domain, source, reported_at, category, raw_message)
                    VALUES
                        (:url_hash, :url, :domain, :source, :reported_at, :category, :raw_message)
                    """,
                    record,
                )
                if conn.execute("SELECT changes()").fetchone()[0] > 0:
                    inserted += 1
                else:
                    skipped += 1  # url_hash 중복으로 무시됨
            except Exception as e:
                # 방어적 프로그래밍: 행 단위 에러는 로그 후 계속 진행
                logger.error(f"[로더] 삽입 실패 — {record['url']} | {e}")
                skipped += 1

        conn.commit()

    return inserted, skipped


def load_directory(data_dir: Path) -> None:
    """
    지정 디렉토리의 모든 CSV 파일을 순서대로 적재한다.

    [data_dir]: CSV 파일들이 위치한 디렉토리 경로
    """
    csv_files = sorted(data_dir.glob("*.csv"))

    if not csv_files:
        logger.warning(f"[로더] {data_dir} 에서 CSV 파일을 찾을 수 없습니다.")
        return

    logger.info(f"[로더] CSV 파일 {len(csv_files)}개 발견")

    total_inserted = 0
    total_skipped = 0

    for csv_path in csv_files:
        inserted, skipped = load_csv_file(csv_path)
        total_inserted += inserted
        total_skipped += skipped
        logger.info(
            f"[로더] {csv_path.name} 완료 — 삽입: {inserted}, 스킵: {skipped}"
        )

    logger.info(
        f"[로더] 전체 완료 — 총 삽입: {total_inserted}, 총 스킵: {total_skipped}"
    )


# =============================================================================
# 진입점
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="C-TAS CSV → blacklist DB 적재")
    parser.add_argument(
        "--dir",
        type=Path,
        default=Path(__file__).parent.parent / "data" / "blacklist",
        help="CSV 파일 디렉토리 경로 (기본값: backend/data/blacklist/)",
    )
    parser.add_argument(
        "--file",
        type=Path,
        default=None,
        help="단일 CSV 파일 경로 (--dir 대신 사용)",
    )
    args = parser.parse_args()

    # DB 초기화 (테이블 없으면 생성)
    init_db()

    if args.file:
        if not args.file.exists():
            logger.error(f"파일을 찾을 수 없습니다: {args.file}")
            sys.exit(1)
        inserted, skipped = load_csv_file(args.file)
        logger.info(f"완료 — 삽입: {inserted}, 스킵: {skipped}")
    else:
        if not args.dir.exists():
            logger.error(f"디렉토리를 찾을 수 없습니다: {args.dir}")
            sys.exit(1)
        load_directory(args.dir)