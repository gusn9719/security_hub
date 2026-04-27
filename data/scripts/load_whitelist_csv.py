# =============================================================================
# backend/scripts/load_whitelist_csv.py
# 역할: 화이트리스트 CSV 파싱 → whitelist DB 적재
# 실행:
#   $env:PYTHONPATH = "C:\dev\security_hub\backend"
#   python scripts/load_whitelist_csv.py               # 기본: data/whitelist/
#   python scripts/load_whitelist_csv.py --file data/whitelist/whitelist_v2.csv
# 변경 이력:
#   - Sprint 5A: 최초 작성
# =============================================================================

import sys
import csv
import logging
import argparse
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from database.db_init import get_rw_connection, init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


# =============================================================================
# 매핑 테이블 (CSV 한국어 값 → DB 영문 코드)
# =============================================================================

MATCH_MODE_MAP: dict[str, str] = {
    "정확 일치":          "exact",
    "서브도메인 포함":    "suffix",
    "TLD 패턴 (*. 전체)": "pattern",
}

RISK_LEVEL_MAP: dict[str, str] = {
    "일반":       "normal",
    "사칭 고위험": "high_risk",
}


# =============================================================================
# 행 파싱
# =============================================================================

def parse_whitelist_row(row: dict) -> dict | None:
    """
    CSV 한 행을 파싱하여 DB 삽입용 딕셔너리로 변환한다.

    [row]: csv.DictReader가 반환한 행 딕셔너리
    반환값: DB 삽입용 딕셔너리 | None (스킵 대상)
    """
    raw_domain = row.get("도메인 (domain)", "").strip().lower()
    if not raw_domain:
        return None

    raw_mode  = row.get("매칭 모드", "정확 일치").strip()
    raw_risk  = row.get("위험도", "일반").strip()
    category  = row.get("카테고리", "").strip()
    note      = row.get("비고 (note)", "").strip() or None

    match_mode = MATCH_MODE_MAP.get(raw_mode)
    if match_mode is None:
        logger.warning(f"[화이트리스트 로더] 알 수 없는 매칭 모드 '{raw_mode}' — {raw_domain} 스킵")
        return None

    risk_level = RISK_LEVEL_MAP.get(raw_risk, "normal")

    # 패턴 항목: DB에 '.go.kr' 형태로 저장 (앞에 . 붙임)
    if match_mode == "pattern" and not raw_domain.startswith("."):
        domain = "." + raw_domain
    else:
        domain = raw_domain

    return {
        "domain":     domain,
        "category":   category,
        "match_mode": match_mode,
        "risk_level": risk_level,
        "note":       note,
        "source":     "csv",
        "added_at":   datetime.now(timezone.utc).isoformat(),
    }


# =============================================================================
# CSV 파일 적재
# =============================================================================

def load_csv_file(csv_path: Path) -> tuple[int, int, int]:
    """
    단일 CSV 파일을 파싱하고 whitelist DB에 upsert한다.

    충돌 처리: domain UNIQUE 충돌 시 match_mode / risk_level / note 갱신 (덮어쓰기)

    반환값: (삽입 건수, 갱신 건수, 스킵 건수)
    """
    inserted = updated = skipped = 0

    with open(csv_path, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    logger.info(f"[로더] {csv_path.name} — 총 {len(rows)}행 파싱 시작")

    with get_rw_connection() as conn:
        for row in rows:
            record = parse_whitelist_row(row)
            if record is None:
                skipped += 1
                continue

            try:
                # 기존 행이 있으면 match_mode/risk_level/note 갱신
                existing = conn.execute(
                    "SELECT id FROM whitelist WHERE domain = ?",
                    (record["domain"],),
                ).fetchone()

                if existing:
                    conn.execute(
                        """
                        UPDATE whitelist
                        SET category   = :category,
                            match_mode = :match_mode,
                            risk_level = :risk_level,
                            note       = :note,
                            source     = :source,
                            added_at   = :added_at
                        WHERE domain = :domain
                        """,
                        record,
                    )
                    updated += 1
                else:
                    conn.execute(
                        """
                        INSERT INTO whitelist
                            (domain, category, match_mode, risk_level, note, source, added_at)
                        VALUES
                            (:domain, :category, :match_mode, :risk_level, :note, :source, :added_at)
                        """,
                        record,
                    )
                    inserted += 1

            except Exception as e:
                logger.error(f"[로더] 삽입 실패 — {record['domain']} | {e}")
                skipped += 1

        conn.commit()

    return inserted, updated, skipped


def load_directory(data_dir: Path) -> None:
    """지정 디렉토리의 모든 CSV 파일을 순서대로 적재한다."""
    csv_files = sorted(data_dir.glob("*.csv"))
    if not csv_files:
        logger.warning(f"[로더] {data_dir} 에서 CSV 파일을 찾을 수 없습니다.")
        return

    total_i = total_u = total_s = 0
    for csv_path in csv_files:
        i, u, s = load_csv_file(csv_path)
        total_i += i; total_u += u; total_s += s
        logger.info(f"[로더] {csv_path.name} — 신규: {i}, 갱신: {u}, 스킵: {s}")

    logger.info(f"[로더] 전체 완료 — 신규: {total_i}, 갱신: {total_u}, 스킵: {total_s}")


# =============================================================================
# 진입점
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="화이트리스트 CSV → whitelist DB 적재")
    parser.add_argument(
        "--dir",
        type=Path,
        default=Path(__file__).parent.parent / "data" / "whitelist",
        help="CSV 디렉토리 경로 (기본값: backend/data/whitelist/)",
    )
    parser.add_argument(
        "--file",
        type=Path,
        default=None,
        help="단일 CSV 파일 경로 (--dir 대신 사용)",
    )
    args = parser.parse_args()

    init_db()

    if args.file:
        if not args.file.exists():
            logger.error(f"파일을 찾을 수 없습니다: {args.file}")
            sys.exit(1)
        i, u, s = load_csv_file(args.file)
        logger.info(f"완료 — 신규: {i}, 갱신: {u}, 스킵: {s}")
    else:
        if not args.dir.exists():
            logger.error(f"디렉토리를 찾을 수 없습니다: {args.dir}")
            sys.exit(1)
        load_directory(args.dir)
