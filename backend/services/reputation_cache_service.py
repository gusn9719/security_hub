# =============================================================================
# backend/services/reputation_cache_service.py
# 역할: 도메인 평판 캐시 레이어 (domain_reputation_cache 테이블)
#
# 설계 원칙:
#   - domain_reputation_service 의 WHOIS/SSL 조회 결과를 TTL 기반으로 캐시.
#   - 캐시 히트 시 외부 조회 생략 → 지연시간 단축 + 레이트리밋 회피.
#   - 모든 예외는 graceful 처리 — 캐시 실패가 서비스를 중단하지 않음.
#   - SQLite BOOLEAN: Python bool ↔ INTEGER 0/1 변환 명시적 처리.
# =============================================================================

import logging
from datetime import datetime, timedelta, timezone

from database.db_init import get_ro_connection, get_rw_connection

logger = logging.getLogger(__name__)

# 캐시 유효 기간 (일). WHOIS 정보는 자주 바뀌지 않으므로 7일이면 충분.
CACHE_TTL_DAYS: int = 7


# =============================================================================
# 내부 헬퍼
# =============================================================================

def _row_to_dict(row) -> dict:
    """
    domain_reputation_cache 행을 analyze_domain_reputation() 반환 형식으로 변환.

    SQLite INTEGER(0/1) → Python bool, NULL ssl_valid → None 처리.
    """
    ssl_valid_raw = row["ssl_valid"]
    return {
        "domain_age_days":      row["domain_age_days"],
        "new_domain":           bool(row["new_domain"]),
        "ssl_valid":            None if ssl_valid_raw is None else bool(ssl_valid_raw),
        "ssl_issued_days":      row["ssl_issued_days"],
        "fresh_infrastructure": bool(row["fresh_infrastructure"]),
        "whois_no_record":      bool(row["whois_no_record"]),
        "skipped":              bool(row["skipped"]),
    }


def _result_to_params(registered_domain: str, result: dict, now: datetime, expires: datetime) -> tuple:
    """dict 결과를 INSERT 파라미터 튜플로 변환."""
    ssl_valid = result.get("ssl_valid")
    return (
        registered_domain,
        result.get("domain_age_days"),
        int(result.get("new_domain", False)),
        None if ssl_valid is None else int(ssl_valid),
        result.get("ssl_issued_days"),
        int(result.get("fresh_infrastructure", False)),
        int(result.get("whois_no_record", False)),
        int(result.get("skipped", False)),
        now.isoformat(),
        expires.isoformat(),
    )


# =============================================================================
# 공개 인터페이스
# =============================================================================

def get_cached_reputation(registered_domain: str) -> dict | None:
    """
    캐시에서 도메인 평판을 조회한다.

    만료된 레코드는 None 반환 (삭제하지 않음 — 다음 save 때 덮어씀).

    [registered_domain]: 등록 도메인 문자열 ('example.com')
    반환값: analyze_domain_reputation() 형식의 dict | None (캐시 미스 또는 만료)
    """
    if not registered_domain:
        return None
    try:
        with get_ro_connection() as conn:
            row = conn.execute(
                "SELECT * FROM domain_reputation_cache WHERE registered_domain = ?",
                (registered_domain,),
            ).fetchone()

        if row is None:
            logger.debug("[평판캐시] 미스 — %s", registered_domain)
            return None

        expires_at = datetime.fromisoformat(row["expires_at"])
        if datetime.now(timezone.utc) > expires_at:
            logger.debug("[평판캐시] 만료 — %s (expired=%s)", registered_domain, row["expires_at"])
            return None

        logger.info("[평판캐시] 히트 — %s (expires=%s)", registered_domain, row["expires_at"])
        return _row_to_dict(row)

    except Exception as e:
        logger.warning("[평판캐시] 조회 실패 (graceful): %s — %s", registered_domain, e)
        return None


def save_reputation(
    registered_domain: str,
    result: dict,
    ttl_days: int = CACHE_TTL_DAYS,
) -> None:
    """
    도메인 평판 결과를 캐시에 저장(또는 갱신)한다.

    INSERT OR REPLACE: 기존 레코드가 있으면 교체(id 변경됨 — 외부 참조 없으므로 무방).

    [registered_domain]: 등록 도메인 문자열
    [result]           : analyze_domain_reputation() 반환값
    [ttl_days]         : 캐시 유효 기간 (기본 7일)
    """
    if not registered_domain:
        return
    if result.get("skipped"):
        # IP 주소 등 스킵된 항목은 캐시하지 않음
        return

    now     = datetime.now(timezone.utc)
    expires = now + timedelta(days=ttl_days)

    try:
        with get_rw_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO domain_reputation_cache
                    (registered_domain,
                     domain_age_days, new_domain, ssl_valid, ssl_issued_days,
                     fresh_infrastructure, whois_no_record, skipped,
                     cached_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                _result_to_params(registered_domain, result, now, expires),
            )
            # with 블록 정상 종료 시 컨텍스트 매니저가 자동 commit
        logger.info(
            "[평판캐시] 저장 완료 — %s (TTL %dd, expires=%s)",
            registered_domain, ttl_days, expires.isoformat(),
        )
    except Exception as e:
        logger.warning("[평판캐시] 저장 실패 (graceful): %s — %s", registered_domain, e)


def purge_expired(batch_size: int = 500) -> int:
    """
    만료된 캐시 레코드를 일괄 삭제한다.

    FastAPI 시작 시 또는 주기적 유지보수 작업에서 호출 가능.
    서비스 중단 없이 graceful 처리.

    [batch_size]: 한 번에 삭제할 최대 레코드 수
    반환값: 삭제된 레코드 수 (실패 시 0)
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        with get_rw_connection() as conn:
            # SQLite 기본 빌드는 DELETE ... LIMIT 미지원 → 서브쿼리로 우회
            conn.execute(
                """
                DELETE FROM domain_reputation_cache
                WHERE id IN (
                    SELECT id FROM domain_reputation_cache
                    WHERE expires_at < ?
                    LIMIT ?
                )
                """,
                (now_iso, batch_size),
            )
            deleted = conn.execute("SELECT changes()").fetchone()[0]
            # with 블록 정상 종료 시 컨텍스트 매니저가 자동 commit
        if deleted:
            logger.info("[평판캐시] 만료 레코드 %d건 삭제 완료", deleted)
        return deleted
    except Exception as e:
        logger.warning("[평판캐시] 만료 레코드 삭제 실패 (graceful): %s", e)
        return 0
