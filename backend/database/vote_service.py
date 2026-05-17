# =============================================================================
# backend/database/vote_service.py
# 역할: url_votes 테이블 읽기/쓰기. 7-A 직접 탐방 세션 종료 후 사용자 피드백 수집.
#
# session_id UNIQUE 제약으로 세션당 1회 투표만 허용한다.
# 중복 INSERT는 OR IGNORE로 조용히 무시한다.
# DC-30: vote 값 'danger'로 통일. device_uuid 필드 추가.
# =============================================================================

import datetime
import hashlib
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def save_vote(url: str, session_id: str, vote: str, device_uuid: str = "") -> bool:
    """
    사용자 투표(safe/danger)를 url_votes에 저장한다.

    동일 session_id로 이미 투표된 경우 INSERT OR IGNORE로 조용히 무시하고 False를 반환한다.

    Args:
        url:         투표 대상 URL
        session_id:  7-A 탐방 세션 ID (container_id) — UNIQUE 제약
        vote:        "safe" 또는 "danger"
        device_uuid: 기기 식별 UUID (NF-30)

    Returns:
        True: 신규 저장 성공 / False: 중복 또는 오류
    """
    if vote not in ("safe", "danger"):
        logger.warning("[투표] 유효하지 않은 vote 값: %s", vote)
        return False

    url_hash = hashlib.sha256(url.encode()).hexdigest()
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat()

    # domain/registered_domain 추출 — idx_votes_device_domain UNIQUE 제약 활성화에 필요
    try:
        from services.url_validator import get_registered_domain
        domain = urlparse(url).hostname or ""
        registered_domain = get_registered_domain(url)
    except Exception:
        domain = ""
        registered_domain = None

    try:
        from database.db_init import get_rw_connection
        with get_rw_connection() as conn:
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO url_votes
                    (url_hash, url, vote, voted_at, session_id, device_uuid,
                     domain, registered_domain)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (url_hash, url, vote, now, session_id, device_uuid,
                 domain, registered_domain),
            )
            saved = cursor.rowcount > 0
            if not saved:
                logger.info("[투표] 중복 투표 무시: session_id=%s", session_id)
            return saved
    except Exception as e:
        logger.warning("[투표] 저장 실패: %s", e)
        return False


def get_vote_counts(url: str) -> dict:
    """
    URL에 대한 safe/danger 투표 수를 반환한다.

    Args:
        url: 집계 대상 URL

    Returns:
        {"safe": int, "danger": int, "total": int}
    """
    url_hash = hashlib.sha256(url.encode()).hexdigest()
    try:
        from database.db_init import get_ro_connection
        with get_ro_connection() as conn:
            rows = conn.execute(
                "SELECT vote, COUNT(*) AS cnt FROM url_votes WHERE url_hash = ? GROUP BY vote",
                (url_hash,),
            ).fetchall()
            counts = {"safe": 0, "danger": 0}
            for row in rows:
                if row["vote"] in counts:
                    counts[row["vote"]] = row["cnt"]
            counts["total"] = counts["safe"] + counts["danger"]
            return counts
    except Exception as e:
        logger.warning("[투표] 집계 실패: %s", e)
        return {"safe": 0, "danger": 0, "total": 0}
