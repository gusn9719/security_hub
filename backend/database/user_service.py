# =============================================================================
# backend/database/user_service.py
# 역할: users 테이블 읽기/쓰기. 카카오 소셜 로그인으로 식별된 자연인 계정 관리.
#
# AUTH-01 (v0530 신설):
#   - 익명 device_uuid(NF-30) 위에 인증 레이어를 얹는다. UUID 100 개와 가입
#     100 개의 비용 비대칭(임시메일·번호와 달리 카카오 계정은 자연인 본인
#     인증을 거친다) 을 활용해 어그로 방어 Layer 5 를 신설한다.
#   - 가입자 투표는 휴리스틱 시그널에서 익명 표 3~4 명분 권위로 환산된다
#     (heuristic_scorer 의 prior_*_vote 조건 참고).
# =============================================================================

import datetime
import logging
import sqlite3

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat()


def upsert_by_kakao_id(
    kakao_id: str,
    nickname: str | None = None,
    email: str | None = None,
) -> int | None:
    """
    카카오 회원 고유번호로 사용자 레코드를 upsert 한다.

    동작:
        - 신규: INSERT 후 새 id 반환. created_at / last_login_at 모두 현재 시각.
        - 기존: nickname / email / last_login_at 갱신. 기존 id 반환.

    Args:
        kakao_id: 카카오 회원 고유번호 (kapi.kakao.com /v2/user/me 의 id).
                  숫자지만 문자열로 저장 — 64bit 범위 안전.
        nickname: 카카오 프로필 닉네임 (필수 동의). None 허용은 호출자 방어용.
        email:    카카오 이메일 (선택 동의). 사용자가 거부했으면 None.

    Returns:
        users.id  (정상)
        None      (DB 오류)
    """
    if not kakao_id:
        logger.warning("[user] upsert: kakao_id 비어있음")
        return None

    now = _now_iso()
    try:
        from database.db_init import get_rw_connection
        with get_rw_connection() as conn:
            row = conn.execute(
                "SELECT id FROM users WHERE kakao_id = ?",
                (kakao_id,),
            ).fetchone()

            if row is None:
                cursor = conn.execute(
                    """
                    INSERT INTO users (kakao_id, nickname, email, created_at, last_login_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (kakao_id, nickname, email, now, now),
                )
                user_id = cursor.lastrowid
                logger.info("[user] 신규 가입 — id=%s kakao_id=%s", user_id, kakao_id)
                return user_id

            user_id = row["id"]
            conn.execute(
                """
                UPDATE users
                   SET nickname      = COALESCE(?, nickname),
                       email         = COALESCE(?, email),
                       last_login_at = ?
                 WHERE id = ?
                """,
                (nickname, email, now, user_id),
            )
            logger.info("[user] 재로그인 — id=%s kakao_id=%s", user_id, kakao_id)
            return user_id
    except sqlite3.Error as e:
        logger.warning("[user] upsert 실패: %s", e)
        return None


def get_by_id(user_id: int) -> dict | None:
    """
    user_id 로 사용자 레코드를 조회한다.

    Args:
        user_id: users.id

    Returns:
        {"id": int, "kakao_id": str, "nickname": str|None, "email": str|None,
         "created_at": str, "last_login_at": str|None}
        또는 None (없거나 DB 오류).
    """
    try:
        from database.db_init import get_ro_connection
        with get_ro_connection() as conn:
            row = conn.execute(
                "SELECT id, kakao_id, nickname, email, created_at, last_login_at "
                "FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
            if row is None:
                return None
            return dict(row)
    except sqlite3.Error as e:
        logger.warning("[user] get_by_id 실패: %s", e)
        return None
