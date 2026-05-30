# =============================================================================
# backend/database/vote_service.py
# 역할: url_votes 테이블 읽기/쓰기. 7-A 직접 탐방 세션 종료 후 사용자 피드백 수집.
#
# ─────────────────────────────────────────────────────────────────────────────
# 투표 종류와 정책 (v0527 정정)
# ─────────────────────────────────────────────────────────────────────────────
# 허용 값: safe / danger / spam / unsure
#
#   safe   : "안전했다"               → 양의 검증 신호 (음의 휴리스틱 가중치)
#   danger : "위험했다"               → 양의 위협 신호
#   spam   : "광고·스팸이었다"        → 보조 신호 (위협은 아님)
#   unsure : "잘 모르겠다 — 판단 보류" → 시스템 학습에 0 기여, DB 슬롯 미점유
#
# unsure 처리 원칙 (v0527 도입):
#   - DB INSERT 하지 않는다.
#   - 어그로 방어 4중 중 Layer 1(UNIQUE device_uuid+registered_domain)을
#     점유하지 않으므로 사용자는 향후 진짜 의견(safe/danger/spam)으로 재투표
#     가능.
#   - 이론적 근거: 데이터 라벨링 연구(Confident Learning, Northcutt et al.
#     2021; Cheap and Fast, Snow et al. 2008)에서 확신 없는 라벨러에게 강제
#     선택을 시키면 라벨 노이즈가 분류기 정확도를 떨어뜨림. unsure 는 옵트
#     아웃 채널로 보존하되 신호 풀에는 넣지 않는다.
#   - 호출자(라우터)에는 success=True 로 응답 — UX 일관성 유지.
#
# DC-30 (v0507): vote 값 'danger' 표준화 + device_uuid 필드.
# v0527        : unsure 무저장 정책 적용.
# =============================================================================

import datetime
import logging
from urllib.parse import urlparse

from database.blacklist_service import compute_url_hash, normalize_url

logger = logging.getLogger(__name__)


# 허용 투표 값 목록.
# 'unsure' 는 UX 표기상 유효하지만 본 모듈은 DB 저장하지 않는다(아래 save_vote 참조).
_VALID_VOTES: tuple[str, ...] = ("safe", "danger", "spam", "unsure")

# DB 슬롯을 점유하는(어그로 방어 Layer 1 대상) 의미 있는 투표 값.
# 휴리스틱 시그널(prior_*_vote_*)에 기여하는 종류와 동일.
_MEANINGFUL_VOTES: frozenset[str] = frozenset({"safe", "danger", "spam"})


def save_vote(
    url: str,
    session_id: str,
    vote: str,
    device_uuid: str = "",
    user_id: int | None = None,
) -> bool:
    """
    사용자 투표를 url_votes 에 저장한다.

    저장 규칙 (v0527):
        - vote ∈ {'safe','danger','spam'} → DB INSERT, UNIQUE 슬롯 점유.
        - vote == 'unsure'                → DB 저장하지 않음, 항상 True 반환.
          (사용자에게는 '의견이 기록되었습니다' UX 응답을 보장하면서 슬롯은
           비워두어 향후 진짜 의견으로 재투표 가능하도록 한다.)
        - 그 외 값                        → False (검증 실패).

    중복 처리:
        - 의미 있는 투표가 동일 session_id 또는 동일 (device_uuid, registered_
          domain) 조합으로 이미 존재하면 SQLite UNIQUE 인덱스 + INSERT OR
          IGNORE 로 조용히 무시.

    Args:
        url:         투표 대상 URL
        session_id:  7-A 탐방 세션 ID (container_id) — UNIQUE 제약
        vote:        "safe" | "danger" | "spam" | "unsure"
        device_uuid: 기기 식별 UUID (NF-30)
        user_id:     카카오 가입자 users.id. None 이면 익명 표.
                     (Phase 2 — heuristic_scorer 가 가입자 표를 익명 표보다
                      강하게 평가하는 데 사용)

    Returns:
        True  = 신규 저장 성공 OR unsure 정책상 무저장
        False = 유효성 실패 또는 DB 오류
    """
    if vote not in _VALID_VOTES:
        logger.warning("[투표] 유효하지 않은 vote 값: %s", vote)
        return False

    # ── unsure: 슬롯 미점유 정책 ───────────────────────────────────────────
    # v0527: 'unsure' 는 의미 있는 신호가 아니므로 DB INSERT 를 건너뛴다.
    # 사용자 UX 상으로는 성공(True) 응답. session_id 슬롯은 안 잡히지만
    # 7-A 세션은 어차피 1회용이므로 영향 없음.
    if vote == "unsure":
        logger.info(
            "[투표] unsure — DB 저장 생략 (슬롯 미점유 정책). session_id=%s",
            session_id,
        )
        return True

    # ── 의미 있는 투표(safe/danger/spam): DB 저장 ──────────────────────────
    # url_hash 는 blacklist_service.normalize_url() 정규화 결과 + SHA256.
    # 블랙리스트/샌드박스/분석이력 모두 동일 키를 사용해야 피드백 순환이
    # 작동한다 (P0-1, 보고서 D-3).
    url_hash = compute_url_hash(normalize_url(url))
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat()

    # domain / registered_domain 추출 — UNIQUE(device_uuid, registered_domain)
    # 인덱스 동작에 필요. 추출 실패 시 인덱스는 NULL 조건으로 잠금 안 됨.
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
                     domain, registered_domain, user_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (url_hash, url, vote, now, session_id, device_uuid,
                 domain, registered_domain, user_id),
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
    URL 에 대한 투표 수를 반환한다.

    반환 키:
        safe / danger / spam   : 의미 있는 투표 카운트 (익명 + 가입자 합)
        anon_safe / anon_danger / anon_spam: user_id IS NULL 인 표만
        user_safe / user_danger / user_spam: user_id IS NOT NULL 인 표만
        unsure                 : v0527 부터 항상 0 (DB 저장 안 함)
        total                  : safe + danger + spam (의미 있는 표 총합)

    안 / 가입자 분리는 heuristic_scorer 가 가입자 표 1 명을 익명 표 3~4 명
    권위로 환산할 때 사용한다. 합계 키(safe/danger/spam) 는 우세 방향
    가드(예: danger > safe) 비교용으로 그대로 유지 — 후방 호환.

    Args:
        url: 집계 대상 URL

    Returns:
        anon_*/user_* + 합계 + total + unsure(=0).
    """
    # P0-1: 블랙리스트와 동일한 정규화로 키를 만든다 (보고서 D-3).
    url_hash = compute_url_hash(normalize_url(url))

    # 기본값 — DB 오류 시에도 같은 키 집합을 보장해 호출자(휴리스틱) 가
    # KeyError 없이 동작하도록.
    zero = {
        "safe": 0, "danger": 0, "spam": 0, "unsure": 0,
        "anon_safe": 0, "anon_danger": 0, "anon_spam": 0,
        "user_safe": 0, "user_danger": 0, "user_spam": 0,
        "total": 0,
    }

    try:
        from database.db_init import get_ro_connection
        with get_ro_connection() as conn:
            # CASE 한 줄로 익명/가입자를 동시에 집계. GROUP BY 두 컬럼.
            rows = conn.execute(
                """
                SELECT vote,
                       CASE WHEN user_id IS NULL THEN 'anon' ELSE 'user' END AS bucket,
                       COUNT(*) AS cnt
                  FROM url_votes
                 WHERE url_hash = ?
                 GROUP BY vote, bucket
                """,
                (url_hash,),
            ).fetchall()

            counts = dict(zero)
            for row in rows:
                vote = row["vote"]
                if vote not in ("safe", "danger", "spam"):
                    continue
                bucket = row["bucket"]   # 'anon' | 'user'
                cnt = row["cnt"]
                counts[f"{bucket}_{vote}"] = cnt
                counts[vote] += cnt      # 합계 키
            counts["total"] = counts["safe"] + counts["danger"] + counts["spam"]
            return counts
    except Exception as e:
        logger.warning("[투표] 집계 실패: %s", e)
        return zero
