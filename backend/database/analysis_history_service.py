# =============================================================================
# backend/database/analysis_history_service.py
# 역할: analysis_history 테이블 쓰기 (DAT-06: /analyze 호출 이력 비동기 저장)
#
# BackgroundTasks.add_task()로 호출되므로 동기 함수로 구현한다.
# =============================================================================

import datetime
import json
import logging

from database.blacklist_service import compute_url_hash, normalize_url

logger = logging.getLogger(__name__)


def save_analysis_history(
    url: str,
    verdict: str,
    registered_domain: str | None = None,
    triggered_signals: dict | None = None,
    heuristic_score: int | None = None,
    prior_vote_danger: int = 0,
    prior_vote_safe: int = 0,
    response_time_ms: int | None = None,
    device_uuid: str = "",
) -> None:
    """
    분석 이력을 analysis_history 테이블에 저장한다.

    BackgroundTasks.add_task()로 호출되는 동기 함수.
    실패해도 예외를 밖으로 던지지 않는다 (서비스 중단 방지).

    Args:
        url:              분석 대상 URL
        verdict:          판정 결과 ('danger' | 'suspicious' | 'safe')
        registered_domain: 등록 도메인 (선택적)
        triggered_signals: 발화된 휴리스틱 시그널 딕셔너리 (선택적)
        heuristic_score:   휴리스틱 합산 점수 (선택적)
        prior_vote_danger: 사전 danger 투표 수
        prior_vote_safe:   사전 safe 투표 수
        response_time_ms:  파이프라인 처리 시간(ms)
        device_uuid:       기기 UUID (NF-30)
    """
    try:
        from database.db_init import get_rw_connection

        # P0-1: 블랙리스트와 동일한 정규화로 키를 만든다 (보고서 D-3).
        url_hash = compute_url_hash(normalize_url(url))
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat()
        signals_json = json.dumps(triggered_signals or {}, ensure_ascii=False)

        with get_rw_connection() as conn:
            conn.execute(
                """
                INSERT INTO analysis_history
                    (url_hash, url, registered_domain, verdict,
                     triggered_signals, heuristic_score,
                     prior_vote_danger, prior_vote_safe,
                     response_time_ms, device_uuid, analyzed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    url_hash, url, registered_domain, verdict,
                    signals_json, heuristic_score,
                    prior_vote_danger, prior_vote_safe,
                    response_time_ms, device_uuid, now,
                ),
            )
        logger.debug("[이력] 저장 완료: verdict=%s url=%s", verdict, url[:60])
    except Exception as e:
        logger.warning("[이력] 저장 실패 (무시): %s", e)
