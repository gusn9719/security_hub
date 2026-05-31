# =============================================================================
# backend/services/kakao_service.py
# 역할: 카카오 access token 으로 사용자 정보 조회. /auth/kakao 라우터 전용 헬퍼.
#
# AUTH-02 (v0530 신설):
#   - 흐름: Flutter (kakao_flutter_sdk_user) 가 카카오 로그인 → access_token 획득
#           → 백엔드 POST /auth/kakao 에 전달 → 본 모듈이 kapi.kakao.com 호출
#           → 사용자 정보 → user_service.upsert → JWT 발급.
#   - 카카오 API 문서: https://developers.kakao.com/docs/latest/ko/kakaologin/rest-api
# =============================================================================

import logging
import httpx

logger = logging.getLogger(__name__)

_KAPI_USER_ME_URL = "https://kapi.kakao.com/v2/user/me"
_REQUEST_TIMEOUT_SEC = 5.0


class KakaoAuthError(Exception):
    """카카오 access token 검증 실패. 라우터에서 401 로 변환."""


async def fetch_user_info(access_token: str) -> dict:
    """
    카카오 access token 으로 사용자 프로필을 조회한다.

    Args:
        access_token: Flutter SDK 가 받은 카카오 access token (Bearer 토큰).

    Returns:
        {"kakao_id": str, "nickname": str|None, "email": str|None}

    Raises:
        KakaoAuthError: token 이 만료/무효이거나 카카오가 응답하지 않을 때.
    """
    if not access_token:
        raise KakaoAuthError("access_token 이 비어있습니다.")

    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT_SEC) as client:
            resp = await client.get(_KAPI_USER_ME_URL, headers=headers)
    except httpx.RequestError as e:
        logger.warning("[kakao] kapi 호출 실패: %s", e)
        raise KakaoAuthError(f"카카오 API 통신 실패: {e}") from e

    # 401: 만료/무효 토큰. 그 외 4xx/5xx 도 인증 실패로 본다.
    if resp.status_code != 200:
        # body 평문은 로그에 남기지 않는다 — 카카오 응답에 회원 식별자·이메일
        # 등이 포함될 수 있어 운영 로그 누적 시 PII 정책 위반 위험. 상태
        # 코드만 기록해도 운영 디버깅에 충분.
        logger.warning("[kakao] kapi 비정상 응답 status=%d", resp.status_code)
        raise KakaoAuthError(f"카카오 토큰 검증 실패 (status={resp.status_code})")

    try:
        data = resp.json()
    except ValueError as e:
        raise KakaoAuthError(f"카카오 응답 JSON 파싱 실패: {e}") from e

    kakao_id_raw = data.get("id")
    if kakao_id_raw is None:
        raise KakaoAuthError("카카오 응답에 회원 고유번호(id) 가 없습니다.")

    # kakao_account 와 properties 위치가 동의 항목 / 시점에 따라 달라지므로
    # 양쪽 모두 시도한 뒤 fallback.
    account = data.get("kakao_account") or {}
    profile = account.get("profile") or {}
    properties = data.get("properties") or {}

    nickname = (
        profile.get("nickname")
        or properties.get("nickname")
        or None
    )
    # 이메일은 선택 동의 — 사용자가 거부하면 키 자체가 없거나 needs_agreement.
    email = account.get("email") if account.get("is_email_valid", True) else None

    return {
        "kakao_id": str(kakao_id_raw),
        "nickname": nickname,
        "email": email,
    }
