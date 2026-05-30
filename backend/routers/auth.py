# =============================================================================
# backend/routers/auth.py
# 역할: 카카오 소셜 로그인 + JWT 발급/검증 라우터.
#
# AUTH-01 (v0530 신설):
#   POST /auth/kakao  — Flutter 가 받은 카카오 access_token → 백엔드 JWT 교환.
#   GET  /auth/me     — Authorization: Bearer <jwt> 로 본인 프로필 조회.
#   POST /auth/logout — 서버 stateless 라 실질 동작 없음. 클라이언트가
#                       JWT 를 SharedPreferences 에서 지우면 끝.
# =============================================================================

import logging

from fastapi import APIRouter, HTTPException, Request, status

from database import user_service
from schemas.auth import AuthTokenResponse, KakaoLoginRequest, MeResponse
from services import jwt_service, kakao_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/kakao", response_model=AuthTokenResponse)
async def login_with_kakao(req: KakaoLoginRequest) -> AuthTokenResponse:
    """
    Flutter 가 받은 카카오 access_token 을 받아 백엔드 JWT 로 교환한다.

    절차:
        1. kapi.kakao.com 으로 토큰 검증 + 사용자 정보 조회.
        2. users 테이블 upsert (신규/재로그인 모두 처리).
        3. JWT 발급 + 프로필 동봉 반환.
    """
    try:
        kakao_user = await kakao_service.fetch_user_info(req.access_token)
    except kakao_service.KakaoAuthError as e:
        logger.info("[auth] 카카오 토큰 검증 실패: %s", e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="카카오 토큰이 유효하지 않습니다.",
        ) from e

    user_id = user_service.upsert_by_kakao_id(
        kakao_id=kakao_user["kakao_id"],
        nickname=kakao_user.get("nickname"),
        email=kakao_user.get("email"),
    )
    if user_id is None:
        logger.warning("[auth] DB upsert 실패 — kakao_id=%s", kakao_user["kakao_id"])
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="사용자 정보를 저장하지 못했습니다.",
        )

    profile = user_service.get_by_id(user_id)
    if profile is None:
        # upsert 직후 조회 실패 — 거의 발생하지 않지만 방어.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="가입 직후 프로필 조회에 실패했습니다.",
        )

    token, expires_in = jwt_service.issue_token(user_id)
    return AuthTokenResponse(
        access_token=token,
        expires_in=expires_in,
        user=MeResponse(**profile),
    )


@router.get("/me", response_model=MeResponse)
async def get_me(request: Request) -> MeResponse:
    """
    Authorization: Bearer <jwt> 로 본인 프로필을 반환한다.

    OptionalAuthMiddleware (Phase 3) 가 request.state.user_id 를 채우지만,
    /auth/me 는 인증이 필수이므로 미들웨어 결과와 무관하게 헤더를 직접
    검증한다. (미들웨어 도입 전에도 이 라우터만으로 동작)
    """
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization: Bearer <jwt> 헤더가 필요합니다.",
        )
    token = auth.split(" ", 1)[1].strip()

    try:
        user_id = jwt_service.decode_token(token)
    except jwt_service.JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        ) from e

    profile = user_service.get_by_id(user_id)
    if profile is None:
        # JWT 는 유효하지만 사용자가 DB 에서 사라진 경우 (예: 탈퇴 후 재발급
        # 토큰을 가진 클라이언트). 401 로 응답해 클라이언트가 토큰 폐기.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="사용자가 존재하지 않습니다.",
        )
    return MeResponse(**profile)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout() -> None:
    """
    클라이언트가 토큰을 폐기하기만 하면 충분하다. 서버는 JWT 를 stateless
    로 운용하므로 별도 블랙리스트를 유지하지 않는다. 라우터는 API 일관성과
    문서화를 위해 둔다.
    """
    return None
