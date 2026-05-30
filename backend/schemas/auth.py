# =============================================================================
# backend/schemas/auth.py
# 역할: 인증 라우터(/auth/*) 의 요청·응답 Pydantic 스키마.
# AUTH-01 (v0530 신설).
# =============================================================================

from pydantic import BaseModel, Field


class KakaoLoginRequest(BaseModel):
    """
    POST /auth/kakao 요청 바디.

    Flutter 가 kakao_flutter_sdk_user 로 받은 카카오 access_token 을 그대로
    백엔드에 전달한다. 백엔드는 이 토큰으로 kapi.kakao.com 을 호출해
    사용자 정보를 받아오므로 클라이언트가 임의 정보로 위장할 수 없다.
    """
    access_token: str = Field(..., min_length=1, max_length=2048)


class AuthTokenResponse(BaseModel):
    """
    POST /auth/kakao 응답.

    Flutter 는 access_token 을 SharedPreferences 에 저장하고, 이후 모든
    요청 헤더 Authorization: Bearer <token> 에 부착한다.

    Attributes:
        access_token: 서버 발급 JWT.
        token_type:   고정 "Bearer".
        expires_in:   초 단위 만료시간.
        user:         가입자 프로필 (가입 직후 클라이언트가 별도 /auth/me
                      호출 없이 화면을 그릴 수 있도록 동봉).
    """
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    user: "MeResponse"


class MeResponse(BaseModel):
    """
    GET /auth/me 응답. 본인 프로필.
    """
    id: int
    kakao_id: str
    nickname: str | None = None
    email: str | None = None
    created_at: str
    last_login_at: str | None = None


# AuthTokenResponse.user 의 forward reference 해제.
AuthTokenResponse.model_rebuild()
