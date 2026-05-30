# =============================================================================
# backend/services/jwt_service.py
# 역할: 서버 발급 JWT(HS256) 의 발급·검증. /auth/kakao 후속 토큰 발급에 사용.
#
# AUTH-03 (v0530 신설):
#   - 서버는 stateless — 로그아웃은 클라이언트가 토큰을 버린다.
#   - 만료시간은 기본 30 일(720 시간). 모바일 앱 특성상 짧은 만료는 UX 손해.
#   - 시크릿은 backend/.env 의 JWT_SECRET (openssl rand -hex 32 결과).
#     운영 환경에서 미설정이면 명시적 ValueError — 약한 기본값으로 폴백 금지.
# =============================================================================

import datetime
import logging
import os

import jwt

logger = logging.getLogger(__name__)

_JWT_ALG_DEFAULT = "HS256"
_JWT_EXPIRE_HOURS_DEFAULT = 720  # 30 days


class JWTError(Exception):
    """JWT 검증 실패. 라우터에서 401 로 변환."""


def _secret() -> str:
    """
    JWT 서명용 시크릿을 환경에서 읽는다.

    미설정이면 ValueError — 운영에서 약한 기본값으로 토큰 발급되는 사고를
    원천 차단한다. 테스트는 monkeypatch 로 환경변수를 주입한다.
    """
    secret = os.environ.get("JWT_SECRET")
    if not secret:
        raise ValueError(
            "JWT_SECRET 환경변수가 설정되지 않았습니다. "
            "backend/.env 에 'openssl rand -hex 32' 결과를 등록하세요."
        )
    return secret


def _algorithm() -> str:
    return os.environ.get("JWT_ALG", _JWT_ALG_DEFAULT)


def _expire_hours() -> int:
    try:
        return int(os.environ.get("JWT_EXPIRE_HOURS", _JWT_EXPIRE_HOURS_DEFAULT))
    except ValueError:
        return _JWT_EXPIRE_HOURS_DEFAULT


def issue_token(user_id: int) -> tuple[str, int]:
    """
    user_id 를 sub 클레임에 담은 JWT 를 발급한다.

    Args:
        user_id: users.id

    Returns:
        (token, expires_in_seconds)
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    expire_hours = _expire_hours()
    exp = now + datetime.timedelta(hours=expire_hours)

    payload = {
        "sub": str(user_id),
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    token = jwt.encode(payload, _secret(), algorithm=_algorithm())
    # PyJWT 2.x 는 str 반환. 1.x 는 bytes — 명시 변환으로 호환.
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token, expire_hours * 3600


def decode_token(token: str) -> int:
    """
    JWT 를 검증하고 user_id 를 반환한다.

    Raises:
        JWTError: 서명 불일치 / 만료 / 변조 / sub 누락.
    """
    if not token:
        raise JWTError("토큰이 비어있습니다.")

    try:
        payload = jwt.decode(
            token,
            _secret(),
            algorithms=[_algorithm()],
        )
    except jwt.ExpiredSignatureError as e:
        raise JWTError("토큰이 만료되었습니다.") from e
    except jwt.InvalidTokenError as e:
        raise JWTError(f"유효하지 않은 토큰: {e}") from e

    sub = payload.get("sub")
    if sub is None:
        raise JWTError("토큰에 sub 클레임이 없습니다.")
    try:
        return int(sub)
    except (TypeError, ValueError) as e:
        raise JWTError("sub 클레임이 정수가 아닙니다.") from e
