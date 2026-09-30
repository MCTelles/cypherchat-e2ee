"""Password and JWT operations shared by HTTP and WebSocket handlers."""

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import InvalidTokenError
from pwdlib import PasswordHash
from sqlmodel import Session

from seguranca_auditoria.config import get_settings
from seguranca_auditoria.database import get_session
from seguranca_auditoria.models import User, UserRole

password_hash = PasswordHash.recommended()
dummy_password_hash = password_hash.hash("dummy-password-for-timing-equalization")
bearer = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        return password_hash.verify(password, stored_hash)
    except (ValueError, TypeError):
        return False


def verify_dummy_password(password: str) -> None:
    """Spend a password verification on logins for an unknown username."""
    password_hash.verify(password, dummy_password_hash)


def make_token(user: User) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {"sub": str(user.id), "iat": now, "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
         "jti": str(uuid4())},
        settings.jwt_secret_key.get_secret_value(), algorithm=settings.jwt_algorithm,
    )


def user_from_token(token: str, session: Session) -> User | None:
    settings = get_settings()
    try:
        data = jwt.decode(token, settings.jwt_secret_key.get_secret_value(),
                          algorithms=[settings.jwt_algorithm], options={"require": ["sub", "iat", "exp", "jti"]})
        user_id = UUID(data["sub"])
    except (InvalidTokenError, KeyError, ValueError, TypeError):
        return None
    user = session.get(User, user_id)
    return user if user is not None and user.is_active else None


def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
                 session: Session = Depends(get_session)) -> User:
    user = user_from_token(credentials.credentials, session) if credentials else None
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Credenciais inválidas",
                            headers={"WWW-Authenticate": "Bearer"})
    return user


def admin_user(user: User = Depends(current_user)) -> User:
    if user.role != UserRole.ADMIN:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Acesso restrito ao administrador")
    return user
