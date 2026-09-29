from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from seguranca_auditoria.database import get_session
from seguranca_auditoria.dependencies import CurrentUser
from seguranca_auditoria.models import User
from seguranca_auditoria.schemas.auth import (
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    UserPublic,
)
from seguranca_auditoria.security import passwords
from seguranca_auditoria.security.tokens import create_access_token

router = APIRouter(prefix="/auth", tags=["auth"])

SessionDep = Annotated[Session, Depends(get_session)]


@router.post("/register", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
def register(data: RegisterRequest, session: SessionDep) -> User:
    # Role and is_active are never read from the request: defaults apply (USER, active).
    user = User(
        username=data.username,
        email=data.email,
        password_hash=passwords.hash_password(data.password),
    )
    session.add(user)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or e-mail already registered",
        ) from None
    session.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
def login(data: LoginRequest, session: SessionDep) -> TokenResponse:
    user = session.exec(select(User).where(User.username == data.username)).first()
    if user is None:
        passwords.verify_dummy_password(data.password)
        password_ok = False
    else:
        password_ok = passwords.verify_password(data.password, user.password_hash)

    if user is None or not password_ok or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return TokenResponse(access_token=create_access_token(user.id))


@router.get("/me", response_model=UserPublic)
def read_me(current_user: CurrentUser) -> User:
    return current_user
