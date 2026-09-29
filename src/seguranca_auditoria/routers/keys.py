from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from seguranca_auditoria.database import get_session
from seguranca_auditoria.dependencies import CurrentUser
from seguranca_auditoria.models import PublicKey, User
from seguranca_auditoria.schemas.keys import (
    ActivePublicKey,
    OwnPublicKey,
    PublicKeyCreate,
)
from seguranca_auditoria.security import keys as key_utils

router = APIRouter(tags=["keys"])

SessionDep = Annotated[Session, Depends(get_session)]

_KEY_NOT_FOUND = "Key not found"
_ACTIVE_KEY_NOT_FOUND = "Active key not found"


def _find_conflict_or_duplicate(
    session: Session, user: User, fp: str
) -> PublicKey | HTTPException | None:
    """Return the already-registered identical key (idempotent case), an HTTP error
    describing why the key cannot be registered, or None if registration may proceed."""
    existing = session.exec(select(PublicKey).where(PublicKey.fingerprint == fp)).first()
    if existing is not None:
        if existing.user_id != user.id:
            return HTTPException(status.HTTP_409_CONFLICT, "Public key already registered")
        if not existing.is_active:
            return HTTPException(
                status.HTTP_409_CONFLICT,
                "This key was revoked and cannot be registered again; generate a new key pair",
            )
        return existing
    active = session.exec(
        select(PublicKey).where(PublicKey.user_id == user.id, PublicKey.is_active)
    ).first()
    if active is not None:
        return HTTPException(
            status.HTTP_409_CONFLICT,
            "An active key already exists; revoke it before registering a new one",
        )
    return None


@router.post("/keys", response_model=OwnPublicKey, status_code=status.HTTP_201_CREATED)
def register_key(
    data: PublicKeyCreate, current_user: CurrentUser, session: SessionDep, response: Response
) -> OwnPublicKey:
    """Register the caller's public key. The server never sees private keys.

    Re-sending the caller's own active key is idempotent (200, same record).
    """
    raw = key_utils.decode_public_key(data.public_key)
    fp = key_utils.fingerprint(raw)

    outcome = _find_conflict_or_duplicate(session, current_user, fp)
    if isinstance(outcome, HTTPException):
        raise outcome
    if isinstance(outcome, PublicKey):
        response.status_code = status.HTTP_200_OK
        return OwnPublicKey.from_model(outcome)

    key = PublicKey(
        user_id=current_user.id,
        public_key=raw,
        fingerprint=fp,
        algorithm=data.algorithm,
    )
    session.add(key)
    try:
        session.commit()
    except IntegrityError:
        # Lost a race (same fingerprint or second active key): the database
        # constraints are the source of truth, so re-evaluate on a clean session.
        session.rollback()
        outcome = _find_conflict_or_duplicate(session, current_user, fp)
        if isinstance(outcome, PublicKey):
            response.status_code = status.HTTP_200_OK
            return OwnPublicKey.from_model(outcome)
        raise (
            outcome
            if isinstance(outcome, HTTPException)
            else HTTPException(status.HTTP_409_CONFLICT, "Key registration conflict")
        ) from None
    session.refresh(key)
    return OwnPublicKey.from_model(key)


@router.get("/keys/me", response_model=list[OwnPublicKey])
def list_own_keys(current_user: CurrentUser, session: SessionDep) -> list[OwnPublicKey]:
    keys = session.exec(
        select(PublicKey)
        .where(PublicKey.user_id == current_user.id)
        .order_by(PublicKey.created_at.desc(), PublicKey.id)
    ).all()
    return [OwnPublicKey.from_model(key) for key in keys]


@router.get("/users/{user_id}/keys/active", response_model=ActivePublicKey)
def get_active_key(
    user_id: UUID, current_user: CurrentUser, session: SessionDep
) -> ActivePublicKey:
    # Unknown user, inactive user and user without active key are indistinguishable.
    key = session.exec(
        select(PublicKey)
        .join(User, User.id == PublicKey.user_id)
        .where(PublicKey.user_id == user_id, PublicKey.is_active, User.is_active)
    ).first()
    if key is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, _ACTIVE_KEY_NOT_FOUND)
    return ActivePublicKey.from_model(key)


@router.post("/keys/{key_id}/revoke", response_model=OwnPublicKey)
def revoke_key(key_id: UUID, current_user: CurrentUser, session: SessionDep) -> OwnPublicKey:
    """Revoke one of the caller's keys. Repeating the call returns the same record."""
    # Lock the row so concurrent revocations keep the first revoked_at.
    key = session.exec(
        select(PublicKey)
        .where(PublicKey.id == key_id, PublicKey.user_id == current_user.id)
        .with_for_update()
    ).first()
    if key is None:  # missing or owned by someone else: same answer
        raise HTTPException(status.HTTP_404_NOT_FOUND, _KEY_NOT_FOUND)
    if key.is_active:
        key.is_active = False
        key.revoked_at = datetime.now(UTC)
        session.add(key)
        session.commit()
        session.refresh(key)
    return OwnPublicKey.from_model(key)
