from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from seguranca_auditoria.models import PublicKey
from seguranca_auditoria.security import keys as key_utils


class PublicKeyCreate(BaseModel):
    """Only the algorithm and the public key. Everything else is server-controlled."""

    model_config = ConfigDict(extra="forbid")

    algorithm: Literal["X25519"]
    public_key: str = Field(max_length=64, description="Base64 of the 32 raw key bytes")

    @field_validator("public_key")
    @classmethod
    def _validate_public_key(cls, value: str) -> str:
        try:
            key_utils.decode_public_key(value)
        except key_utils.InvalidPublicKeyError as exc:
            raise ValueError(str(exc)) from None
        return value


class OwnPublicKey(BaseModel):
    id: UUID
    algorithm: str
    public_key: str
    fingerprint: str
    is_active: bool
    created_at: datetime
    revoked_at: datetime | None

    @classmethod
    def from_model(cls, key: PublicKey) -> "OwnPublicKey":
        return cls(
            id=key.id,
            algorithm=key.algorithm,
            public_key=key_utils.encode_public_key(key.public_key),
            fingerprint=key.fingerprint,
            is_active=key.is_active,
            created_at=key.created_at,
            revoked_at=key.revoked_at,
        )


class ActivePublicKey(BaseModel):
    id: UUID
    user_id: UUID
    algorithm: str
    public_key: str
    fingerprint: str
    created_at: datetime

    @classmethod
    def from_model(cls, key: PublicKey) -> "ActivePublicKey":
        return cls(
            id=key.id,
            user_id=key.user_id,
            algorithm=key.algorithm,
            public_key=key_utils.encode_public_key(key.public_key),
            fingerprint=key.fingerprint,
            created_at=key.created_at,
        )
