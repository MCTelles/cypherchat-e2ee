from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import Column, DateTime, LargeBinary, String, func
from sqlmodel import Field, SQLModel


class PublicKey(SQLModel, table=True):
    __tablename__ = "public_keys"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    user_id: UUID = Field(
        foreign_key="users.id",
        index=True,
        nullable=False,
        ondelete="CASCADE",
    )
    public_key: bytes = Field(sa_column=Column(LargeBinary, nullable=False))
    fingerprint: str = Field(
        sa_column=Column(String(64), unique=True, index=True, nullable=False)
    )
    algorithm: str = Field(
        default="X25519",
        sa_column=Column(String(30), nullable=False),
    )
    is_active: bool = Field(default=True, index=True, nullable=False)
    created_at: datetime = Field(
        sa_column=Column(
            DateTime(timezone=True), nullable=False, server_default=func.now()
        )
    )
    revoked_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
