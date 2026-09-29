from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import Column, DateTime, Index, LargeBinary, String, func, text
from sqlmodel import Field, SQLModel


class PublicKey(SQLModel, table=True):
    __tablename__ = "public_keys"
    __table_args__ = (
        # At most one active key per user, enforced by the database.
        # Existing databases: apply sql/0001_public_keys_one_active_per_user.sql.
        Index(
            "uq_public_keys_one_active_per_user",
            "user_id",
            unique=True,
            postgresql_where=text("is_active"),
        ),
    )

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
