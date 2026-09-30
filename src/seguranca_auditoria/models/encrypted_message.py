from datetime import datetime
from enum import Enum
from uuid import UUID, uuid4

from sqlalchemy import Column, DateTime, Enum as SQLAlchemyEnum, LargeBinary, String, func
from sqlmodel import Field, SQLModel


class MessageStatus(str, Enum):
    PENDING = "pending"
    DELIVERED = "delivered"
    READ = "read"
    EXPIRED = "expired"


class EncryptedMessage(SQLModel, table=True):
    __tablename__ = "encrypted_messages"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    sender_id: UUID = Field(
        foreign_key="users.id",
        index=True,
        nullable=False,
        ondelete="CASCADE",
    )
    recipient_id: UUID = Field(
        foreign_key="users.id",
        index=True,
        nullable=False,
        ondelete="CASCADE",
    )
    ciphertext: bytes = Field(sa_column=Column(LargeBinary, nullable=False))
    nonce: bytes = Field(sa_column=Column(LargeBinary, nullable=False))
    ephemeral_public_key: bytes = Field(
        sa_column=Column(LargeBinary, nullable=False),
    )
    signature: bytes = Field(sa_column=Column(LargeBinary, nullable=False))
    algorithm: str = Field(sa_column=Column(String(50), nullable=False))
    status: MessageStatus = Field(
        default=MessageStatus.PENDING,
        sa_column=Column(
            SQLAlchemyEnum(
                MessageStatus,
                name="message_status",
                values_callable=lambda enum: [item.value for item in enum],
                native_enum=False,
                create_constraint=True,
                validate_strings=True,
            ),
            nullable=False,
        ),
    )
    created_at: datetime = Field(
        sa_column=Column(
            DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
        )
    )
    delivered_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    expires_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True, index=True),
    )
