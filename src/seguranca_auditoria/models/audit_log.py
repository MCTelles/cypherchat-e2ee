from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Column, DateTime, Enum as SQLAlchemyEnum, JSON, String, Text, func
from sqlmodel import Field, SQLModel


class AuditResult(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"


class AuditLog(SQLModel, table=True):
    __tablename__ = "audit_logs"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    occurred_at: datetime = Field(
        sa_column=Column(
            DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
        )
    )
    actor_user_id: UUID | None = Field(
        default=None,
        foreign_key="users.id",
        index=True,
        nullable=True,
        ondelete="SET NULL",
    )
    action: str = Field(sa_column=Column(String(80), index=True, nullable=False))
    resource_type: str | None = Field(
        default=None,
        sa_column=Column(String(80), nullable=True),
    )
    resource_id: str | None = Field(
        default=None,
        sa_column=Column(String(64), nullable=True),
    )
    source_ip: str | None = Field(
        default=None,
        sa_column=Column(String(45), nullable=True),
    )
    result: AuditResult = Field(
        sa_column=Column(
            SQLAlchemyEnum(
                AuditResult,
                name="audit_result",
                values_callable=lambda enum: [item.value for item in enum],
                native_enum=False,
                create_constraint=True,
                validate_strings=True,
            ),
            nullable=False,
        )
    )
    reason: str | None = Field(
        default=None,
        sa_column=Column(Text, nullable=True),
    )
    details: dict[str, Any] | None = Field(
        default=None,
        sa_column=Column(JSON, nullable=True),
    )
