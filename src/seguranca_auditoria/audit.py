"""Structured 5W audit events without secrets or message contents."""

import json
import logging
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import event
from sqlmodel import Session

from seguranca_auditoria.models import AuditLog, AuditResult

logger = logging.getLogger("cypherchat.audit")
logger.setLevel(logging.INFO)
logger.propagate = False
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)


@event.listens_for(Session, "after_commit")
def _emit_committed_events(session: Session) -> None:
    for payload in session.info.pop("audit_events", []):
        logger.info(json.dumps(payload))


@event.listens_for(Session, "after_rollback")
def _discard_rolled_back_events(session: Session) -> None:
    session.info.pop("audit_events", None)


def record(session: Session, *, who: UUID | None, what: str, where: str | None,
           why: str, result: AuditResult, resource_type: str | None = None,
           resource_id: str | None = None) -> None:
    """Caller commits the transaction so an event and its mutation stay atomic."""
    event = AuditLog(actor_user_id=who, action=what, source_ip=where,
                     reason=why, result=result, resource_type=resource_type,
                     resource_id=resource_id)
    session.add(event)
    session.info.setdefault("audit_events", []).append({
        "when": datetime.now(timezone.utc).isoformat(),
        "who": str(who) if who else None, "what": what,
        "where": where, "why": why, "result": result.value,
        "resource_type": resource_type, "resource_id": resource_id,
    })
