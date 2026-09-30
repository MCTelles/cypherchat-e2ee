"""Local CypherChat API: identity directory, administration and ciphertext relay."""

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect, status
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, func, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import Session, select
from starlette.responses import JSONResponse

from seguranca_auditoria.audit import record
from seguranca_auditoria.config import get_settings
from seguranca_auditoria.database import get_engine, get_session
from seguranca_auditoria.models import (AuditLog, AuditResult, EncryptedMessage,
                                       MessageStatus, PublicKey, User, UserRole)
from seguranca_auditoria.rate_limit import (RequestBodyLimit, http_rate_limit,
                                           login_limiter, ws_limiter)
from seguranca_auditoria.security.auth import (admin_user, current_user, hash_password,
                                               make_token, user_from_token, verify_dummy_password,
                                               verify_password)
from seguranca_auditoria.security.e2ee import (ALGORITHM, _signed_bytes, b64,
                                              fingerprint, unb64)

logging.basicConfig(level=get_settings().log_level)
app = FastAPI(title="CypherChat E2EE", version="0.1.0")
app.middleware("http")(http_rate_limit)
app.add_middleware(RequestBodyLimit)


@app.exception_handler(RequestValidationError)
async def validation_error(_request: Request, _exc: RequestValidationError):
    # FastAPI's default error can echo supplied values, including passwords.
    return JSONResponse({"detail": "Entrada inválida"}, status_code=422)


@app.exception_handler(Exception)
async def unexpected_error(request: Request, exc: Exception):
    logging.getLogger("cypherchat.server").error(json.dumps({
        "when": datetime.now(timezone.utc).isoformat(), "who": None,
        "what": "server.error", "where": source_ip(request),
        "why": type(exc).__name__, "result": "failure",
        "path": request.url.path,
    }))
    return JSONResponse({"detail": "Erro interno"}, status_code=500)


class RegisterInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_]+$")
    email: str = Field(min_length=5, max_length=254, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
    password: str = Field(min_length=12, max_length=128)
    public_key: str = Field(min_length=40, max_length=48)
    signing_public_key: str = Field(min_length=40, max_length=48)


class LoginInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_]+$")
    password: str = Field(min_length=1, max_length=128)


class MeUpdateInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str | None = Field(default=None, min_length=5, max_length=254,
                              pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
    password: str | None = Field(default=None, min_length=12, max_length=128)


class AdminUpdateInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    is_active: bool | None = None
    role: UserRole | None = None


class UserOutput(BaseModel):
    id: UUID
    username: str
    email: str
    role: UserRole
    is_active: bool


def user_output(user: User) -> dict:
    return UserOutput.model_validate(user, from_attributes=True).model_dump(mode="json")


def key_output(user: User, key: PublicKey) -> dict:
    return {"id": str(user.id), "username": user.username,
            "public_key": b64(key.public_key), "signing_public_key": b64(key.signing_public_key),
            "fingerprint": key.fingerprint, "algorithm": key.algorithm}


def source_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.get("/ready")
def readiness(session: Session = Depends(get_session)):
    try:
        session.exec(text("SELECT 1")).one()
    except SQLAlchemyError:
        raise HTTPException(503, "Banco indisponível") from None
    return {"status": "ready"}


@app.post("/auth/register", status_code=201)
async def register(payload: RegisterInput, request: Request,
                   session: Session = Depends(get_session)):
    ip = source_ip(request)
    if not await login_limiter.allow(f"register:{ip}"):
        raise HTTPException(429, "Muitas tentativas. Tente novamente mais tarde")
    try:
        public = unb64(payload.public_key)
        signing = unb64(payload.signing_public_key)
        encryption_key = x25519.X25519PublicKey.from_public_bytes(public)
        x25519.X25519PrivateKey.generate().exchange(encryption_key)
        ed25519.Ed25519PublicKey.from_public_bytes(signing)
    except (ValueError, TypeError):
        raise HTTPException(422, "Chave pública inválida") from None
    user = User(username=payload.username, email=payload.email.lower(),
                password_hash=hash_password(payload.password), role=UserRole.USER)
    key = PublicKey(user_id=user.id, public_key=public, signing_public_key=signing,
                    fingerprint=fingerprint(public, signing), algorithm=ALGORITHM)
    session.add(user)
    try:
        session.flush()
        session.add(key)
        record(session, who=user.id, what="user.create", where=ip, why="self_registration",
               result=AuditResult.SUCCESS, resource_type="user", resource_id=str(user.id))
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        unique_conflict = getattr(exc.orig, "sqlstate", None) == "23505" or "UNIQUE constraint" in str(exc.orig)
        record(session, who=None, what="user.create", where=ip,
               why="duplicate_identity" if unique_conflict else "database_integrity_error",
               result=AuditResult.FAILURE, resource_type="user")
        session.commit()
        if unique_conflict:
            raise HTTPException(409, "Usuário, email ou chave já cadastrado") from None
        raise HTTPException(500, "Não foi possível cadastrar o usuário") from None
    return user_output(user)


@app.post("/auth/token")
async def login(payload: LoginInput, request: Request,
                session: Session = Depends(get_session)):
    ip = source_ip(request)
    if not await login_limiter.allow(f"login:{ip}:{payload.username}"):
        raise HTTPException(429, "Muitas tentativas. Tente novamente mais tarde")
    user = session.exec(select(User).where(User.username == payload.username)).first()
    if user is None:
        verify_dummy_password(payload.password)
    if user is None or not verify_password(payload.password, user.password_hash) or not user.is_active:
        record(session, who=user.id if user else None, what="user.login", where=ip,
               why="invalid_credentials", result=AuditResult.FAILURE,
               resource_type="user", resource_id=str(user.id) if user else None)
        session.commit()
        raise HTTPException(401, "Credenciais inválidas")
    user.last_login_at = datetime.now(timezone.utc)
    session.add(user)
    record(session, who=user.id, what="user.login", where=ip, why="valid_credentials",
           result=AuditResult.SUCCESS, resource_type="user", resource_id=str(user.id))
    session.commit()
    return {"access_token": make_token(user), "token_type": "bearer"}


@app.get("/me")
def me(user: User = Depends(current_user)):
    return user_output(user)


@app.patch("/me")
def update_me(payload: MeUpdateInput, request: Request, user: User = Depends(current_user),
              session: Session = Depends(get_session)):
    if not payload.model_fields_set or any(getattr(payload, field) is None for field in payload.model_fields_set):
        raise HTTPException(422, "Nenhum campo para atualizar")
    if payload.email is not None:
        user.email = payload.email.lower()
    if payload.password is not None:
        user.password_hash = hash_password(payload.password)
    session.add(user)
    record(session, who=user.id, what="user.update", where=source_ip(request),
           why="self_service", result=AuditResult.SUCCESS, resource_type="user",
           resource_id=str(user.id))
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(409, "Email já cadastrado") from None
    return user_output(user)


@app.get("/users")
def directory(user: User = Depends(current_user), session: Session = Depends(get_session)):
    rows = session.exec(select(User, PublicKey).where(
        User.id == PublicKey.user_id, User.is_active == True,  # noqa: E712
        PublicKey.is_active == True, User.id != user.id  # noqa: E712
    ).limit(100)).all()
    return [key_output(account, key) for account, key in rows]


@app.get("/users/{user_id}/key")
def lookup_key(user_id: UUID, _user: User = Depends(current_user),
               session: Session = Depends(get_session)):
    account = session.get(User, user_id)
    if account is None or not account.is_active:
        raise HTTPException(404, "Usuário não encontrado")
    key = session.exec(select(PublicKey).where(PublicKey.user_id == user_id,
                                               PublicKey.is_active == True)).first()  # noqa: E712
    if key is None:
        raise HTTPException(404, "Chave não encontrada")
    return key_output(account, key)


@app.get("/admin/users")
def admin_list(_admin: User = Depends(admin_user), session: Session = Depends(get_session)):
    return [user_output(user) for user in session.exec(select(User).limit(200)).all()]


@app.patch("/admin/users/{user_id}")
def admin_update(user_id: UUID, payload: AdminUpdateInput, request: Request,
                 admin: User = Depends(admin_user), session: Session = Depends(get_session)):
    account = session.get(User, user_id)
    if account is None:
        raise HTTPException(404, "Usuário não encontrado")
    if user_id == admin.id and (payload.is_active is False or payload.role == UserRole.USER):
        raise HTTPException(409, "O administrador não pode revogar sua própria conta")
    if not payload.model_fields_set or any(getattr(payload, field) is None for field in payload.model_fields_set):
        raise HTTPException(422, "Nenhum campo para atualizar")
    if payload.is_active is not None:
        account.is_active = payload.is_active
    if payload.role is not None:
        account.role = payload.role
    session.add(account)
    record(session, who=admin.id, what="user.admin_update", where=source_ip(request),
           why="admin_action", result=AuditResult.SUCCESS, resource_type="user",
           resource_id=str(user_id))
    session.commit()
    return user_output(account)


@app.delete("/admin/users/{user_id}", status_code=204)
def admin_delete(user_id: UUID, request: Request, admin: User = Depends(admin_user),
                 session: Session = Depends(get_session)):
    if user_id == admin.id:
        raise HTTPException(409, "O administrador não pode excluir sua própria conta")
    account = session.get(User, user_id)
    if account is None:
        raise HTTPException(404, "Usuário não encontrado")
    # Keep the user row so prior audit events retain their actor and target IDs.
    account.is_active = False
    session.add(account)
    record(session, who=admin.id, what="user.remove", where=source_ip(request),
           why="admin_deactivation", result=AuditResult.SUCCESS, resource_type="user",
           resource_id=str(user_id))
    session.commit()


@app.get("/admin/audit")
def admin_audit(_admin: User = Depends(admin_user), session: Session = Depends(get_session)):
    events = session.exec(select(AuditLog).order_by(AuditLog.occurred_at.desc()).limit(100)).all()
    return [{"id": str(event.id), "when": event.occurred_at, "who": event.actor_user_id,
             "what": event.action, "where": event.source_ip, "why": event.reason,
             "result": event.result.value, "resource_type": event.resource_type,
             "resource_id": event.resource_id} for event in events]


class ConnectionManager:
    def __init__(self):
        self.connections: dict[UUID, list[WebSocket]] = {}
        self.lock = asyncio.Lock()
        self.slots = asyncio.Semaphore(100)

    async def add(self, user_id: UUID, socket: WebSocket) -> bool:
        async with self.lock:
            active = self.connections.setdefault(user_id, [])
            if len(active) >= get_settings().max_ws_connections_per_user:
                return False
            active.append(socket)
            return True

    async def remove(self, user_id: UUID, socket: WebSocket):
        async with self.lock:
            active = self.connections.get(user_id, [])
            if socket in active:
                active.remove(socket)
            if not active:
                self.connections.pop(user_id, None)

    async def relay(self, user_id: UUID, payload: dict):
        for socket in list(self.connections.get(user_id, [])):
            try:
                await socket.send_json(payload)
            except (RuntimeError, WebSocketDisconnect):
                await self.remove(user_id, socket)


manager = ConnectionManager()


def message_output(message: EncryptedMessage) -> dict:
    return {"type": "message", "id": str(message.id), "sender_id": str(message.sender_id),
            "recipient_id": str(message.recipient_id), "algorithm": message.algorithm,
            "ephemeral_public_key": b64(message.ephemeral_public_key),
            "nonce": b64(message.nonce), "ciphertext": b64(message.ciphertext),
            "signature": b64(message.signature)}


def parse_message(data: dict, sender: User, session: Session) -> EncryptedMessage:
    allowed = {"type", "recipient_id", "algorithm", "ephemeral_public_key", "nonce",
               "ciphertext", "signature"}
    if set(data) != allowed or data.get("type") != "send" or data.get("algorithm") != ALGORITHM:
        raise ValueError("Formato de mensagem inválido")
    recipient_id = UUID(data["recipient_id"])
    recipient = session.get(User, recipient_id)
    if recipient is None or not recipient.is_active or recipient_id == sender.id:
        raise ValueError("Destinatário inválido")
    nonce, ephemeral, ciphertext, signature = (
        unb64(data[name]) for name in ("nonce", "ephemeral_public_key", "ciphertext", "signature")
    )
    if len(nonce) != 12 or len(ephemeral) != 32 or len(signature) != 64 or not 16 <= len(ciphertext) <= get_settings().max_message_bytes:
        raise ValueError("Tamanho de mensagem inválido")
    x25519.X25519PublicKey.from_public_bytes(ephemeral)
    signing = session.exec(select(PublicKey).where(PublicKey.user_id == sender.id,
                                                  PublicKey.is_active == True)).first()  # noqa: E712
    if signing is None:
        raise ValueError("Chave do remetente ausente")
    signed = {**data, "sender_id": str(sender.id), "recipient_id": str(recipient_id)}
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(signing.signing_public_key).verify(
            signature, _signed_bytes(signed))
    except Exception as exc:
        raise ValueError("Assinatura inválida") from exc
    now = datetime.now(timezone.utc)
    session.exec(delete(EncryptedMessage).where(EncryptedMessage.expires_at < now))
    pending_count = session.exec(select(func.count()).select_from(EncryptedMessage).where(
        EncryptedMessage.recipient_id == recipient_id,
        EncryptedMessage.status == MessageStatus.PENDING,
    )).one()
    if pending_count >= get_settings().max_pending_messages_per_user:
        raise ValueError("Caixa de mensagens cheia")
    return EncryptedMessage(sender_id=sender.id, recipient_id=recipient_id,
                            nonce=nonce, ephemeral_public_key=ephemeral,
                            ciphertext=ciphertext, signature=signature, algorithm=ALGORITHM,
                            expires_at=now + timedelta(days=get_settings().message_retention_days))


@app.websocket("/ws")
async def websocket_chat(socket: WebSocket):
    await socket.accept()
    user: User | None = None
    connected = False
    ip = socket.client.host if socket.client else "unknown"
    reserved = False
    try:
        if not await ws_limiter.allow(f"handshake:{ip}"):
            await socket.close(code=1013)
            return
        try:
            await asyncio.wait_for(manager.slots.acquire(), timeout=0.05)
        except asyncio.TimeoutError:
            await socket.close(code=1013)
            return
        reserved = True
        raw = await asyncio.wait_for(socket.receive_text(), timeout=5)
        auth = json.loads(raw)
        if len(raw) > 4096 or set(auth) != {"type", "token"} or auth["type"] != "auth":
            await socket.close(code=1008)
            return
        with Session(get_engine()) as session:
            user = user_from_token(auth["token"], session)
        if user is None or not await manager.add(user.id, socket):
            await socket.close(code=1008)
            return
        connected = True
        with Session(get_engine()) as session:
            record(session, who=user.id, what="session.connect", where=ip,
                   why="websocket_authenticated", result=AuditResult.SUCCESS,
                   resource_type="user", resource_id=str(user.id))
            session.commit()
        await socket.send_json({"type": "ready", "user_id": str(user.id)})
        with Session(get_engine()) as session:
            session.exec(delete(EncryptedMessage).where(
                EncryptedMessage.expires_at < datetime.now(timezone.utc)))
            session.commit()
            pending = session.exec(select(EncryptedMessage).where(
                EncryptedMessage.recipient_id == user.id,
                EncryptedMessage.status == MessageStatus.PENDING,
            ).order_by(EncryptedMessage.created_at).limit(100)).all()
            for item in pending:
                await socket.send_json(message_output(item))
        while True:
            raw = await asyncio.wait_for(socket.receive_text(), timeout=300)
            if len(raw) > 24000 or not await ws_limiter.allow(str(user.id)):
                await socket.send_json({"type": "error", "detail": "Limite excedido"})
                continue
            try:
                data = json.loads(raw)
                if not isinstance(data, dict):
                    raise ValueError("Formato inválido")
                with Session(get_engine()) as session:
                    if user_from_token(auth["token"], session) is None:
                        await socket.close(code=1008)
                        break
                    if data.get("type") == "send":
                        message = parse_message(data, user, session)
                        session.add(message)
                        record(session, who=user.id, what="message.send", where=ip,
                               why="user_request", result=AuditResult.SUCCESS,
                               resource_type="message", resource_id=str(message.id))
                        session.commit()
                        await socket.send_json({"type": "sent", "id": str(message.id)})
                        await manager.relay(message.recipient_id, message_output(message))
                    elif data.get("type") == "ack" and set(data) == {"type", "id"}:
                        message = session.get(EncryptedMessage, UUID(data["id"]))
                        if message is None or message.recipient_id != user.id:
                            raise ValueError("Mensagem não encontrada")
                        session.delete(message)
                        record(session, who=user.id, what="message.delivered", where=ip,
                               why="recipient_acknowledged", result=AuditResult.SUCCESS,
                               resource_type="message", resource_id=str(message.id))
                        session.commit()
                        await socket.send_json({"type": "acked", "id": data["id"]})
                    else:
                        raise ValueError("Operação inválida")
            except (ValueError, TypeError, KeyError, json.JSONDecodeError):
                await socket.send_json({"type": "error", "detail": "Mensagem inválida"})
    except (WebSocketDisconnect, asyncio.TimeoutError, json.JSONDecodeError, ValueError, TypeError):
        pass
    finally:
        if connected and user is not None:
            await manager.remove(user.id, socket)
            with Session(get_engine()) as session:
                record(session, who=user.id, what="session.disconnect", where=ip,
                       why="websocket_closed", result=AuditResult.SUCCESS,
                       resource_type="user", resource_id=str(user.id))
                session.commit()
        if reserved:
            manager.slots.release()
