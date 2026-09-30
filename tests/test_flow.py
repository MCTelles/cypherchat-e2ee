"""Security and real-time flow checks with an isolated local database."""

import os
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session
from sqlmodel import select

os.environ.setdefault("DATABASE_URL", "sqlite:////private/tmp/cypherchat-test-bootstrap.db")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret-at-least-32-bytes-long")

from seguranca_auditoria.config import get_settings  # noqa: E402
from seguranca_auditoria.database import create_db_and_tables, get_engine  # noqa: E402
from seguranca_auditoria.main import app  # noqa: E402
from seguranca_auditoria.models import AuditLog, EncryptedMessage, User, UserRole  # noqa: E402
from seguranca_auditoria.rate_limit import http_limiter, login_limiter, ws_limiter  # noqa: E402
from seguranca_auditoria.security.e2ee import Identity, b64, decrypt, encrypt, unb64  # noqa: E402
from seguranca_auditoria.terminal_client import checked_public_keys  # noqa: E402


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'chat.db'}")
    get_settings.cache_clear()
    get_engine.cache_clear()
    create_db_and_tables()
    http_limiter.buckets.clear()
    login_limiter.buckets.clear()
    ws_limiter.buckets.clear()
    with TestClient(app) as test_client:
        yield test_client
    get_engine().dispose()
    get_engine.cache_clear()


def register(client, name):
    identity = Identity.generate()
    response = client.post("/auth/register", json={
        "username": name, "email": f"{name}@test.example", "password": "correct-horse-battery",
        "public_key": b64(identity.public_key),
        "signing_public_key": b64(identity.signing_public_key),
    })
    assert response.status_code == 201, response.text
    token_response = client.post("/auth/token", json={"username": name, "password": "correct-horse-battery"})
    assert token_response.status_code == 200, token_response.text
    return identity, response.json()["id"], token_response.json()["access_token"]


def test_e2ee_local_private_key_and_tamper_detection():
    from cryptography.exceptions import InvalidSignature

    alice, bob = Identity.generate(), Identity.generate()
    sender_id, recipient_id = UUID(int=1), UUID(int=2)
    protected = alice.protect("local-secret-password")
    assert alice.public_key not in protected
    assert Identity.unprotect(protected, "local-secret-password").fingerprint == alice.fingerprint
    message = encrypt(alice, bob.public_key, sender_id, recipient_id, "segredo")
    assert "segredo" not in str(message)
    assert decrypt(bob, alice.signing_public_key, message) == "segredo"
    message["recipient_id"] = str(UUID(int=3))
    with pytest.raises(InvalidSignature):
        decrypt(bob, alice.signing_public_key, message)


def test_roles_mass_assignment_and_message_relay(client):
    assert client.get("/ready").json() == {"status": "ready"}
    alice, alice_id, alice_token = register(client, "alice")
    bob, bob_id, bob_token = register(client, "bob")
    admin_route = client.get("/admin/users", headers={"Authorization": f"Bearer {alice_token}"})
    assert admin_route.status_code == 403
    assert client.patch("/me", headers={"Authorization": f"Bearer {alice_token}"},
                        json={"role": "admin"}).status_code == 422
    assert client.get("/users", headers={"Authorization": f"Bearer {alice_token}"}).json()[0]["id"] == bob_id
    envelope = encrypt(alice, bob.public_key, UUID(alice_id), UUID(bob_id), "oi Bob")
    outgoing = {"type": "send", **{key: value for key, value in envelope.items() if key != "sender_id"}}
    with client.websocket_connect("/ws") as alice_socket, client.websocket_connect("/ws") as bob_socket:
        alice_socket.send_json({"type": "auth", "token": alice_token})
        assert alice_socket.receive_json()["type"] == "ready"
        bob_socket.send_json({"type": "auth", "token": bob_token})
        assert bob_socket.receive_json()["type"] == "ready"
        alice_socket.send_json(outgoing)
        assert alice_socket.receive_json()["type"] == "sent"
        event = bob_socket.receive_json()
        assert event["type"] == "message"
        assert decrypt(bob, alice.signing_public_key, event) == "oi Bob"
        with Session(get_engine()) as session:
            stored = session.exec(select(EncryptedMessage)).one()
            assert b"oi Bob" not in stored.ciphertext
            assert stored.sender_id == UUID(alice_id)
            assert stored.recipient_id == UUID(bob_id)
        alice_socket.send_json({"type": "ack", "id": event["id"]})
        assert alice_socket.receive_json()["type"] == "error"
        bob_socket.send_json({"type": "ack", "id": event["id"]})
        assert bob_socket.receive_json() == {"type": "acked", "id": event["id"]}
        with Session(get_engine()) as session:
            assert session.exec(select(EncryptedMessage)).all() == []


def test_invalid_signature(client):
    alice, alice_id, alice_token = register(client, "alice")
    bob, bob_id, _ = register(client, "bob")
    envelope = encrypt(alice, bob.public_key, UUID(alice_id), UUID(bob_id), "hello")
    envelope["ciphertext"] = b64(b"changed")
    with client.websocket_connect("/ws") as socket:
        socket.send_json({"type": "auth", "token": alice_token})
        assert socket.receive_json()["type"] == "ready"
        socket.send_json({"type": "send", **{key: value for key, value in envelope.items() if key != "sender_id"}})
        assert socket.receive_json()["type"] == "error"


def test_admin_audit_and_deactivation(client):
    _, admin_id, admin_token = register(client, "admin")
    _, alice_id, alice_token = register(client, "alice")
    with Session(get_engine()) as session:
        account = session.get(User, UUID(admin_id))
        account.role = UserRole.ADMIN
        session.add(account)
        session.commit()
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    users = client.get("/admin/users", headers=admin_headers)
    assert users.status_code == 200
    assert len(users.json()) == 2
    assert client.delete(f"/admin/users/{alice_id}", headers=admin_headers).status_code == 204
    assert client.get("/me", headers={"Authorization": f"Bearer {alice_token}"}).status_code == 401
    audit = client.get("/admin/audit", headers=admin_headers)
    assert audit.status_code == 200
    events = audit.json()
    removal = next(event for event in events if event["what"] == "user.remove")
    assert removal["who"] == admin_id
    assert removal["resource_id"] == alice_id
    assert removal["where"] and removal["when"] and removal["why"]


def test_oversized_request_is_rejected(client):
    response = client.post("/auth/register", content=b"x" * 20000,
                           headers={"Content-Type": "application/json"})
    assert response.status_code == 413
    response = client.post("/auth/register", content=(b"x" * 10000 for _ in range(2)),
                           headers={"Content-Type": "application/json"})
    assert response.status_code == 413


def test_directory_fingerprint_must_match_key_material():
    from seguranca_auditoria.security.e2ee import ALGORITHM

    original, substituted = Identity.generate(), Identity.generate()
    forged = {"public_key": b64(substituted.public_key),
              "signing_public_key": b64(substituted.signing_public_key),
              "fingerprint": original.fingerprint, "algorithm": ALGORITHM}
    with pytest.raises(RuntimeError, match="fingerprint"):
        checked_public_keys(forged)


def test_rejects_noncanonical_base64():
    assert unb64("AA==") == b"\x00"
    with pytest.raises(ValueError, match="canônico"):
        unb64("AB==")


def test_unknown_user_still_verifies_password(client, monkeypatch):
    attempts = []
    monkeypatch.setattr("seguranca_auditoria.main.verify_dummy_password",
                        lambda password: attempts.append(password))
    response = client.post("/auth/token", json={"username": "missing", "password": "guess"})
    assert response.status_code == 401
    assert attempts == ["guess"]


def test_rejects_low_order_key_and_limits_login_attempts(client):
    identity = Identity.generate()
    response = client.post("/auth/register", json={
        "username": "invalidkey", "email": "invalidkey@test.example",
        "password": "correct-horse-battery", "public_key": b64(bytes(32)),
        "signing_public_key": b64(identity.signing_public_key),
    })
    assert response.status_code == 422
    register(client, "alice")
    login_limiter.buckets.clear()
    for _ in range(5):
        response = client.post("/auth/token", json={"username": "alice", "password": "wrong"})
        assert response.status_code == 401
    response = client.post("/auth/token", json={"username": "alice", "password": "wrong"})
    assert response.status_code == 429


def test_pending_queue_limit_and_expiration(client, monkeypatch):
    monkeypatch.setenv("MAX_PENDING_MESSAGES_PER_USER", "1")
    get_settings.cache_clear()
    alice, alice_id, alice_token = register(client, "alice")
    bob, bob_id, _ = register(client, "bob")
    with client.websocket_connect("/ws") as socket:
        socket.send_json({"type": "auth", "token": alice_token})
        assert socket.receive_json()["type"] == "ready"
        for expected in ("sent", "error"):
            envelope = encrypt(alice, bob.public_key, UUID(alice_id), UUID(bob_id), "pendente")
            socket.send_json({"type": "send", **{k: v for k, v in envelope.items()
                                                 if k != "sender_id"}})
            assert socket.receive_json()["type"] == expected
    with Session(get_engine()) as session:
        queued = session.exec(select(EncryptedMessage)).one()
        queued.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        session.add(queued)
        session.commit()
    bob_token = client.post("/auth/token", json={"username": "bob",
                                               "password": "correct-horse-battery"}).json()["access_token"]
    with client.websocket_connect("/ws") as socket:
        socket.send_json({"type": "auth", "token": bob_token})
        assert socket.receive_json()["type"] == "ready"
        with Session(get_engine()) as session:
            assert session.exec(select(EncryptedMessage)).all() == []


def test_registration_and_update_reject_extra_fields(client):
    identity = Identity.generate()
    response = client.post("/auth/register", json={
        "username": "mallory", "email": "mallory@test.example",
        "password": "correct-horse-battery", "public_key": b64(identity.public_key),
        "signing_public_key": b64(identity.signing_public_key), "role": "admin",
    })
    assert response.status_code == 422
    _, user_id, token = register(client, "alice")
    headers = {"Authorization": f"Bearer {token}"}
    assert client.patch("/me", headers=headers, json={"email": None}).status_code == 422
    response = client.patch("/me", headers=headers, json={"email": "newalice@test.example"})
    assert response.status_code == 200
    assert response.json()["email"] == "newalice@test.example"
    with Session(get_engine()) as session:
        event = session.exec(select(AuditLog).where(AuditLog.action == "user.update")).one()
        assert str(event.actor_user_id) == user_id
    assert client.post("/auth/token", json={"username": "' OR 1=1 --",
                                            "password": "anything"}).status_code == 422
