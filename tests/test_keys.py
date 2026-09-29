import base64
import hashlib
import threading
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import x25519
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError
from sqlmodel import select

from seguranca_auditoria.models import PublicKey, User

PASSWORD = "senha-ficticia-123"


def new_key() -> tuple[str, bytes]:
    raw = x25519.X25519PrivateKey.generate().public_key().public_bytes_raw()
    return base64.b64encode(raw).decode(), raw


def make_user(client, name: str) -> dict:
    body = {"username": name, "email": f"{name}@example.com", "password": PASSWORD}
    user = client.post("/auth/register", json=body).json()
    token = client.post(
        "/auth/login", json={"username": name, "password": PASSWORD}
    ).json()["access_token"]
    return {"id": user["id"], "headers": {"Authorization": f"Bearer {token}"}}


@pytest.fixture
def alice(client):
    return make_user(client, "alice")


@pytest.fixture
def bob(client):
    return make_user(client, "bob")


def post_key(client, user, public_key=None, **extra):
    body = {"algorithm": "X25519", "public_key": new_key()[0] if public_key is None else public_key, **extra}
    return client.post("/keys", json=body, headers=user["headers"])


# ---------- register ----------

def test_register_key_success_and_fingerprint(client, session, alice):
    b64, raw = new_key()
    r = post_key(client, alice, b64)
    assert r.status_code == 201
    body = r.json()
    assert set(body) == {"id", "algorithm", "public_key", "fingerprint", "is_active", "created_at", "revoked_at"}
    assert body["public_key"] == b64 and body["algorithm"] == "X25519"
    assert body["is_active"] is True and body["revoked_at"] is None
    assert body["fingerprint"] == hashlib.sha256(raw).hexdigest()
    row = session.exec(select(PublicKey)).one()
    assert str(row.user_id) == alice["id"] and row.public_key == raw


def test_register_requires_authentication(client):
    body = {"algorithm": "X25519", "public_key": new_key()[0]}
    assert client.post("/keys", json=body).status_code == 401
    assert client.post("/keys", json=body, headers={"Authorization": "Bearer x.y.z"}).status_code == 401


ZERO = base64.b64encode(bytes(32)).decode()


@pytest.mark.parametrize(
    "public_key",
    [
        "not base64!!",
        "AAAA",  # valid Base64, 3 bytes
        base64.b64encode(b"x" * 31).decode(),
        base64.b64encode(b"x" * 33).decode(),
        "",
        new_key()[0].rstrip("="),  # missing padding
        new_key()[0] + "\n",
        ZERO,  # small-order point
    ],
)
def test_register_rejects_malformed_keys(client, session, alice, public_key):
    r = post_key(client, alice, public_key)
    assert r.status_code == 422, r.text
    assert session.exec(select(PublicKey)).all() == []


def test_register_rejects_non_canonical_base64(client, alice):
    b64, _ = new_key()
    # Flip the unused low bits of the last character before the padding "=".
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    last = alphabet.index(b64[42])
    tweaked = b64[:42] + alphabet[last ^ 1] + "="
    assert tweaked != b64 and base64.b64decode(tweaked) == base64.b64decode(b64)
    assert post_key(client, alice, tweaked).status_code == 422


@pytest.mark.parametrize("algorithm", ["RSA", "Ed25519", "x25519", ""])
def test_register_rejects_unsupported_algorithm(client, alice, algorithm):
    r = client.post("/keys", json={"algorithm": algorithm, "public_key": new_key()[0]}, headers=alice["headers"])
    assert r.status_code == 422


def test_register_missing_algorithm(client, alice):
    r = client.post("/keys", json={"public_key": new_key()[0]}, headers=alice["headers"])
    assert r.status_code == 422


@pytest.mark.parametrize(
    "extra",
    [
        {"user_id": str(uuid4())},
        {"fingerprint": "a" * 64},
        {"is_active": False},
        {"revoked_at": "2020-01-01T00:00:00Z"},
        {"id": str(uuid4())},
    ],
)
def test_register_rejects_internal_fields(client, session, alice, extra):
    assert post_key(client, alice, **extra).status_code == 422
    assert session.exec(select(PublicKey)).all() == []


def test_register_same_active_key_is_idempotent(client, session, alice):
    b64, _ = new_key()
    first = post_key(client, alice, b64)
    second = post_key(client, alice, b64)
    assert (first.status_code, second.status_code) == (201, 200)
    assert first.json() == second.json()
    assert len(session.exec(select(PublicKey)).all()) == 1


def test_register_second_active_key_conflicts(client, session, alice):
    assert post_key(client, alice).status_code == 201
    r = post_key(client, alice)
    assert r.status_code == 409 and "revoke" in r.json()["detail"]
    assert len(session.exec(select(PublicKey)).all()) == 1


def test_register_key_owned_by_another_user_conflicts(client, alice, bob):
    b64, _ = new_key()
    assert post_key(client, alice, b64).status_code == 201
    assert post_key(client, bob, b64).status_code == 409


# ---------- concurrency ----------

def run_concurrently(app, users_and_keys):
    results = [None] * len(users_and_keys)
    barrier = threading.Barrier(len(users_and_keys))

    def worker(i, user, b64):
        with TestClient(app) as c:
            barrier.wait()
            results[i] = c.post(
                "/keys", json={"algorithm": "X25519", "public_key": b64}, headers=user["headers"]
            ).status_code

    threads = [threading.Thread(target=worker, args=(i, u, k)) for i, (u, k) in enumerate(users_and_keys)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    return results


def test_concurrent_distinct_keys_leave_one_active(client, session, alice):
    from seguranca_auditoria.main import app

    results = run_concurrently(app, [(alice, new_key()[0]) for _ in range(8)])
    assert sorted(results) == [201] + [409] * 7
    session.expire_all()
    assert len(session.exec(select(PublicKey).where(PublicKey.is_active)).all()) == 1


def test_concurrent_same_key_creates_single_record(client, session, alice):
    from seguranca_auditoria.main import app

    b64, _ = new_key()
    results = run_concurrently(app, [(alice, b64)] * 8)
    assert sorted(results) == [200] * 7 + [201]
    session.expire_all()
    assert len(session.exec(select(PublicKey)).all()) == 1


def test_database_rejects_two_active_keys_for_one_user(client, session, alice):
    user = session.exec(select(User)).one()
    for i in range(2):
        session.add(PublicKey(user_id=user.id, public_key=bytes([i]) * 32, fingerprint=f"fp{i}"))
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


# ---------- queries ----------

def test_list_own_keys_includes_revoked_and_is_private(client, alice, bob):
    first = post_key(client, alice).json()
    client.post(f"/keys/{first['id']}/revoke", headers=alice["headers"])
    second = post_key(client, alice).json()
    post_key(client, bob)
    r = client.get("/keys/me", headers=alice["headers"])
    assert r.status_code == 200
    by_id = {k["id"]: k for k in r.json()}
    assert set(by_id) == {first["id"], second["id"]}
    assert by_id[first["id"]]["is_active"] is False and by_id[first["id"]]["revoked_at"]
    assert by_id[second["id"]]["is_active"] is True
    assert client.get("/keys/me").status_code == 401


def test_get_active_key_of_another_user(client, alice, bob):
    key = post_key(client, bob).json()
    r = client.get(f"/users/{bob['id']}/keys/active", headers=alice["headers"])
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"id", "user_id", "algorithm", "public_key", "fingerprint", "created_at"}
    assert body["id"] == key["id"] and body["user_id"] == bob["id"]
    assert client.get(f"/users/{bob['id']}/keys/active").status_code == 401


def test_get_active_key_not_found_cases_look_the_same(client, session, alice, bob):
    responses = [
        client.get(f"/users/{uuid4()}/keys/active", headers=alice["headers"]),  # unknown user
        client.get(f"/users/{bob['id']}/keys/active", headers=alice["headers"]),  # no key
    ]
    key = post_key(client, bob).json()
    client.post(f"/keys/{key['id']}/revoke", headers=bob["headers"])
    responses.append(client.get(f"/users/{bob['id']}/keys/active", headers=alice["headers"]))  # revoked
    post_key(client, bob)
    bob_user = session.exec(select(User).where(User.username == "bob")).one()
    bob_user.is_active = False
    session.add(bob_user)
    session.commit()
    responses.append(client.get(f"/users/{bob['id']}/keys/active", headers=alice["headers"]))  # inactive user
    assert {r.status_code for r in responses} == {404}
    assert len({r.text for r in responses}) == 1


def test_get_active_key_invalid_uuid(client, alice):
    assert client.get("/users/nope/keys/active", headers=alice["headers"]).status_code == 422


# ---------- revoke ----------

def test_owner_can_revoke_and_record_is_kept(client, session, alice):
    key = post_key(client, alice).json()
    r = client.post(f"/keys/{key['id']}/revoke", headers=alice["headers"])
    assert r.status_code == 200
    assert r.json()["is_active"] is False and r.json()["revoked_at"].endswith(("Z", "+00:00"))
    row = session.exec(select(PublicKey)).one()
    assert row.is_active is False and row.revoked_at is not None
    assert client.get(f"/users/{alice['id']}/keys/active", headers=alice["headers"]).status_code == 404


def test_revoke_by_other_user_is_not_found_and_changes_nothing(client, session, alice, bob):
    key = post_key(client, alice).json()
    r = client.post(f"/keys/{key['id']}/revoke", headers=bob["headers"], json={"user_id": bob["id"]})
    assert r.status_code == 404
    assert client.post(f"/keys/{uuid4()}/revoke", headers=bob["headers"]).status_code == 404
    session.expire_all()
    assert session.exec(select(PublicKey)).one().is_active is True


def test_revoke_requires_authentication(client, alice):
    key = post_key(client, alice).json()
    assert client.post(f"/keys/{key['id']}/revoke").status_code == 401


def test_revoke_is_idempotent_and_keeps_first_timestamp(client, alice):
    key = post_key(client, alice).json()
    first = client.post(f"/keys/{key['id']}/revoke", headers=alice["headers"])
    second = client.post(f"/keys/{key['id']}/revoke", headers=alice["headers"])
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()


def test_new_key_after_revocation_and_no_reactivation(client, session, alice):
    old_b64, _ = new_key()
    old = post_key(client, alice, old_b64).json()
    client.post(f"/keys/{old['id']}/revoke", headers=alice["headers"])

    # A different key can now be registered...
    new = post_key(client, alice)
    assert new.status_code == 201 and new.json()["id"] != old["id"]
    # ...but the revoked one cannot come back, even after revoking the new one.
    assert post_key(client, alice, old_b64).status_code == 409
    client.post(f"/keys/{new.json()['id']}/revoke", headers=alice["headers"])
    r = post_key(client, alice, old_b64)
    assert r.status_code == 409 and "revoked" in r.json()["detail"]
    session.expire_all()
    assert all(not k.is_active for k in session.exec(select(PublicKey)).all())
