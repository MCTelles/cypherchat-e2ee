from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest
from sqlmodel import select

from seguranca_auditoria.models import User, UserRole
from seguranca_auditoria.security import passwords
from conftest import TEST_JWT_SECRET

PASSWORD = "senha-ficticia-123"
USER = {"username": "alice", "email": "alice@example.com", "password": PASSWORD}


def register(client, **overrides):
    return client.post("/auth/register", json={**USER, **overrides})


def login(client, username="alice", password=PASSWORD):
    return client.post("/auth/login", json={"username": username, "password": password})


def token_for(client) -> str:
    register(client)
    return login(client).json()["access_token"]


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def forge(claims: dict, secret: str = TEST_JWT_SECRET, algorithm: str = "HS256") -> str:
    return jwt.encode(claims, secret, algorithm=algorithm)


def good_claims(sub=None) -> dict:
    now = datetime.now(UTC)
    return {"sub": str(sub or uuid4()), "iat": now, "exp": now + timedelta(minutes=5)}


# ---------- register ----------

def test_register_creates_user_with_argon2_hash(client, session):
    r = register(client)
    assert r.status_code == 201
    body = r.json()
    assert body["username"] == "alice" and body["role"] == "user"
    assert set(body) == {"id", "username", "email", "role", "created_at"}
    assert PASSWORD not in r.text and "hash" not in r.text and "argon2" not in r.text
    user = session.exec(select(User)).one()
    assert user.password_hash.startswith("$argon2") and PASSWORD not in user.password_hash
    assert user.role == UserRole.USER and user.is_active


def test_register_normalizes_username_and_email(client, session):
    r = register(client, username="  Alice  ", email="Alice@Example.COM")
    assert r.status_code == 201
    assert r.json()["username"] == "alice" and r.json()["email"] == "alice@example.com"


def test_register_duplicate_username_and_email_return_409(client, session):
    assert register(client).status_code == 201
    assert register(client, email="other@example.com").status_code == 409
    assert register(client, username="other").status_code == 409
    assert register(client, username="ALICE", email="x@example.com").status_code == 409
    assert len(session.exec(select(User)).all()) == 1
    # Session still usable after the rollback.
    assert register(client, username="bob", email="bob@example.com").status_code == 201


@pytest.mark.parametrize("field", ["role", "is_active", "password_hash", "id"])
def test_register_rejects_internal_fields(client, session, field):
    value = "admin" if field == "role" else "x"
    r = register(client, **{field: value})
    assert r.status_code == 422
    assert session.exec(select(User)).all() == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"username": "ab"},
        {"username": "a" * 51},
        {"username": "bad name!"},
        {"email": "not-an-email"},
        {"password": "curta"},
        {"password": "x" * 129},
        {"password": " " * 20},
    ],
)
def test_register_validation_errors_do_not_echo_input(client, overrides):
    r = register(client, **overrides)
    assert r.status_code == 422
    for error in r.json()["detail"]:
        assert set(error) == {"loc", "msg", "type"}
    if "password" in overrides:
        assert overrides["password"].strip() == "" or overrides["password"] not in r.text


# ---------- login ----------

def test_login_success_returns_bearer_token(client):
    register(client)
    r = login(client)
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer" and body["access_token"]
    claims = jwt.decode(body["access_token"], TEST_JWT_SECRET, algorithms=["HS256"])
    assert set(claims) == {"sub", "iat", "exp"}
    assert claims["exp"] - claims["iat"] == 30 * 60


def test_login_is_case_insensitive_on_username(client):
    register(client)
    assert login(client, username="ALICE").status_code == 200


def test_login_failures_share_generic_response(client, session):
    register(client)
    register(client, username="inactive", email="i@example.com")
    inactive = session.exec(select(User).where(User.username == "inactive")).one()
    inactive.is_active = False
    session.add(inactive)
    session.commit()

    responses = [
        login(client, password="senha-errada-123"),
        login(client, username="ghost"),
        login(client, username="inactive"),
    ]
    assert {r.status_code for r in responses} == {401}
    assert len({r.text for r in responses}) == 1
    assert responses[0].json() == {"detail": "Invalid credentials"}
    assert responses[0].headers["www-authenticate"] == "Bearer"


def test_login_verifies_a_hash_even_for_unknown_user(client, monkeypatch):
    calls = []
    real = passwords.verify_dummy_password
    monkeypatch.setattr(passwords, "verify_dummy_password", lambda p: (calls.append(1), real(p)))
    assert login(client, username="ghost").status_code == 401
    assert calls == [1]


# ---------- /auth/me ----------

def test_me_returns_own_public_profile(client):
    token = token_for(client)
    r = client.get("/auth/me", headers=bearer(token))
    assert r.status_code == 200
    assert r.json()["username"] == "alice"
    assert set(r.json()) == {"id", "username", "email", "role", "created_at"}
    assert PASSWORD not in r.text and "hash" not in r.text


def assert_401(r):
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


def test_me_without_token(client):
    assert_401(client.get("/auth/me"))


def test_me_with_wrong_scheme_or_garbage(client):
    assert_401(client.get("/auth/me", headers={"Authorization": "Basic abc"}))
    assert_401(client.get("/auth/me", headers=bearer("not.a.jwt")))


def test_me_with_tampered_token(client):
    token = token_for(client)
    head, payload, sig = token.split(".")
    assert_401(client.get("/auth/me", headers=bearer(f"{head}.{payload}.{sig[:-2]}xx")))
    assert_401(client.get("/auth/me", headers=bearer(forge(good_claims(), secret="x" * 40))))


def test_me_with_expired_token(client, session):
    register(client)
    user = session.exec(select(User)).one()
    now = datetime.now(UTC)
    claims = {"sub": str(user.id), "iat": now - timedelta(hours=2), "exp": now - timedelta(hours=1)}
    assert_401(client.get("/auth/me", headers=bearer(forge(claims))))


def test_me_rejects_alg_none_and_other_algorithms(client, session):
    register(client)
    user = session.exec(select(User)).one()
    claims = good_claims(user.id)
    assert forge(claims)  # sanity: the same claims are valid with HS256
    assert client.get("/auth/me", headers=bearer(forge(claims))).status_code == 200
    unsigned = jwt.encode(claims, None, algorithm="none")
    assert_401(client.get("/auth/me", headers=bearer(unsigned)))
    assert_401(client.get("/auth/me", headers=bearer(forge(claims, algorithm="HS512", secret=TEST_JWT_SECRET * 2))))


@pytest.mark.parametrize("missing", ["sub", "iat", "exp"])
def test_me_with_missing_required_claim(client, session, missing):
    register(client)
    user = session.exec(select(User)).one()
    claims = good_claims(user.id)
    del claims[missing]
    assert_401(client.get("/auth/me", headers=bearer(forge(claims))))


@pytest.mark.parametrize("sub", ["not-a-uuid", "", "123", 42])
def test_me_with_invalid_sub(client, sub):
    claims = good_claims()
    claims["sub"] = sub
    assert_401(client.get("/auth/me", headers=bearer(forge(claims))))


def test_me_with_unknown_user_id(client):
    assert_401(client.get("/auth/me", headers=bearer(forge(good_claims()))))


def test_token_of_deleted_user_is_rejected(client, session):
    token = token_for(client)
    session.delete(session.exec(select(User)).one())
    session.commit()
    assert_401(client.get("/auth/me", headers=bearer(token)))


def test_token_of_deactivated_user_is_rejected(client, session):
    token = token_for(client)
    user = session.exec(select(User)).one()
    user.is_active = False
    session.add(user)
    session.commit()
    assert_401(client.get("/auth/me", headers=bearer(token)))


def test_role_comes_from_database_not_token(client, session):
    token = token_for(client)
    user = session.exec(select(User)).one()
    user.role = UserRole.ADMIN
    session.add(user)
    session.commit()
    assert client.get("/auth/me", headers=bearer(token)).json()["role"] == "admin"
