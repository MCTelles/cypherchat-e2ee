"""Test setup.

DB tests need TEST_DATABASE_URL pointing to a dedicated PostgreSQL database whose
name contains "test". The schema of that database is dropped and recreated, so
never point it at real data. Without it, DB tests are skipped.
"""

import os

import pytest
from sqlalchemy.engine import make_url

TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL")
TEST_JWT_SECRET = "test-only-secret-with-more-than-32-bytes!"

if TEST_DATABASE_URL and "test" not in (make_url(TEST_DATABASE_URL).database or ""):
    pytest.exit("TEST_DATABASE_URL must point to a database with 'test' in its name")

# Environment variables take precedence over any local .env file.
os.environ["APP_ENV"] = "test"
os.environ["DATABASE_URL"] = (
    TEST_DATABASE_URL or "postgresql+psycopg://unused:unused@127.0.0.1:1/unused_test"
)
os.environ["JWT_SECRET_KEY"] = TEST_JWT_SECRET
os.environ["ACCESS_TOKEN_EXPIRE_MINUTES"] = "30"


@pytest.fixture(scope="session")
def _schema():
    if not TEST_DATABASE_URL:
        pytest.skip("TEST_DATABASE_URL not set")
    from sqlmodel import SQLModel

    import seguranca_auditoria.models  # noqa: F401
    from seguranca_auditoria.database import get_engine

    engine = get_engine()
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    yield engine
    SQLModel.metadata.drop_all(engine)


@pytest.fixture
def session(_schema):
    from sqlmodel import Session, SQLModel

    # Clean state for every test.
    with Session(_schema) as s:
        for table in reversed(SQLModel.metadata.sorted_tables):
            s.execute(table.delete())
        s.commit()
    with Session(_schema) as s:
        yield s


@pytest.fixture
def client(session):
    from fastapi.testclient import TestClient

    from seguranca_auditoria.main import app

    with TestClient(app) as c:
        yield c
