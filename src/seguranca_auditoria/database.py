from collections.abc import Generator
from functools import lru_cache

from sqlmodel import Session, SQLModel, create_engine

from seguranca_auditoria.config import get_settings


@lru_cache
def get_engine():
    settings = get_settings()
    return create_engine(
        settings.database_url,
        echo=False,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=0,
        pool_timeout=5,
    )


def create_db_and_tables() -> None:
    # Importing the package registers every table in SQLModel.metadata.
    import seguranca_auditoria.models  # noqa: F401

    SQLModel.metadata.create_all(get_engine())


def get_session() -> Generator[Session, None, None]:
    with Session(get_engine()) as session:
        yield session
