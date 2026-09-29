import pytest
from pydantic import ValidationError

from seguranca_auditoria.config import Settings

DB = "postgresql+psycopg://u:dbpassword@127.0.0.1:5432/x"


def make(secret: str, **kw) -> Settings:
    return Settings(_env_file=None, database_url=DB, jwt_secret_key=secret, **kw)


def test_valid_secret_is_accepted():
    assert make("a" * 32).jwt_secret_key.get_secret_value() == "a" * 32


@pytest.mark.parametrize(
    "secret",
    ["", "   ", "short", "a" * 31, "SUBSTITUA_POR_UM_SEGREDO", "changeme", "Substitua-por-um-segredo-longo-e-aleatorio-123"],
)
def test_invalid_secret_is_rejected_without_leaking_it(secret):
    with pytest.raises(ValidationError) as exc:
        make(secret)
    text = str(exc.value)
    assert "jwt_secret_key" in text
    if secret.strip():
        assert secret not in text
    assert "dbpassword" not in text


def test_non_positive_expiration_rejected():
    with pytest.raises(ValidationError):
        make("a" * 32, access_token_expire_minutes=0)
