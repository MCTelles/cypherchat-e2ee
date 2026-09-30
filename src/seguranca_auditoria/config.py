from functools import lru_cache
from typing import Literal

from pydantic import SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MIN_JWT_SECRET_BYTES = 32
_PLACEHOLDER_SECRETS = {
    "substitua_por_um_segredo",
    "changeme",
    "change-me",
    "change_me",
    "secret",
    "your-secret-key",
    "your_secret_key",
    "jwt_secret_key",
    "password",
}


class Settings(BaseSettings):
    """Configuration loaded from environment variables or a local .env file."""

    app_env: Literal["development", "test", "production"] = "development"
    database_url: str
    jwt_secret_key: SecretStr
    jwt_algorithm: Literal["HS256"] = "HS256"
    access_token_expire_minutes: int = 30
    log_level: str = "INFO"
    max_message_bytes: int = 8192
    max_ws_connections_per_user: int = 2
    max_pending_messages_per_user: int = 100
    message_retention_days: int = 7

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        hide_input_in_errors=True,
    )

    @field_validator("jwt_secret_key")
    @classmethod
    def _validate_jwt_secret(cls, value: SecretStr) -> SecretStr:
        secret = value.get_secret_value()
        normalized = secret.strip().lower()
        if not normalized:
            raise ValueError("JWT_SECRET_KEY must not be empty")
        if normalized in _PLACEHOLDER_SECRETS or normalized.startswith("substitua"):
            raise ValueError("JWT_SECRET_KEY must not be a placeholder value")
        if len(secret.encode("utf-8")) < MIN_JWT_SECRET_BYTES:
            raise ValueError(
                f"JWT_SECRET_KEY must have at least {MIN_JWT_SECRET_BYTES} bytes"
            )
        return value

    @field_validator("access_token_expire_minutes")
    @classmethod
    def _validate_expiration(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("ACCESS_TOKEN_EXPIRE_MINUTES must be positive")
        return value

    @model_validator(mode="after")
    def validate_security(self) -> "Settings":
        if self.app_env == "production" and not self.database_url.startswith("postgresql+psycopg://"):
            raise ValueError("Produção exige PostgreSQL")
        if not 1 <= self.max_pending_messages_per_user <= 1000 or not 1 <= self.message_retention_days <= 30:
            raise ValueError("Limites de fila ou retenção inválidos")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
