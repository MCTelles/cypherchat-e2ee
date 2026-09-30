from functools import lru_cache
from typing import Literal

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    @model_validator(mode="after")
    def validate_security(self) -> "Settings":
        secret = self.jwt_secret_key.get_secret_value()
        if len(secret) < 32 or secret.startswith("SUBSTITUA_"):
            raise ValueError("JWT_SECRET_KEY deve ser aleatório e ter pelo menos 32 caracteres")
        if self.app_env == "production" and not self.database_url.startswith("postgresql+psycopg://"):
            raise ValueError("Produção exige PostgreSQL")
        if not 1 <= self.max_pending_messages_per_user <= 1000 or not 1 <= self.message_retention_days <= 30:
            raise ValueError("Limites de fila ou retenção inválidos")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
