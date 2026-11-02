from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Старый default из кода. Он длиннее 32 байт, поэтому длина сама по себе его не отсекает.
INSECURE_JWT_SECRET = "auth_service_dev_secret_change_me"
MIN_JWT_SECRET_BYTES = 32
# Асимметричной подписи ещё нет: другой alg позволяет подменить алгоритм.
PINNED_JWT_ALGORITHM = "HS256"

MIN_ACCESS_TOKEN_TTL_MINUTES = 1
MAX_ACCESS_TOKEN_TTL_MINUTES = 60
MIN_REFRESH_TOKEN_TTL_MINUTES = 5
MAX_REFRESH_TOKEN_TTL_MINUTES = 30 * 24 * 60
MAX_ACCESS_TOKEN_LIFETIME_SECONDS = MAX_ACCESS_TOKEN_TTL_MINUTES * 60
# verify_token общий для access и refresh, поэтому жёсткий потолок — срок refresh.
MAX_TOKEN_LIFETIME_SECONDS = MAX_REFRESH_TOKEN_TTL_MINUTES * 60


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = Field(default="sqlite+pysqlite:///./auth_service.db", alias="DATABASE_URL")
    jwt_secret: str = Field(alias="JWT_SECRET")
    jwt_algorithm: str = Field(default=PINNED_JWT_ALGORITHM, alias="JWT_ALGORITHM")
    access_token_ttl_minutes: int = Field(
        default=15,
        alias="ACCESS_TOKEN_TTL_MINUTES",
        ge=MIN_ACCESS_TOKEN_TTL_MINUTES,
        le=MAX_ACCESS_TOKEN_TTL_MINUTES,
    )
    refresh_token_ttl_minutes: int = Field(
        default=10080,
        alias="REFRESH_TOKEN_TTL_MINUTES",
        ge=MIN_REFRESH_TOKEN_TTL_MINUTES,
        le=MAX_REFRESH_TOKEN_TTL_MINUTES,
    )
    tenant_service_url: str = Field(default="http://tenant-service", alias="TENANT_SERVICE_URL")
    http_timeout_seconds: float = Field(default=5.0, alias="HTTP_TIMEOUT_SECONDS", gt=0)
    marketplace_profile_sync_enabled: bool = Field(default=True, alias="MARKETPLACE_PROFILE_SYNC_ENABLED")
    alembic_ini_path: str = Field(default="alembic.ini", alias="ALEMBIC_INI_PATH")
    platform_admin_login: str | None = Field(default=None, alias="PLATFORM_ADMIN_LOGIN")
    platform_admin_password: str | None = Field(default=None, alias="PLATFORM_ADMIN_PASSWORD")
    platform_admin_email: str | None = Field(default=None, alias="PLATFORM_ADMIN_EMAIL")

    @field_validator("jwt_secret")
    @classmethod
    def jwt_secret_must_be_usable(cls, value: str) -> str:
        if value == INSECURE_JWT_SECRET:
            raise ValueError("JWT_SECRET must not be the shipped default.")
        if len(value.encode("utf-8")) < MIN_JWT_SECRET_BYTES:
            raise ValueError(f"JWT_SECRET must be at least {MIN_JWT_SECRET_BYTES} bytes.")
        return value

    @field_validator("jwt_algorithm")
    @classmethod
    def jwt_algorithm_must_stay_hs256(cls, value: str) -> str:
        if value != PINNED_JWT_ALGORITHM:
            raise ValueError("JWT_ALGORITHM must be HS256 until asymmetric signing exists.")
        return value
