from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = Field(default="sqlite+pysqlite:///./auth_service.db", alias="DATABASE_URL")
    jwt_secret: str = Field(default="auth_service_dev_secret_change_me", alias="JWT_SECRET")
    jwt_algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    access_token_ttl_minutes: int = Field(default=15, alias="ACCESS_TOKEN_TTL_MINUTES", ge=1)
    refresh_token_ttl_minutes: int = Field(default=10080, alias="REFRESH_TOKEN_TTL_MINUTES", ge=5)
    tenant_service_url: str = Field(default="http://tenant-service", alias="TENANT_SERVICE_URL")
    http_timeout_seconds: float = Field(default=5.0, alias="HTTP_TIMEOUT_SECONDS", gt=0)
    marketplace_profile_sync_enabled: bool = Field(default=True, alias="MARKETPLACE_PROFILE_SYNC_ENABLED")
    alembic_ini_path: str = Field(default="alembic.ini", alias="ALEMBIC_INI_PATH")
    platform_admin_login: str | None = Field(default=None, alias="PLATFORM_ADMIN_LOGIN")
    platform_admin_password: str | None = Field(default=None, alias="PLATFORM_ADMIN_PASSWORD")
    platform_admin_email: str | None = Field(default=None, alias="PLATFORM_ADMIN_EMAIL")
