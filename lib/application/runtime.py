from __future__ import annotations

from contextlib import contextmanager
from typing import Generator

import httpx
from sqlalchemy import text

from application.config import Settings
from application.db import DatabaseManager
from application.gateways import MarketplaceGateway
from application.security import JwtService, PasswordService
from application.use_cases import AuthService


class AuthApplicationRuntime:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._database = DatabaseManager(settings.database_url)
        self._jwt_service = JwtService(secret=settings.jwt_secret, algorithm=settings.jwt_algorithm)
        self._password_service = PasswordService()
        self._http_client = httpx.Client(timeout=settings.http_timeout_seconds)
        self._marketplace_gateway = MarketplaceGateway(
            http_client=self._http_client,
            tenant_service_url=settings.tenant_service_url,
        )

    @contextmanager
    def auth_service_scope(self) -> Generator[AuthService, None, None]:
        session = self._database.create_session()
        try:
            yield AuthService(
                session=session,
                jwt_service=self._jwt_service,
                password_service=self._password_service,
                access_ttl_minutes=self._settings.access_token_ttl_minutes,
                refresh_ttl_minutes=self._settings.refresh_token_ttl_minutes,
                marketplace_gateway=self._marketplace_gateway,
                marketplace_profile_sync_enabled=self._settings.marketplace_profile_sync_enabled,
            )
        finally:
            session.close()

    def check_ready(self) -> None:
        session = self._database.create_session()
        try:
            session.execute(text("SELECT 1"))
        finally:
            session.close()

    def shutdown(self) -> None:
        self._http_client.close()
        self._database.dispose()
