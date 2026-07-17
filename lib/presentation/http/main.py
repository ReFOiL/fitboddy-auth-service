from __future__ import annotations

from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI

from application.commands import BootstrapPlatformAdminCommand
from application.config import Settings
from application.errors import AuthError
from application.runtime import AuthApplicationRuntime
from presentation.http.error_translator import ErrorTranslator
from presentation.http.handlers.auth_handler import AuthHttpHandler
from presentation.http.request_factory import AuthRequestFactory
from presentation.http.response_factory import AuthResponseFactory
from presentation.http.routes.admin_routes import AdminRoutes
from presentation.http.routes.auth_routes import AuthRoutes
from presentation.http.routes.system_routes import SystemRoutes

logger = logging.getLogger(__name__)


def _bootstrap_platform_admin(runtime: AuthApplicationRuntime, settings: Settings) -> None:
    login = (settings.platform_admin_login or "").strip()
    password = settings.platform_admin_password or ""
    email = (settings.platform_admin_email or "").strip()
    if not login or not password or not email:
        return
    try:
        with runtime.auth_service_scope() as auth_service:
            created = auth_service.bootstrap_platform_admin(
                BootstrapPlatformAdminCommand(login=login, email=email, password=password)
            )
            if created is not None:
                logger.info("Bootstrapped platform_admin user login=%s", created.login)
    except AuthError:
        logger.exception("Failed to bootstrap platform_admin user")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = Settings()
    runtime = AuthApplicationRuntime(settings)
    _bootstrap_platform_admin(runtime, settings)
    app.state.auth_handler = AuthHttpHandler(
        runtime=runtime,
        response_factory=AuthResponseFactory(),
        error_translator=ErrorTranslator(),
        request_factory=AuthRequestFactory(),
    )
    try:
        yield
    finally:
        runtime.shutdown()


app = FastAPI(title="auth-service", version="0.1.0", lifespan=lifespan)
app.include_router(SystemRoutes().router)
app.include_router(AuthRoutes().router)
app.include_router(AdminRoutes().router)
