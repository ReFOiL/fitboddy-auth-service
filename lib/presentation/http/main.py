from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from application.config import Settings
from application.runtime import AuthApplicationRuntime
from presentation.http.error_translator import ErrorTranslator
from presentation.http.handlers.auth_handler import AuthHttpHandler
from presentation.http.request_factory import AuthRequestFactory
from presentation.http.response_factory import AuthResponseFactory
from presentation.http.routes.auth_routes import AuthRoutes
from presentation.http.routes.system_routes import SystemRoutes


@asynccontextmanager
async def lifespan(app: FastAPI):
    runtime = AuthApplicationRuntime(Settings())
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
