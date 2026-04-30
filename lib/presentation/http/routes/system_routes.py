from fastapi import APIRouter, Request
from presentation.http.schemas import HealthResponse


class SystemRoutes:
    def __init__(self) -> None:
        self.router = APIRouter()
        self.router.add_api_route("/health", self.health, methods=["GET"], response_model=HealthResponse)
        self.router.add_api_route("/ready", self.ready, methods=["GET"], response_model=HealthResponse)

    def health(self, request: Request) -> HealthResponse:
        return request.app.state.auth_handler.health()

    def ready(self, request: Request) -> HealthResponse:
        return request.app.state.auth_handler.ready()
