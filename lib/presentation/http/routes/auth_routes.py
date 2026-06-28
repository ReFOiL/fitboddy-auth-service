from fastapi import APIRouter, Header, Request, status

from presentation.http.schemas import (
    AuthResponse,
    CheckRequest,
    InternalUserSummariesRequest,
    InternalUserSummariesResponse,
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    RegisterRequest,
    TokenPairResponse,
    UserResponse,
)


class AuthRoutes:
    def __init__(self) -> None:
        self.router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
        self.router.add_api_route(
            "/register",
            self.register,
            methods=["POST"],
            response_model=AuthResponse,
            status_code=status.HTTP_201_CREATED,
        )
        self.router.add_api_route("/login", self.login, methods=["POST"], response_model=AuthResponse)
        self.router.add_api_route("/refresh", self.refresh, methods=["POST"], response_model=TokenPairResponse)
        self.router.add_api_route("/logout", self.logout, methods=["POST"], status_code=status.HTTP_204_NO_CONTENT)
        self.router.add_api_route("/me", self.me, methods=["GET"], response_model=UserResponse)
        self.router.add_api_route("/check", self.check, methods=["POST"], response_model=UserResponse)
        self.router.add_api_route(
            "/internal/summaries",
            self.internal_summaries,
            methods=["POST"],
            response_model=InternalUserSummariesResponse,
        )

    def register(self, payload: RegisterRequest, request: Request) -> AuthResponse:
        return request.app.state.auth_handler.register(payload)

    def login(self, payload: LoginRequest, request: Request) -> AuthResponse:
        return request.app.state.auth_handler.login(payload)

    def refresh(self, payload: RefreshRequest, request: Request) -> TokenPairResponse:
        return request.app.state.auth_handler.refresh(payload)

    def logout(self, payload: LogoutRequest, request: Request) -> None:
        request.app.state.auth_handler.logout(payload)

    def me(
        self,
        request: Request,
        authorization: str = Header(default="", alias="Authorization"),
    ) -> UserResponse:
        return request.app.state.auth_handler.me(authorization=authorization)

    def check(self, payload: CheckRequest, request: Request) -> UserResponse:
        return request.app.state.auth_handler.check(payload)

    def internal_summaries(self, payload: InternalUserSummariesRequest, request: Request) -> InternalUserSummariesResponse:
        return request.app.state.auth_handler.internal_summaries(payload)
