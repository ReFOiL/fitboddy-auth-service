from fastapi import APIRouter, Header, Query, Request, status

from presentation.http.schemas import (
    AuthResponse,
    CheckRequest,
    ClientLookupResponse,
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
        # Префикс /api/v1/auth шлюз уже проксирует на auth-service, отдельный location не нужен.
        self.router.add_api_route(
            "/clients/by-login",
            self.lookup_client_by_login,
            methods=["GET"],
            response_model=ClientLookupResponse,
            responses={
                401: {"description": "Missing or invalid bearer token"},
                403: {"description": "Caller role is not trainer or platform_admin"},
                404: {"description": "No active client with this login"},
                422: {"description": "Login does not match ^[a-z0-9_.-]{3,32}$ after trim and lowercase"},
            },
        )
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

    def lookup_client_by_login(
        self,
        request: Request,
        authorization: str = Header(default="", alias="Authorization"),
        login: str = Query(),
    ) -> ClientLookupResponse:
        return request.app.state.auth_handler.lookup_client_by_login(authorization=authorization, login=login)

    def check(self, payload: CheckRequest, request: Request) -> UserResponse:
        return request.app.state.auth_handler.check(payload)

    def internal_summaries(self, payload: InternalUserSummariesRequest, request: Request) -> InternalUserSummariesResponse:
        return request.app.state.auth_handler.internal_summaries(payload)
