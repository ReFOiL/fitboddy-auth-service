from fastapi import HTTPException, status

from application.commands import GetUserCommand, ListUsersCommand, PatchUserCommand
from application.errors import AuthError
from application.runtime import AuthApplicationRuntime
from presentation.http.error_translator import ErrorTranslator
from presentation.http.request_factory import AuthRequestFactory
from presentation.http.response_factory import AuthResponseFactory
from presentation.http.schemas import (
    AuthResponse,
    CheckRequest,
    HealthResponse,
    InternalUserSummariesRequest,
    InternalUserSummariesResponse,
    LoginRequest,
    LogoutRequest,
    PatchUserRequest,
    RefreshRequest,
    RegisterRequest,
    TokenPairResponse,
    UserListResponse,
    UserResponse,
)


class AuthHttpHandler:
    def __init__(
        self,
        runtime: AuthApplicationRuntime,
        response_factory: AuthResponseFactory,
        error_translator: ErrorTranslator,
        request_factory: AuthRequestFactory,
    ) -> None:
        self._runtime = runtime
        self._response_factory = response_factory
        self._error_translator = error_translator
        self._request_factory = request_factory

    def health(self) -> HealthResponse:
        return HealthResponse(status="ok")

    def ready(self) -> HealthResponse:
        self._runtime.check_ready()
        return HealthResponse(status="ready")

    def register(self, payload: RegisterRequest) -> AuthResponse:
        try:
            with self._runtime.auth_service_scope() as auth_service:
                result = auth_service.register_user(self._request_factory.to_register_command(payload))
                return self._response_factory.from_service_result(result)
        except AuthError as exc:
            self._error_translator.raise_http_error(exc)
        raise AssertionError("unreachable")

    def login(self, payload: LoginRequest) -> AuthResponse:
        try:
            with self._runtime.auth_service_scope() as auth_service:
                result = auth_service.login_user(self._request_factory.to_login_command(payload))
                return self._response_factory.from_service_result(result)
        except AuthError as exc:
            self._error_translator.raise_http_error(exc)
        raise AssertionError("unreachable")

    def refresh(self, payload: RefreshRequest) -> TokenPairResponse:
        try:
            with self._runtime.auth_service_scope() as auth_service:
                token_pair = auth_service.refresh_session(self._request_factory.to_refresh_command(payload))
                return TokenPairResponse(
                    access_token=token_pair.access_token,
                    refresh_token=token_pair.refresh_token,
                    token_type=token_pair.token_type,
                )
        except AuthError as exc:
            self._error_translator.raise_http_error(exc)
        raise AssertionError("unreachable")

    def logout(self, payload: LogoutRequest) -> None:
        try:
            with self._runtime.auth_service_scope() as auth_service:
                auth_service.logout_session(self._request_factory.to_logout_command(payload))
                return
        except AuthError as exc:
            self._error_translator.raise_http_error(exc)
        raise AssertionError("unreachable")

    def me(self, authorization: str) -> UserResponse:
        access_token = authorization.removeprefix("Bearer ").strip()
        if not access_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Bearer token.")
        try:
            with self._runtime.auth_service_scope() as auth_service:
                user = auth_service.get_current_user(self._request_factory.to_me_command(access_token))
                return self._response_factory.from_domain_user(user)
        except AuthError as exc:
            self._error_translator.raise_http_error(exc)
        raise AssertionError("unreachable")

    def check(self, payload: CheckRequest) -> UserResponse:
        try:
            with self._runtime.auth_service_scope() as auth_service:
                user = auth_service.get_current_user(self._request_factory.to_check_command(payload.access_token))
                return self._response_factory.from_domain_user(user)
        except AuthError as exc:
            self._error_translator.raise_http_error(exc)
        raise AssertionError("unreachable")

    def internal_summaries(self, payload: InternalUserSummariesRequest) -> InternalUserSummariesResponse:
        try:
            with self._runtime.auth_service_scope() as auth_service:
                summaries = auth_service.list_user_summaries(self._request_factory.to_internal_summaries_command(payload))
                return self._response_factory.from_user_summaries(summaries)
        except AuthError as exc:
            self._error_translator.raise_http_error(exc)
        raise AssertionError("unreachable")

    def list_users(
        self,
        *,
        authorization: str,
        query: str | None,
        role: str | None,
        is_active: bool | None,
        page: int,
        page_size: int,
    ) -> UserListResponse:
        access_token = self._extract_bearer(authorization)
        try:
            with self._runtime.auth_service_scope() as auth_service:
                auth_service.require_platform_admin(access_token)
                users, total = auth_service.list_users(
                    ListUsersCommand(query=query, role=role, is_active=is_active, page=page, page_size=page_size)
                )
                return UserListResponse(
                    items=[self._response_factory.from_domain_user(user) for user in users],
                    total=total,
                    page=page,
                    page_size=page_size,
                )
        except AuthError as exc:
            self._error_translator.raise_http_error(exc)
        raise AssertionError("unreachable")

    def get_user(self, *, authorization: str, user_id: str) -> UserResponse:
        access_token = self._extract_bearer(authorization)
        try:
            with self._runtime.auth_service_scope() as auth_service:
                auth_service.require_platform_admin(access_token)
                user = auth_service.get_user(GetUserCommand(user_id=user_id))
                return self._response_factory.from_domain_user(user)
        except AuthError as exc:
            self._error_translator.raise_http_error(exc)
        raise AssertionError("unreachable")

    def patch_user(self, *, authorization: str, user_id: str, payload: PatchUserRequest) -> UserResponse:
        access_token = self._extract_bearer(authorization)
        try:
            with self._runtime.auth_service_scope() as auth_service:
                auth_service.require_platform_admin(access_token)
                user = auth_service.patch_user(
                    PatchUserCommand(user_id=user_id, is_active=payload.is_active, role=payload.role)
                )
                return self._response_factory.from_domain_user(user)
        except AuthError as exc:
            self._error_translator.raise_http_error(exc)
        raise AssertionError("unreachable")

    @staticmethod
    def _extract_bearer(authorization: str) -> str:
        access_token = authorization.removeprefix("Bearer ").strip()
        if not access_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Bearer token.")
        return access_token
