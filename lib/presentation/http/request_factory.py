from application.commands import (
    GetCurrentUserCommand,
    ListUserSummariesCommand,
    LoginUserCommand,
    LogoutSessionCommand,
    RefreshSessionCommand,
    RegisterUserCommand,
)
from presentation.http.schemas import InternalUserSummariesRequest, LoginRequest, LogoutRequest, RefreshRequest, RegisterRequest


class AuthRequestFactory:
    def to_register_command(self, payload: RegisterRequest) -> RegisterUserCommand:
        return RegisterUserCommand(
            role=payload.role,
            login=payload.login,
            email=str(payload.email),
            password=payload.password,
        )

    def to_login_command(self, payload: LoginRequest) -> LoginUserCommand:
        return LoginUserCommand(
            email_or_login=payload.email_or_login,
            password=payload.password,
        )

    def to_refresh_command(self, payload: RefreshRequest) -> RefreshSessionCommand:
        return RefreshSessionCommand(refresh_token=payload.refresh_token)

    def to_logout_command(self, payload: LogoutRequest) -> LogoutSessionCommand:
        return LogoutSessionCommand(refresh_token=payload.refresh_token)

    def to_me_command(self, access_token: str) -> GetCurrentUserCommand:
        return GetCurrentUserCommand(access_token=access_token)

    def to_check_command(self, access_token: str) -> GetCurrentUserCommand:
        return GetCurrentUserCommand(access_token=access_token)

    def to_internal_summaries_command(self, payload: InternalUserSummariesRequest) -> ListUserSummariesCommand:
        return ListUserSummariesCommand(user_ids=payload.user_ids)
