from dataclasses import dataclass


@dataclass(frozen=True)
class RegisterUserCommand:
    role: str
    login: str
    email: str
    password: str


@dataclass(frozen=True)
class LoginUserCommand:
    email_or_login: str
    password: str


@dataclass(frozen=True)
class RefreshSessionCommand:
    refresh_token: str


@dataclass(frozen=True)
class LogoutSessionCommand:
    refresh_token: str


@dataclass(frozen=True)
class GetCurrentUserCommand:
    access_token: str


@dataclass(frozen=True)
class ListUserSummariesCommand:
    user_ids: list[str]


@dataclass(frozen=True)
class BootstrapPlatformAdminCommand:
    login: str
    email: str
    password: str


@dataclass(frozen=True)
class ListUsersCommand:
    query: str | None
    role: str | None
    is_active: bool | None
    page: int
    page_size: int


@dataclass(frozen=True)
class GetUserCommand:
    user_id: str


@dataclass(frozen=True)
class PatchUserCommand:
    user_id: str
    is_active: bool | None
    role: str | None
