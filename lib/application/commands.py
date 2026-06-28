from dataclasses import dataclass


@dataclass(frozen=True)
class RegisterUserCommand:
    role: str
    login: str
    email: str
    password: str


@dataclass(frozen=True)
class LoginUserCommand:
    email: str
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
