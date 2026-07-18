from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class HealthResponse(BaseModel):
    status: str


class RegisterRequest(BaseModel):
    role: str = Field(default="client", min_length=3, max_length=32)
    login: str = Field(min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_.-]+$")
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email_or_login: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=8, max_length=128)


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


class CheckRequest(BaseModel):
    access_token: str


class InternalUserSummariesRequest(BaseModel):
    user_ids: list[str] = Field(default_factory=list)


class TokenPairResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    user_id: str
    tenant_id: str
    login: str
    # Plain str: response must not 500 on already-stored bootstrap/dev emails
    # (EmailStr rejects reserved TLDs like .local).
    email: str
    role: str
    is_active: bool
    created_at: datetime


class AuthResponse(BaseModel):
    user: UserResponse
    tokens: TokenPairResponse


class UserSummaryResponse(BaseModel):
    user_id: str
    login: str


class InternalUserSummariesResponse(BaseModel):
    items: list[UserSummaryResponse] = Field(default_factory=list)


class PatchUserRequest(BaseModel):
    is_active: bool | None = None
    role: str | None = Field(default=None, min_length=3, max_length=32)


class UserListResponse(BaseModel):
    items: list[UserResponse] = Field(default_factory=list)
    total: int
    page: int
    page_size: int