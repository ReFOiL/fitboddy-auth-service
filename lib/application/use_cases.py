from __future__ import annotations

from dataclasses import dataclass
import re
from uuid import uuid4

from sqlalchemy.orm import Session

from application.commands import (
    BootstrapPlatformAdminCommand,
    GetCurrentUserCommand,
    GetUserCommand,
    ListUserSummariesCommand,
    ListUsersCommand,
    LoginUserCommand,
    LogoutSessionCommand,
    PatchUserCommand,
    RefreshSessionCommand,
    RegisterUserCommand,
)
from application.errors import (
    ConflictError,
    ForbiddenError,
    IntegrationError,
    NotFoundError,
    UnauthorizedError,
    ValidationError,
)
from application.gateways import MarketplaceGateway
from application.models import RefreshTokenModel, UserModel
from application.repositories import RefreshTokenRepository, UserRepository
from application.security import JwtService, PasswordService, TokenError
from domain.entities import User, UserSummary


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


@dataclass(frozen=True)
class AuthResult:
    user: User
    tokens: TokenPair


class UserMapper:
    def to_domain(self, user: UserModel) -> User:
        return User(
            user_id=user.user_id,
            tenant_id=user.tenant_id,
            login=user.login,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
            created_at=user.created_at,
        )

    def to_summary(self, user: UserModel) -> UserSummary:
        return UserSummary(user_id=user.user_id, login=user.login)


class AuthService:
    _DEFAULT_TENANT_ID = "marketplace"
    _PLATFORM_ADMIN_ROLE = "platform_admin"
    _LOGIN_PATTERN = re.compile(r"^[a-z0-9_.-]{3,32}$")
    _ROLE_MAP = {
        "owner": "trainer",
        "coach": "trainer",
        "trainer": "trainer",
        "client": "client",
    }
    _ASSIGNABLE_ROLES = frozenset({"trainer", "client", "platform_admin"})

    def __init__(
        self,
        *,
        session: Session,
        jwt_service: JwtService,
        password_service: PasswordService,
        access_ttl_minutes: int,
        refresh_ttl_minutes: int,
        marketplace_gateway: MarketplaceGateway,
        marketplace_profile_sync_enabled: bool,
    ) -> None:
        self._session = session
        self._jwt_service = jwt_service
        self._password_service = password_service
        self._access_ttl_minutes = access_ttl_minutes
        self._refresh_ttl_minutes = refresh_ttl_minutes
        self._marketplace_gateway = marketplace_gateway
        self._marketplace_profile_sync_enabled = marketplace_profile_sync_enabled
        self._users = UserRepository(session)
        self._refresh_tokens = RefreshTokenRepository(session)
        self._mapper = UserMapper()

    def register_user(self, command: RegisterUserCommand) -> AuthResult:
        login_lookup = self._normalize_login(command.login)
        if self._users.find_by_login(login_lookup) is not None:
            raise ConflictError("User with this login already exists.")

        email_lookup = command.email.strip().lower()
        if self._users.find_by_email(email_lookup) is not None:
            raise ConflictError("User with this email already exists.")

        role = self._normalize_role(command.role)

        user = UserModel(
            user_id=str(uuid4()),
            tenant_id=self._DEFAULT_TENANT_ID,
            login=login_lookup,
            email=email_lookup,
            password_hash=self._password_service.hash(command.password),
            role=role,
            is_active=True,
        )
        self._users.add(user)
        self._session.flush()
        if self._marketplace_profile_sync_enabled:
            try:
                self._marketplace_gateway.upsert_discovery_profile(user.user_id, role)
            except IntegrationError:
                self._session.rollback()
                raise

        token_pair = self._issue_token_pair(user)
        self._session.commit()
        self._users.refresh(user)
        return AuthResult(user=self._mapper.to_domain(user), tokens=token_pair)

    def login_user(self, command: LoginUserCommand) -> AuthResult:
        normalized_credential = command.email_or_login.strip().lower()
        user = self._users.find_by_email(normalized_credential)
        if user is None:
            user = self._users.find_by_login(normalized_credential)
        if user is None or user.password_hash is None:
            raise UnauthorizedError("Invalid credentials.")
        if not self._password_service.verify(command.password, user.password_hash):
            raise UnauthorizedError("Invalid credentials.")
        if not user.is_active:
            raise UnauthorizedError("User is inactive.")

        token_pair = self._issue_token_pair(user)
        self._session.commit()
        return AuthResult(user=self._mapper.to_domain(user), tokens=token_pair)

    def refresh_session(self, command: RefreshSessionCommand) -> TokenPair:
        payload = self._decode_refresh_token(command.refresh_token)
        token_id = payload.get("jti")
        user_id = payload.get("sub")
        tenant_id = payload.get("tenant_id")
        if not token_id or not user_id or not tenant_id:
            raise UnauthorizedError("Refresh token is malformed.")

        stored_token = self._refresh_tokens.find_by_id(token_id)
        if stored_token is None or stored_token.is_revoked or self._refresh_tokens.is_expired(stored_token):
            raise UnauthorizedError("Refresh token is revoked or expired.")

        user = self._users.find_by_id(user_id)
        if user is None or not user.is_active or user.tenant_id != tenant_id:
            raise UnauthorizedError("User is invalid for this token.")

        self._refresh_tokens.revoke(stored_token)
        token_pair = self._issue_token_pair(user)
        self._session.commit()
        return token_pair

    def logout_session(self, command: LogoutSessionCommand) -> None:
        payload = self._decode_refresh_token(command.refresh_token)
        token_id = payload.get("jti")
        if not token_id:
            raise UnauthorizedError("Token id is missing.")

        stored_token = self._refresh_tokens.find_by_id(token_id)
        if stored_token is None:
            raise UnauthorizedError("Unknown refresh token.")

        self._refresh_tokens.revoke(stored_token)
        self._session.commit()

    def get_current_user(self, command: GetCurrentUserCommand) -> User:
        try:
            payload = self._jwt_service.verify_token(command.access_token)
        except TokenError as exc:
            raise UnauthorizedError("Invalid access token.") from exc
        if payload.get("type") != "access":
            raise UnauthorizedError("Invalid token type.")

        user_id = payload.get("sub")
        tenant_id = payload.get("tenant_id")
        if not user_id or not tenant_id:
            raise UnauthorizedError("Access token is malformed.")

        user = self._users.find_by_id(user_id)
        if user is None or not user.is_active or user.tenant_id != tenant_id:
            raise UnauthorizedError("User not found for this token.")
        return self._mapper.to_domain(user)

    def list_user_summaries(self, command: ListUserSummariesCommand) -> list[UserSummary]:
        unique_user_ids = list(dict.fromkeys(user_id.strip() for user_id in command.user_ids if user_id.strip()))
        if not unique_user_ids:
            return []
        users = self._users.list_by_ids(unique_user_ids)
        return [self._mapper.to_summary(user) for user in users]

    def require_platform_admin(self, access_token: str) -> User:
        user = self.get_current_user(GetCurrentUserCommand(access_token=access_token))
        if user.role != self._PLATFORM_ADMIN_ROLE:
            raise ForbiddenError("platform_admin role required")
        return user

    def bootstrap_platform_admin(self, command: BootstrapPlatformAdminCommand) -> tuple[User, str]:
        """Create or repair platform_admin from env credentials.

        Returns (user, action) where action is "created" or "updated".
        """
        login_lookup = self._normalize_login(command.login)
        email_lookup = command.email.strip().lower()
        existing = self._users.find_by_login(login_lookup)
        if existing is None:
            existing = self._users.find_by_email(email_lookup)

        if existing is not None:
            email_owner = self._users.find_by_email(email_lookup)
            if email_owner is not None and email_owner.user_id != existing.user_id:
                raise ConflictError("User with this email already exists.")
            existing.login = login_lookup
            existing.email = email_lookup
            existing.password_hash = self._password_service.hash(command.password)
            existing.role = self._PLATFORM_ADMIN_ROLE
            existing.is_active = True
            self._session.commit()
            self._users.refresh(existing)
            return self._mapper.to_domain(existing), "updated"

        user = UserModel(
            user_id=str(uuid4()),
            tenant_id=self._DEFAULT_TENANT_ID,
            login=login_lookup,
            email=email_lookup,
            password_hash=self._password_service.hash(command.password),
            role=self._PLATFORM_ADMIN_ROLE,
            is_active=True,
        )
        self._users.add(user)
        self._session.commit()
        self._users.refresh(user)
        return self._mapper.to_domain(user), "created"

    def list_users(self, command: ListUsersCommand) -> tuple[list[User], int]:
        page = max(command.page, 1)
        page_size = min(max(command.page_size, 1), 100)
        offset = (page - 1) * page_size
        role = command.role.strip().lower() if command.role else None
        if role and role not in self._ASSIGNABLE_ROLES:
            raise ValidationError("Unsupported role filter.")
        rows, total = self._users.search(
            query=command.query,
            role=role,
            is_active=command.is_active,
            offset=offset,
            limit=page_size,
        )
        return [self._mapper.to_domain(row) for row in rows], total

    def get_user(self, command: GetUserCommand) -> User:
        user = self._users.find_by_id(command.user_id)
        if user is None:
            raise NotFoundError("User not found.")
        return self._mapper.to_domain(user)

    def patch_user(self, command: PatchUserCommand) -> User:
        user = self._users.find_by_id(command.user_id)
        if user is None:
            raise NotFoundError("User not found.")

        if command.is_active is not None:
            user.is_active = command.is_active

        if command.role is not None:
            role_key = command.role.strip().lower()
            if role_key not in self._ASSIGNABLE_ROLES:
                raise ValidationError("Unsupported role. Use 'trainer', 'client', or 'platform_admin'.")
            user.role = role_key
            if self._marketplace_profile_sync_enabled and role_key in {"trainer", "client"}:
                try:
                    self._marketplace_gateway.upsert_discovery_profile(user.user_id, role_key)
                except IntegrationError:
                    self._session.rollback()
                    raise

        self._session.commit()
        self._users.refresh(user)
        return self._mapper.to_domain(user)

    def _decode_refresh_token(self, refresh_token: str) -> dict:
        try:
            payload = self._jwt_service.verify_token(refresh_token)
        except TokenError as exc:
            raise UnauthorizedError("Invalid refresh token.") from exc
        if payload.get("type") != "refresh":
            raise UnauthorizedError("Invalid token type.")
        return payload

    def _issue_token_pair(self, user: UserModel) -> TokenPair:
        token_pair_data = self._jwt_service.build_token_pair(
            user_id=user.user_id,
            tenant_id=user.tenant_id,
            role=user.role,
            access_ttl_minutes=self._access_ttl_minutes,
            refresh_ttl_minutes=self._refresh_ttl_minutes,
        )
        self._refresh_tokens.add(
            RefreshTokenModel(
                token_id=token_pair_data.refresh_jti,
                user_id=user.user_id,
                tenant_id=user.tenant_id,
                expires_at=token_pair_data.refresh_expires_at,
                is_revoked=False,
            )
        )
        return TokenPair(access_token=token_pair_data.access_token, refresh_token=token_pair_data.refresh_token)

    def _normalize_role(self, role: str) -> str:
        role_key = role.strip().lower()
        normalized_role = self._ROLE_MAP.get(role_key)
        if normalized_role is None:
            raise ValidationError("Unsupported role. Use 'trainer' or 'client'.")
        return normalized_role

    def _normalize_login(self, login: str) -> str:
        normalized_login = login.strip().lower()
        if not self._LOGIN_PATTERN.fullmatch(normalized_login):
            raise ValidationError("Unsupported login format. Use 3-32 chars: a-z, 0-9, _, -, .")
        return normalized_login