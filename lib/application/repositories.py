from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from application.models import RefreshTokenModel, UserModel


class UserRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def find_by_tenant_email(self, tenant_id: str, email: str) -> UserModel | None:
        return self._session.execute(
            select(UserModel).where(UserModel.tenant_id == tenant_id, UserModel.email == email)
        ).scalar_one_or_none()

    def find_by_email(self, email: str) -> UserModel | None:
        return self._session.execute(select(UserModel).where(UserModel.email == email)).scalar_one_or_none()

    def find_by_login(self, login: str) -> UserModel | None:
        return self._session.execute(select(UserModel).where(UserModel.login == login)).scalar_one_or_none()

    def find_by_id(self, user_id: str) -> UserModel | None:
        return self._session.get(UserModel, user_id)

    def list_by_ids(self, user_ids: list[str]) -> list[UserModel]:
        if not user_ids:
            return []
        statement = select(UserModel).where(UserModel.user_id.in_(user_ids))
        return list(self._session.execute(statement).scalars().all())

    def add(self, user: UserModel) -> None:
        self._session.add(user)

    def refresh(self, user: UserModel) -> None:
        self._session.refresh(user)


class RefreshTokenRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, refresh_token: RefreshTokenModel) -> None:
        self._session.add(refresh_token)

    def find_by_id(self, token_id: str) -> RefreshTokenModel | None:
        return self._session.get(RefreshTokenModel, token_id)

    def revoke(self, refresh_token: RefreshTokenModel) -> None:
        refresh_token.is_revoked = True

    @staticmethod
    def is_expired(refresh_token: RefreshTokenModel) -> bool:
        return refresh_token.expires_at <= datetime.now(UTC)
