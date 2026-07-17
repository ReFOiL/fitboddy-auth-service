from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import func, or_, select
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

    def search(
        self,
        *,
        query: str | None,
        role: str | None,
        is_active: bool | None,
        offset: int,
        limit: int,
    ) -> tuple[list[UserModel], int]:
        statement = select(UserModel)
        count_statement = select(func.count()).select_from(UserModel)

        if query:
            pattern = f"%{query.strip().lower()}%"
            filter_expr = or_(
                func.lower(UserModel.login).like(pattern),
                func.lower(UserModel.email).like(pattern),
                UserModel.user_id.like(pattern),
            )
            statement = statement.where(filter_expr)
            count_statement = count_statement.where(filter_expr)

        if role:
            statement = statement.where(UserModel.role == role)
            count_statement = count_statement.where(UserModel.role == role)

        if is_active is not None:
            statement = statement.where(UserModel.is_active.is_(is_active))
            count_statement = count_statement.where(UserModel.is_active.is_(is_active))

        total = int(self._session.execute(count_statement).scalar_one())
        rows = list(
            self._session.execute(
                statement.order_by(UserModel.created_at.desc()).offset(offset).limit(limit)
            ).scalars().all()
        )
        return rows, total

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
        expires_at = refresh_token.expires_at
        if expires_at.tzinfo is None:
            return expires_at <= datetime.now(UTC).replace(tzinfo=None)
        return expires_at <= datetime.now(UTC)
