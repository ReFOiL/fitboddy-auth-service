from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from application.db import Base


class UserModel(Base):
    __tablename__ = "auth_users"

    user_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    login: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="client")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))


class RefreshTokenModel(Base):
    __tablename__ = "auth_refresh_tokens"

    token_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("auth_users.user_id"), index=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
