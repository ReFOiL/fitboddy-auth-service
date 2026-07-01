"""add login to auth users

Revision ID: 0002_add_login_to_auth_users
Revises: 0001_create_auth_tables
Create Date: 2026-06-28 23:40:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0002_add_login_to_auth_users"
down_revision: Union[str, Sequence[str], None] = "0001_create_auth_tables"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _build_base_login(email: str | None, user_id: str) -> str:
    if isinstance(email, str):
        local_part = email.split("@", 1)[0].strip().lower()
        if local_part:
            return local_part
    return user_id.strip().lower()


def _build_unique_login(base_login: str, used_logins: set[str]) -> str:
    max_length = 64
    safe_base = (base_login or "user").strip().lower() or "user"
    candidate = safe_base[:max_length]
    if candidate not in used_logins:
        used_logins.add(candidate)
        return candidate

    suffix = 2
    while True:
        suffix_part = f"_{suffix}"
        trimmed = safe_base[: max_length - len(suffix_part)]
        candidate = f"{trimmed}{suffix_part}"
        if candidate not in used_logins:
            used_logins.add(candidate)
            return candidate
        suffix += 1


def upgrade() -> None:
    op.add_column("auth_users", sa.Column("login", sa.String(length=64), nullable=True))
    bind = op.get_bind()
    used_logins = {
        row["login"]
        for row in bind.execute(sa.text("SELECT login FROM auth_users WHERE login IS NOT NULL")).mappings()
        if row["login"]
    }
    rows = bind.execute(
        sa.text(
            """
            SELECT user_id, email
            FROM auth_users
            WHERE login IS NULL
            ORDER BY user_id
            """
        )
    ).mappings()
    for row in rows:
        base_login = _build_base_login(row["email"], row["user_id"])
        login = _build_unique_login(base_login, used_logins)
        bind.execute(
            sa.text(
                """
                UPDATE auth_users
                SET login = :login
                WHERE user_id = :user_id
                """
            ),
            {"login": login, "user_id": row["user_id"]},
        )
    with op.batch_alter_table("auth_users") as batch_op:
        batch_op.alter_column("login", existing_type=sa.String(length=64), nullable=False)
    op.create_index("ix_auth_users_login", "auth_users", ["login"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_auth_users_login", table_name="auth_users")
    with op.batch_alter_table("auth_users") as batch_op:
        batch_op.drop_column("login")
