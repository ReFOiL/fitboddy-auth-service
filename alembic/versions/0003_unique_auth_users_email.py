"""unique constraint on auth users email

Revision ID: 0003_unique_auth_users_email
Revises: 0002_add_login_to_auth_users
Create Date: 2026-08-15 17:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0003_unique_auth_users_email"
down_revision: Union[str, Sequence[str], None] = "0002_add_login_to_auth_users"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_EMAIL_MAX_LENGTH = 320


def _rewrite_duplicate_email(email: str, user_id: str) -> str:
    local_part, separator, domain = email.partition("@")
    if separator and domain:
        candidate = f"{local_part}+dup-{user_id}@{domain}"
    else:
        candidate = f"dup-{user_id}@invalid.local"
    return candidate[:_EMAIL_MAX_LENGTH]


def upgrade() -> None:
    bind = op.get_bind()
    duplicate_emails = bind.execute(
        sa.text(
            """
            SELECT email
            FROM auth_users
            GROUP BY email
            HAVING COUNT(*) > 1
            """
        )
    ).mappings()
    for duplicate in duplicate_emails:
        rows = bind.execute(
            sa.text(
                """
                SELECT user_id, email
                FROM auth_users
                WHERE email = :email
                ORDER BY created_at ASC, user_id ASC
                """
            ),
            {"email": duplicate["email"]},
        ).mappings()
        for extra in list(rows)[1:]:
            bind.execute(
                sa.text(
                    """
                    UPDATE auth_users
                    SET email = :email
                    WHERE user_id = :user_id
                    """
                ),
                {
                    "email": _rewrite_duplicate_email(extra["email"], extra["user_id"]),
                    "user_id": extra["user_id"],
                },
            )

    op.drop_index("ix_auth_users_email", table_name="auth_users")
    op.create_index("ix_auth_users_email", "auth_users", ["email"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_auth_users_email", table_name="auth_users")
    op.create_index("ix_auth_users_email", "auth_users", ["email"], unique=False)
