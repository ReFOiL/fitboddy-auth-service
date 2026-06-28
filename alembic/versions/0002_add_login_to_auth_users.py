"""add login to auth users

Revision ID: 0002_add_login_to_auth_users
Revises: 0001_create_auth_tables
Create Date: 2026-06-28 23:40:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0002_add_login_to_auth_users"
down_revision: Union[str, Sequence[str], None] = "0001_create_auth_tables"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("auth_users", sa.Column("login", sa.String(length=64), nullable=True))
    op.execute(
        """
        WITH prepared AS (
            SELECT
                user_id,
                COALESCE(NULLIF(lower(split_part(email, '@', 1)), ''), lower(user_id)) AS base_login,
                row_number() OVER (
                    PARTITION BY COALESCE(NULLIF(lower(split_part(email, '@', 1)), ''), lower(user_id))
                    ORDER BY user_id
                ) AS row_num
            FROM auth_users
            WHERE login IS NULL
        )
        UPDATE auth_users AS users
        SET login = CASE
            WHEN prepared.row_num = 1 THEN prepared.base_login
            ELSE concat(substr(prepared.base_login, 1, 58), '_', prepared.row_num::text)
        END
        FROM prepared
        WHERE users.user_id = prepared.user_id
        """
    )
    with op.batch_alter_table("auth_users") as batch_op:
        batch_op.alter_column("login", existing_type=sa.String(length=64), nullable=False)
    op.create_index("ix_auth_users_login", "auth_users", ["login"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_auth_users_login", table_name="auth_users")
    with op.batch_alter_table("auth_users") as batch_op:
        batch_op.drop_column("login")
