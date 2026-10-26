"""add_totp_backup_codes

Revision ID: d4f8b1a9c6e7
Revises: c822e7183ed9
Create Date: 2026-05-24 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d4f8b1a9c6e7"
down_revision: str | Sequence[str] | None = "c822e7183ed9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "totp_backup_codes",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("code_hash", sa.String(length=255), nullable=False),
        sa.Column(
            "used", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_totp_backup_user", "totp_backup_codes", ["user_id"])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("idx_totp_backup_user", "totp_backup_codes")
    op.drop_table("totp_backup_codes")
