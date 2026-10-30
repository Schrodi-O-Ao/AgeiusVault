"""add_audit_chain_unique_constraint

Revision ID: e5a1b2c3d4e5
Revises: d4f8b1a9c6e7
Create Date: 2026-10-30 00:00:00.000000

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e5a1b2c3d4e5"
down_revision: str | Sequence[str] | None = "d4f8b1a9c6e7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_unique_constraint(
        "uq_audit_chain_request_step",
        "audit_chain",
        ["request_id", "step_index"],
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint(
        "uq_audit_chain_request_step",
        "audit_chain",
        type_="unique",
    )
