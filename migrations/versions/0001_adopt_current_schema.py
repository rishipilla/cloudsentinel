"""Adopt the current CloudSentinel schema without removing existing data.

Revision ID: 0001_current_schema
Revises:
"""
from alembic import op
from sqlalchemy import text

from migrations.schema_v1 import metadata

revision = "0001_current_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # create_all is intentionally used only for this idempotent baseline: it
    # creates missing tables/indexes and leaves existing tables/rows untouched.
    bind = op.get_bind()
    metadata.create_all(bind=bind)
    # create_all skips an existing table wholesale, including any missing
    # indexes; create these separately so an adopted legacy schema converges.
    for table in metadata.sorted_tables:
        for index in table.indexes:
            index.create(bind=bind, checkfirst=True)
    if bind.dialect.name == "postgresql":
        # Match the additive compatibility upgrades previously performed at
        # application startup for databases created by earlier releases.
        bind.execute(text(
            "ALTER TABLE threat_intel_rate_locks "
            "ADD COLUMN IF NOT EXISTS recent_requests VARCHAR(1000) NOT NULL DEFAULT '[]'"
        ))
        bind.execute(text(
            "ALTER TABLE threat_intel_rate_locks "
            "ADD COLUMN IF NOT EXISTS daily_window VARCHAR(10)"
        ))
        bind.execute(text(
            "ALTER TABLE threat_intel_rate_locks "
            "ADD COLUMN IF NOT EXISTS daily_count INTEGER NOT NULL DEFAULT 0"
        ))
        bind.execute(text(
            "ALTER TABLE incident_notifications "
            "ADD COLUMN IF NOT EXISTS lease_provider VARCHAR(32)"
        ))
        bind.execute(text(
            "ALTER TABLE notification_attempts ALTER COLUMN completed_at DROP NOT NULL"
        ))


def downgrade() -> None:
    # The baseline adopts pre-existing tables and may include user history.
    # A destructive downgrade is deliberately unsupported.
    raise RuntimeError("The CloudSentinel baseline migration cannot be downgraded safely.")
