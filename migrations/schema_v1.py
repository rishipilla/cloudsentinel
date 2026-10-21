"""Frozen SQLAlchemy schema snapshot for revision 0001.

Keep this snapshot immutable. Future schema changes belong in a new revision.
"""
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    UniqueConstraint,
    text,
)

metadata = MetaData()

monitoring_checks = Table(
    "monitoring_checks", metadata,
    Column("id", Integer, primary_key=True),
    Column("checked_url", String(2083), nullable=False),
    Column("checked_at", DateTime(timezone=True), nullable=False),
    Column("is_success", Boolean, nullable=False),
    Column("status_code", Integer),
    Column("latency_ms", Float),
    Column("error_detail", String(500)),
)
Index("ix_monitoring_checks_checked_at", monitoring_checks.c.checked_at)
Index(
    "ix_monitoring_checks_checked_url_checked_at",
    monitoring_checks.c.checked_url,
    monitoring_checks.c.checked_at,
)

monitoring_schedules = Table(
    "monitoring_schedules", metadata,
    Column("id", Integer, primary_key=True),
    Column("target_url", String(2083), nullable=False),
    Column("interval_seconds", Integer, nullable=False),
    Column("timeout_seconds", Float, nullable=False),
    Column("failure_threshold", Integer, nullable=False),
    Column("enabled", Boolean, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("next_run_at", DateTime(timezone=True), nullable=False),
    Column("last_run_at", DateTime(timezone=True)),
    Column("last_status", String(16)),
    Column("last_error", String(500)),
    Column("consecutive_failures", Integer, nullable=False),
    Column("lease_owner", String(100)),
    Column("lease_expires_at", DateTime(timezone=True)),
    Column("deleted_at", DateTime(timezone=True)),
)
Index(
    "ix_monitoring_schedules_due",
    monitoring_schedules.c.enabled,
    monitoring_schedules.c.deleted_at,
    monitoring_schedules.c.next_run_at,
)

scheduled_executions = Table(
    "scheduled_executions", metadata,
    Column("id", Integer, primary_key=True),
    Column("schedule_id", Integer, ForeignKey("monitoring_schedules.id"), nullable=False),
    Column("scheduled_for", DateTime(timezone=True), nullable=False),
    Column("started_at", DateTime(timezone=True), nullable=False),
    Column("completed_at", DateTime(timezone=True), nullable=False),
    Column("check_id", Integer, ForeignKey("monitoring_checks.id"), nullable=False),
    UniqueConstraint("schedule_id", "scheduled_for", name="uq_scheduled_execution_slot"),
)
Index(
    "ix_scheduled_executions_schedule_checked",
    scheduled_executions.c.schedule_id,
    scheduled_executions.c.completed_at,
)

monitoring_incidents = Table(
    "monitoring_incidents", metadata,
    Column("id", Integer, primary_key=True),
    Column("schedule_id", Integer, ForeignKey("monitoring_schedules.id"), nullable=False),
    Column("started_at", DateTime(timezone=True), nullable=False),
    Column("resolved_at", DateTime(timezone=True)),
    Column("failure_count", Integer, nullable=False),
    Column("latest_error", String(500), nullable=False),
    Column("latest_check_id", Integer, ForeignKey("monitoring_checks.id"), nullable=False),
)
Index(
    "uq_monitoring_incidents_open_schedule",
    monitoring_incidents.c.schedule_id,
    unique=True,
    postgresql_where=text("resolved_at IS NULL"),
    sqlite_where=text("resolved_at IS NULL"),
)
Index(
    "ix_monitoring_incidents_schedule_started",
    monitoring_incidents.c.schedule_id,
    monitoring_incidents.c.started_at,
)

incident_notifications = Table(
    "incident_notifications", metadata,
    Column("id", Integer, primary_key=True),
    Column("incident_id", Integer, ForeignKey("monitoring_incidents.id"), nullable=False),
    Column("event_type", String(16), nullable=False),
    Column("status", String(16), nullable=False),
    Column("attempt_count", Integer, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("next_attempt_at", DateTime(timezone=True), nullable=False),
    Column("lease_owner", String(100)),
    Column("lease_expires_at", DateTime(timezone=True)),
    Column("lease_provider", String(32)),
    Column("delivered_at", DateTime(timezone=True)),
    Column("last_error", String(200)),
    UniqueConstraint("incident_id", "event_type", name="uq_incident_notification_event"),
)
Index(
    "ix_incident_notifications_due",
    incident_notifications.c.status,
    incident_notifications.c.next_attempt_at,
)

notification_attempts = Table(
    "notification_attempts", metadata,
    Column("id", Integer, primary_key=True),
    Column("notification_id", Integer, ForeignKey("incident_notifications.id"), nullable=False),
    Column("attempt_number", Integer, nullable=False),
    Column("provider", String(32), nullable=False),
    Column("status", String(16), nullable=False),
    Column("started_at", DateTime(timezone=True), nullable=False),
    Column("completed_at", DateTime(timezone=True)),
    Column("error_summary", String(200)),
    UniqueConstraint("notification_id", "attempt_number", name="uq_notification_attempt_number"),
)
Index(
    "ix_notification_attempts_notification",
    notification_attempts.c.notification_id,
    notification_attempts.c.started_at,
)

threat_intel_cache = Table(
    "threat_intel_cache", metadata,
    Column("id", Integer, primary_key=True),
    Column("provider", String(32), nullable=False),
    Column("indicator_type", String(16), nullable=False),
    Column("indicator", String(253), nullable=False),
    Column("cached_at", DateTime(timezone=True), nullable=False),
    Column("result_json", String(2000), nullable=False),
    UniqueConstraint(
        "provider", "indicator_type", "indicator", name="uq_threat_intel_cache_indicator"
    ),
)
Index("ix_threat_intel_cache_cached_at", threat_intel_cache.c.cached_at)

threat_intel_rate_locks = Table(
    "threat_intel_rate_locks", metadata,
    Column("provider", String(32), primary_key=True),
    Column("recent_requests", String(1000), nullable=False),
    Column("daily_window", String(10)),
    Column("daily_count", Integer, nullable=False),
)
