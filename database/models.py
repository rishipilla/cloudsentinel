from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, UniqueConstraint, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class MonitoringCheck(Base):
    __tablename__ = "monitoring_checks"
    __table_args__ = (
        Index("ix_monitoring_checks_checked_at", "checked_at"),
        Index("ix_monitoring_checks_checked_url_checked_at", "checked_url", "checked_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    checked_url: Mapped[str] = mapped_column(String(2083), nullable=False)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    is_success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    error_detail: Mapped[str | None] = mapped_column(String(500), nullable=True)


class MonitoringSchedule(Base):
    __tablename__ = "monitoring_schedules"
    __table_args__ = (
        Index("ix_monitoring_schedules_due", "enabled", "deleted_at", "next_run_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_url: Mapped[str] = mapped_column(String(2083), nullable=False)
    interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    timeout_seconds: Mapped[float] = mapped_column(Float, nullable=False, default=5.0)
    failure_threshold: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    lease_owner: Mapped[str | None] = mapped_column(String(100), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ScheduledExecution(Base):
    __tablename__ = "scheduled_executions"
    __table_args__ = (
        UniqueConstraint("schedule_id", "scheduled_for", name="uq_scheduled_execution_slot"),
        Index("ix_scheduled_executions_schedule_checked", "schedule_id", "completed_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    schedule_id: Mapped[int] = mapped_column(
        ForeignKey("monitoring_schedules.id"), nullable=False
    )
    scheduled_for: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    check_id: Mapped[int] = mapped_column(ForeignKey("monitoring_checks.id"), nullable=False)


class MonitoringIncident(Base):
    __tablename__ = "monitoring_incidents"
    __table_args__ = (
        Index(
            "uq_monitoring_incidents_open_schedule",
            "schedule_id",
            unique=True,
            postgresql_where=text("resolved_at IS NULL"),
            sqlite_where=text("resolved_at IS NULL"),
        ),
        Index("ix_monitoring_incidents_schedule_started", "schedule_id", "started_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    schedule_id: Mapped[int] = mapped_column(
        ForeignKey("monitoring_schedules.id"), nullable=False
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False)
    latest_error: Mapped[str] = mapped_column(String(500), nullable=False)
    latest_check_id: Mapped[int] = mapped_column(
        ForeignKey("monitoring_checks.id"), nullable=False
    )


class IncidentNotification(Base):
    """Transactional outbox item for one incident lifecycle event."""
    __tablename__ = "incident_notifications"
    __table_args__ = (
        UniqueConstraint("incident_id", "event_type", name="uq_incident_notification_event"),
        Index("ix_incident_notifications_due", "status", "next_attempt_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("monitoring_incidents.id"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    lease_owner: Mapped[str | None] = mapped_column(String(100), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lease_provider: Mapped[str | None] = mapped_column(String(32), nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(200), nullable=True)


class NotificationAttempt(Base):
    __tablename__ = "notification_attempts"
    __table_args__ = (
        UniqueConstraint("notification_id", "attempt_number", name="uq_notification_attempt_number"),
        Index("ix_notification_attempts_notification", "notification_id", "started_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    notification_id: Mapped[int] = mapped_column(ForeignKey("incident_notifications.id"), nullable=False)
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_summary: Mapped[str | None] = mapped_column(String(200), nullable=True)


class ThreatIntelCache(Base):
    __tablename__ = "threat_intel_cache"
    __table_args__ = (
        UniqueConstraint("provider", "indicator_type", "indicator", name="uq_threat_intel_cache_indicator"),
        Index("ix_threat_intel_cache_cached_at", "cached_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    indicator_type: Mapped[str] = mapped_column(String(16), nullable=False)
    indicator: Mapped[str] = mapped_column(String(253), nullable=False)
    cached_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    result_json: Mapped[str] = mapped_column(String(2000), nullable=False)


class ThreatIntelRateLock(Base):
    __tablename__ = "threat_intel_rate_locks"
    provider: Mapped[str] = mapped_column(String(32), primary_key=True)
    recent_requests: Mapped[str] = mapped_column(String(1000), nullable=False, default="[]")
    daily_window: Mapped[str | None] = mapped_column(String(10), nullable=True)
    daily_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
