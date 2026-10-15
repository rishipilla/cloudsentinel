from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, Index, Integer, String
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
