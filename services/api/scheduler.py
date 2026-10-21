"""Durable PostgreSQL-backed scheduled endpoint worker."""

import asyncio
import logging
import os
import socket
import uuid
from datetime import datetime, timedelta, timezone
from typing import Awaitable, Callable

from sqlalchemy import or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from database.models import (
    IncidentNotification,
    MonitoringIncident,
    MonitoringSchedule,
    ScheduledExecution,
)
from database.session import (
    create_database_engine,
    initialize_database,
    monitoring_check_from_result,
    session_factory_for,
)
from services.api.monitor import check_endpoint

logger = logging.getLogger(__name__)
LEASE_SECONDS = 60
POLL_SECONDS = 1.0


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def claim_next_schedule(
    session_factory: sessionmaker[Session],
    worker_id: str,
    *,
    now: datetime | None = None,
    lease_seconds: int = LEASE_SECONDS,
) -> dict | None:
    """Claim the oldest due schedule; PostgreSQL row locks serialize workers."""
    claimed_at = _as_utc(now or utc_now())
    with session_factory.begin() as session:
        schedule = session.scalar(
            select(MonitoringSchedule)
            .where(
                MonitoringSchedule.enabled.is_(True),
                MonitoringSchedule.deleted_at.is_(None),
                MonitoringSchedule.next_run_at <= claimed_at,
                or_(
                    MonitoringSchedule.lease_expires_at.is_(None),
                    MonitoringSchedule.lease_expires_at <= claimed_at,
                ),
            )
            .order_by(MonitoringSchedule.next_run_at, MonitoringSchedule.id)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if schedule is None:
            return None
        scheduled_for = _as_utc(schedule.next_run_at)
        schedule.lease_owner = worker_id
        schedule.lease_expires_at = claimed_at + timedelta(seconds=lease_seconds)
        return {
            "schedule_id": schedule.id,
            "worker_id": worker_id,
            "target_url": schedule.target_url,
            "timeout_seconds": schedule.timeout_seconds,
            "failure_threshold": schedule.failure_threshold,
            "interval_seconds": schedule.interval_seconds,
            "scheduled_for": scheduled_for,
            "started_at": claimed_at,
        }


def _failure_detail(check) -> str:
    if check.error_detail:
        return check.error_detail
    if check.status_code is not None:
        return f"HTTP response status {check.status_code}"
    return "Endpoint probe failed"


def persist_scheduled_result(
    session_factory: sessionmaker[Session],
    claim: dict,
    result: dict,
    *,
    completed_at: datetime | None = None,
) -> bool:
    """Atomically persist a scheduled check, its slot, and incident transition."""
    completed = _as_utc(completed_at or utc_now())
    with session_factory.begin() as session:
        schedule = session.scalar(
            select(MonitoringSchedule)
            .where(MonitoringSchedule.id == claim["schedule_id"])
            .with_for_update()
        )
        if schedule is None or schedule.lease_owner != claim["worker_id"]:
            return False

        existing = session.scalar(
            select(ScheduledExecution).where(
                ScheduledExecution.schedule_id == schedule.id,
                ScheduledExecution.scheduled_for == claim["scheduled_for"],
            )
        )
        if existing is not None:
            schedule.lease_owner = None
            schedule.lease_expires_at = None
            return False

        check = monitoring_check_from_result(result)
        session.add(check)
        session.flush()
        session.add(
            ScheduledExecution(
                schedule_id=schedule.id,
                scheduled_for=claim["scheduled_for"],
                started_at=claim["started_at"],
                completed_at=completed,
                check_id=check.id,
            )
        )

        # Retain the completed check in history, but don't let a probe for an
        # old URL mutate the health state or incident for a newly edited target.
        if schedule.target_url != claim["target_url"]:
            if schedule.enabled and schedule.deleted_at is None:
                schedule.next_run_at = completed + timedelta(seconds=schedule.interval_seconds)
            schedule.lease_owner = None
            schedule.lease_expires_at = None
            return True

        schedule.last_run_at = completed
        result_status = result.get("status")
        schedule.last_status = (
            result_status
            if result_status in {"healthy", "degraded", "down"}
            else "healthy" if check.is_success else "down"
        )
        schedule.last_error = check.error_detail
        schedule.consecutive_failures = (
            0 if check.is_success else schedule.consecutive_failures + 1
        )
        # An operator may pause or soft-delete a schedule while its probe is in
        # flight. Preserve that decision instead of silently re-arming it.
        if schedule.enabled and schedule.deleted_at is None:
            schedule.next_run_at = completed + timedelta(seconds=schedule.interval_seconds)
        schedule.lease_owner = None
        schedule.lease_expires_at = None

        open_incident = session.scalar(
            select(MonitoringIncident)
            .where(
                MonitoringIncident.schedule_id == schedule.id,
                MonitoringIncident.resolved_at.is_(None),
            )
            .with_for_update()
        )
        if check.is_success:
            if open_incident is not None:
                open_incident.resolved_at = completed
                session.add(IncidentNotification(
                    incident_id=open_incident.id,
                    event_type="resolved",
                    next_attempt_at=completed,
                ))
        elif open_incident is not None:
            open_incident.failure_count = schedule.consecutive_failures
            open_incident.latest_error = _failure_detail(check)
            open_incident.latest_check_id = check.id
        elif schedule.consecutive_failures >= schedule.failure_threshold:
            incident = MonitoringIncident(
                    schedule_id=schedule.id,
                    started_at=completed,
                    failure_count=schedule.consecutive_failures,
                    latest_error=_failure_detail(check),
                    latest_check_id=check.id,
                )
            session.add(incident)
            session.flush()
            session.add(IncidentNotification(
                incident_id=incident.id,
                event_type="opened",
                next_attempt_at=completed,
            ))
        return True


Checker = Callable[[str, float], Awaitable[dict]]


def release_claim(session_factory: sessionmaker[Session], claim: dict) -> None:
    """Release only the lease still owned by this worker; leave the slot due."""
    with session_factory.begin() as session:
        schedule = session.scalar(
            select(MonitoringSchedule)
            .where(MonitoringSchedule.id == claim["schedule_id"])
            .with_for_update()
        )
        if schedule is not None and schedule.lease_owner == claim["worker_id"]:
            schedule.lease_owner = None
            schedule.lease_expires_at = None


async def run_one_due_check(
    session_factory: sessionmaker[Session],
    worker_id: str,
    checker: Checker = check_endpoint,
    *,
    now: datetime | None = None,
) -> bool:
    claim = claim_next_schedule(session_factory, worker_id, now=now)
    if claim is None:
        return False

    try:
        result = await asyncio.wait_for(
            checker(claim["target_url"], timeout_seconds=claim["timeout_seconds"]),
            timeout=claim["timeout_seconds"] + 5,
        )
    except asyncio.CancelledError:
        # Shutdown should not force the next worker to wait for lease expiry.
        # If release itself fails, the durable lease still expires safely.
        try:
            await asyncio.to_thread(release_claim, session_factory, claim)
        except SQLAlchemyError:
            logger.warning("Could not release schedule lease during shutdown (schedule_id=%s).", claim["schedule_id"])
        raise
    except (TimeoutError, asyncio.TimeoutError):
        result = {
            "url": claim["target_url"],
            "status": "down",
            "error": "Request timed out",
            "checked_at": utc_now().isoformat(),
        }
    except Exception:
        logger.warning("Scheduled endpoint check failed unexpectedly (schedule_id=%s).", claim["schedule_id"])
        result = {
            "url": claim["target_url"],
            "status": "down",
            "error": "Connection failed",
            "checked_at": utc_now().isoformat(),
        }

    return persist_scheduled_result(session_factory, claim, result)


async def run_worker(
    *,
    poll_seconds: float = POLL_SECONDS,
    worker_id: str | None = None,
) -> None:
    engine = create_database_engine()
    worker_id = worker_id or f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    try:
        while True:
            try:
                initialize_database(engine)
                break
            except SQLAlchemyError:
                logger.error("Scheduled worker cannot reach its database; retrying startup.")
                await asyncio.sleep(poll_seconds)
        session_factory = session_factory_for(engine)
        logger.info("Scheduled endpoint worker started (worker_id=%s).", worker_id)
        while True:
            try:
                did_work = await run_one_due_check(session_factory, worker_id)
            except SQLAlchemyError:
                logger.error("Scheduled worker database operation failed; retrying.")
                did_work = False
            except Exception:
                logger.error("Scheduled worker encountered an unexpected error; retrying.")
                did_work = False
            if not did_work:
                await asyncio.sleep(poll_seconds)
    finally:
        engine.dispose()


if __name__ == "__main__":
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    try:
        asyncio.run(run_worker())
    except KeyboardInterrupt:
        logger.info("Scheduled endpoint worker stopped.")
