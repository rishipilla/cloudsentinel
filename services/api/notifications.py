"""Durable incident-email outbox worker (stdlib SMTP, no broker dependency)."""

import asyncio
import logging
import os
import socket
import smtplib
import ssl
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import getaddresses

from sqlalchemy import and_, or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from database.models import IncidentNotification, MonitoringIncident, MonitoringSchedule, NotificationAttempt
from database.session import create_database_engine, initialize_database, session_factory_for

logger = logging.getLogger(__name__)
LEASE_SECONDS = 120
MAX_ATTEMPTS = 5
POLL_SECONDS = 2.0
RESEND_IDEMPOTENCY_WINDOW = timedelta(hours=24)


class SafeDeliveryRetry(Exception):
    """A delivery failure known to have happened before provider acceptance."""


class DeliveryOutcomeUncertain(Exception):
    """SMTP may have accepted the message; retrying could send a duplicate."""


class DeliveryRejected(Exception):
    """The SMTP server explicitly rejected the message; do not retry it."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _config() -> dict:
    return {
        "host": os.getenv("SMTP_HOST", "").strip(),
        "port": int(os.getenv("SMTP_PORT", "1025")),
        "username": os.getenv("SMTP_USERNAME", ""),
        "password": os.getenv("SMTP_PASSWORD", ""),
        "sender": os.getenv("SMTP_FROM", "").strip(),
        "recipient": os.getenv("ALERT_EMAIL_TO", "").strip(),
        "starttls": os.getenv("SMTP_STARTTLS", "true").lower() == "true",
        "dev_mode": os.getenv("ALERT_EMAIL_DEV_MODE", "true").lower() == "true",
        "resolve_enabled": os.getenv("ALERT_EMAIL_ON_RESOLVE", "false").lower() == "true",
        "provider": os.getenv("EMAIL_PROVIDER", "smtp").strip().lower(),
        "resend_api_key": os.getenv("RESEND_API_KEY", ""),
        "environment": os.getenv("CLOUDSENTINEL_ENV", "development").lower(),
    }


def _message(session: Session, row: IncidentNotification, config: dict) -> EmailMessage:
    incident = session.get(MonitoringIncident, row.incident_id)
    schedule = session.get(MonitoringSchedule, incident.schedule_id) if incident else None
    event_label = "opened" if row.event_type == "opened" else "resolved"
    # Integer IDs are only unique inside one database. Including the durable
    # outbox creation time keeps provider idempotency keys stable for retries,
    # while preventing collisions between isolated databases (for example,
    # repeated Mailpit integration-test runs whose IDs all start at 1).
    created_at = row.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    else:
        created_at = created_at.astimezone(timezone.utc)
    event_key = (
        f"incident-{row.incident_id}-{row.event_type}-"
        f"{created_at.strftime('%Y%m%dT%H%M%S%fZ')}"
    )
    message = EmailMessage()
    message["Subject"] = f"CloudSentinel availability incident {event_label}"
    message["From"] = config["sender"]
    message["To"] = config["recipient"]
    message["Message-ID"] = f"<{event_key}@cloudsentinel.local>"
    message["X-CloudSentinel-Notification-ID"] = str(row.id)
    message["X-CloudSentinel-Event-Key"] = event_key
    # No endpoint URL, credentials, exception text, or probe payload is sent.
    message.set_content(
        f"An endpoint availability incident was {event_label}.\n"
        f"Incident ID: {row.incident_id}\n"
        f"Schedule ID: {incident.schedule_id if incident else 'unavailable'}\n"
        f"Endpoint: {schedule.target_url.split('/')[2] if schedule else 'unavailable'}\n"
        "This notification reports endpoint availability only."
    )
    return message


def send_email(message: EmailMessage, config: dict) -> None:
    if config.get("provider", "smtp") == "resend_api":
        _send_resend_api(message, config)
        return
    if config.get("provider", "smtp") != "smtp":
        raise ValueError("Unsupported email provider.")
    host = config["host"].lower()
    loopback_hosts = {"localhost", "127.0.0.1", "::1", "mailpit"}
    if not config["starttls"] and (
        config.get("environment") == "production"
        or host not in loopback_hosts
        or config["username"]
        or config["password"]
    ):
        raise ValueError("Unencrypted SMTP is restricted to local development.")
    context = ssl.create_default_context()
    accepted = False
    try:
        with smtplib.SMTP(config["host"], config["port"], timeout=10) as client:
            try:
                client.ehlo()
                if config["starttls"]:
                    client.starttls(context=context)
                    client.ehlo()
                if config["username"]:
                    client.login(config["username"], config["password"])
            except Exception as exc:
                raise SafeDeliveryRetry() from exc
            try:
                refused = client.send_message(message)
            except smtplib.SMTPResponseException as exc:
                if 400 <= exc.smtp_code < 500:
                    raise SafeDeliveryRetry() from exc
                raise DeliveryRejected() from exc
            except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused) as exc:
                raise SafeDeliveryRetry() from exc
            except Exception as exc:
                # The failure happened during DATA/acceptance, so SMTP cannot tell
                # us whether the recipient already received this event.
                raise DeliveryOutcomeUncertain() from exc
            if refused:
                # Some recipients may already have accepted the message.
                raise DeliveryOutcomeUncertain()
            accepted = True
    except (SafeDeliveryRetry, DeliveryRejected, DeliveryOutcomeUncertain):
        raise
    except Exception as exc:
        if accepted:
            # SMTP has already confirmed acceptance; failure during QUIT is not
            # grounds to send a second copy.
            return
        # DNS/connect failures are before the message can be accepted.
        raise SafeDeliveryRetry() from exc


def _send_resend_api(message: EmailMessage, config: dict) -> None:
    import httpx

    payload = {
        "from": message["From"],
        "to": [address for _, address in getaddresses(message.get_all("To", [])) if address],
        "subject": message["Subject"],
        "text": message.get_content(),
    }
    event_key = message["X-CloudSentinel-Event-Key"]
    with httpx.Client(timeout=10.0, trust_env=False, follow_redirects=False) as client:
        response = client.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {config['resend_api_key']}",
                "Content-Type": "application/json",
                "Idempotency-Key": event_key,
            },
            json=payload,
        )
        response.raise_for_status()


def claim_notification(
    session_factory: sessionmaker[Session],
    worker_id: str,
    *,
    provider: str = "smtp",
    now: datetime | None = None,
) -> dict | None:
    claimed_at = _as_utc(now or utc_now())
    with session_factory.begin() as session:
        def mark_uncertain(row: IncidentNotification, reason: str) -> None:
            latest_attempt = session.scalar(
                select(NotificationAttempt)
                .where(NotificationAttempt.notification_id == row.id)
                .order_by(NotificationAttempt.attempt_number.desc())
                .limit(1)
            )
            if latest_attempt is not None:
                latest_attempt.status = "uncertain"
                latest_attempt.completed_at = claimed_at
                latest_attempt.error_summary = reason
            row.status = "uncertain"
            row.last_error = reason
            row.lease_owner = None
            row.lease_expires_at = None
            row.lease_provider = None

        while True:
            row = session.scalar(
                select(IncidentNotification)
                .where(
                    or_(
                        and_(
                            IncidentNotification.status == "pending",
                            IncidentNotification.next_attempt_at <= claimed_at,
                            or_(IncidentNotification.lease_expires_at.is_(None), IncidentNotification.lease_expires_at <= claimed_at),
                        ),
                        and_(
                            IncidentNotification.status == "sending",
                            or_(IncidentNotification.lease_expires_at.is_(None), IncidentNotification.lease_expires_at <= claimed_at),
                        ),
                    )
                )
                .order_by(IncidentNotification.next_attempt_at, IncidentNotification.id)
                .with_for_update(skip_locked=True)
                .limit(1)
            )
            if row is None:
                return None

            if row.status == "sending":
                prior_attempt = session.scalar(
                    select(NotificationAttempt).where(
                        NotificationAttempt.notification_id == row.id,
                        NotificationAttempt.attempt_number == row.attempt_count,
                    )
                )
                if row.lease_provider != "resend_api":
                    # SMTP has no idempotency protocol. A crash at any point after
                    # dispatch began is treated as uncertain and never resent.
                    mark_uncertain(
                        row,
                        "Delivery outcome uncertain after worker restart; not retried to prevent a duplicate",
                    )
                    session.flush()
                    continue

                # Resend's stable idempotency key makes replay safe after a crash.
                first_resend_attempt = session.scalar(
                    select(NotificationAttempt)
                    .where(
                        NotificationAttempt.notification_id == row.id,
                        NotificationAttempt.provider == "resend_api",
                    )
                    .order_by(NotificationAttempt.attempt_number)
                    .limit(1)
                )
                if (
                    first_resend_attempt is not None
                    and claimed_at - _as_utc(first_resend_attempt.started_at) >= RESEND_IDEMPOTENCY_WINDOW
                ):
                    # The provider's idempotency guarantee is time-bounded. Do
                    # not replay a possibly accepted send after that guarantee
                    # expires; surface it for operator reconciliation instead.
                    mark_uncertain(
                        row,
                        "Resend idempotency window expired; delivery requires provider verification",
                    )
                    session.flush()
                    continue
                if prior_attempt is not None:
                    prior_attempt.status = "retrying"
                    prior_attempt.completed_at = claimed_at
                    prior_attempt.error_summary = "Worker lease expired; retrying idempotently"
                row.status = "pending"
                row.lease_owner = None
                row.lease_expires_at = None
                row.lease_provider = None
                session.flush()
                continue

            if provider == "resend_api" and row.attempt_count:
                first_resend_attempt = session.scalar(
                    select(NotificationAttempt)
                    .where(
                        NotificationAttempt.notification_id == row.id,
                        NotificationAttempt.provider == "resend_api",
                    )
                    .order_by(NotificationAttempt.attempt_number)
                    .limit(1)
                )
                if (
                    first_resend_attempt is not None
                    and claimed_at - _as_utc(first_resend_attempt.started_at) >= RESEND_IDEMPOTENCY_WINDOW
                ):
                    mark_uncertain(
                        row,
                        "Resend idempotency window expired; delivery requires provider verification",
                    )
                    session.flush()
                    continue

            attempt_number = row.attempt_count + 1
            row.attempt_count = attempt_number
            row.status = "sending"
            row.lease_owner = worker_id
            row.lease_expires_at = claimed_at + timedelta(seconds=LEASE_SECONDS)
            row.lease_provider = provider
            session.add(NotificationAttempt(
                notification_id=row.id,
                attempt_number=attempt_number,
                provider=provider,
                status="sending",
                started_at=claimed_at,
                completed_at=None,
            ))
            return {
                "id": row.id,
                "worker_id": worker_id,
                "incident_id": row.incident_id,
                "event_type": row.event_type,
                "attempt_number": attempt_number,
                "claimed_at": claimed_at,
            }


def _finish_attempt(
    session_factory: sessionmaker[Session],
    claim: dict,
    error: str | None,
    *,
    provider: str,
    retryable: bool = True,
    terminal_status: str = "failed",
    now: datetime | None = None,
) -> None:
    completed = now or utc_now()
    with session_factory.begin() as session:
        row = session.scalar(select(IncidentNotification).where(IncidentNotification.id == claim["id"]).with_for_update())
        if row is None or row.lease_owner != claim["worker_id"]:
            return
        succeeded = error is None
        terminal = not succeeded and (not retryable or row.attempt_count >= MAX_ATTEMPTS)
        attempt = session.scalar(select(NotificationAttempt).where(
            NotificationAttempt.notification_id == row.id,
            NotificationAttempt.attempt_number == claim["attempt_number"],
        ).with_for_update())
        if attempt is None:
            logger.error("Notification attempt history is missing (notification_id=%s).", row.id)
            return
        attempt.provider = provider
        attempt.status = "delivered" if succeeded else terminal_status if terminal else "retrying"
        attempt.completed_at = completed
        attempt.error_summary = (
            None if succeeded else
            "Delivery outcome uncertain; not retried" if terminal and terminal_status == "uncertain" else
            "Email provider unavailable" if not terminal else "Delivery failed after retry limit"
        )
        row.lease_owner = None
        row.lease_expires_at = None
        row.lease_provider = None
        if error is None:
            row.status = "delivered"
            row.delivered_at = completed
            row.last_error = None
        elif terminal:
            row.status = terminal_status
            row.last_error = (
                "Delivery outcome uncertain; not retried to prevent a duplicate"
                if terminal_status == "uncertain"
                else "Delivery failed after retry limit"
                if row.attempt_count >= MAX_ATTEMPTS
                else "Email provider rejected the message"
            )
        else:
            row.status = "pending"
            row.next_attempt_at = completed + timedelta(seconds=min(3600, 5 * (2 ** (row.attempt_count - 1))))
            row.last_error = "Email provider unavailable"


def _suppress(session_factory: sessionmaker[Session], claim: dict) -> None:
    with session_factory.begin() as session:
        row = session.scalar(select(IncidentNotification).where(IncidentNotification.id == claim["id"]).with_for_update())
        if row is not None and row.lease_owner == claim["worker_id"]:
            row.status = "suppressed"
            row.lease_owner = None
            row.lease_expires_at = None
            row.lease_provider = None
            attempt = session.scalar(select(NotificationAttempt).where(
                NotificationAttempt.notification_id == row.id,
                NotificationAttempt.attempt_number == claim["attempt_number"],
            ).with_for_update())
            if attempt is not None:
                attempt.status = "suppressed"
                attempt.completed_at = utc_now()


def process_one_notification(session_factory: sessionmaker[Session], worker_id: str, config: dict | None = None) -> bool:
    config = config or _config()
    provider = config.get("provider", "smtp")
    claim = claim_notification(session_factory, worker_id, provider=provider)
    if claim is None:
        return False
    if claim["event_type"] == "resolved" and not config["resolve_enabled"]:
        _suppress(session_factory, claim)
        return True
    if config["dev_mode"]:
        logger.info("Development email suppressed (notification_id=%s, event=%s).", claim["id"], claim["event_type"])
        _suppress(session_factory, claim)
        return True
    if provider == "resend_api":
        configured = bool(config.get("resend_api_key") and config.get("sender") and config.get("recipient"))
    elif provider == "smtp":
        configured = bool(config.get("host") and config.get("sender") and config.get("recipient"))
        configured = configured and config["starttls"] or (
            configured
            and config.get("environment") != "production"
            and config.get("host", "").lower() in {"localhost", "127.0.0.1", "::1", "mailpit"}
            and not config.get("username")
            and not config.get("password")
        )
        configured = configured and (bool(config.get("username")) == bool(config.get("password")))
    else:
        configured = False
    if not configured:
        logger.error("Email delivery configuration is incomplete (notification_id=%s).", claim["id"])
        _finish_attempt(session_factory, claim, "configuration", provider=provider)
        return True
    try:
        with session_factory() as session:
            row = session.get(IncidentNotification, claim["id"])
            message = _message(session, row, config)
        send_email(message, config)
    except DeliveryOutcomeUncertain:
        logger.warning("Email delivery outcome is uncertain (notification_id=%s); not retrying to avoid a duplicate.", claim["id"])
        _finish_attempt(
            session_factory, claim, "uncertain", provider=provider,
            retryable=False, terminal_status="uncertain",
        )
    except DeliveryRejected:
        logger.warning("Email provider rejected notification (notification_id=%s).", claim["id"])
        _finish_attempt(
            session_factory, claim, "rejected", provider=provider,
            retryable=False, terminal_status="failed",
        )
    except SafeDeliveryRetry:
        logger.warning("Email provider was unavailable before accepting notification (notification_id=%s).", claim["id"])
        _finish_attempt(session_factory, claim, "provider", provider=provider)
    except Exception:
        logger.warning("Email delivery attempt failed (notification_id=%s).", claim["id"])
        if provider == "resend_api":
            # Resend receives a stable idempotency key for every retry.
            _finish_attempt(session_factory, claim, "provider", provider=provider)
        else:
            _finish_attempt(
                session_factory, claim, "uncertain", provider=provider,
                retryable=False, terminal_status="uncertain",
            )
    else:
        _finish_attempt(session_factory, claim, None, provider=provider)
    return True


async def run_worker(*, poll_seconds: float = POLL_SECONDS, worker_id: str | None = None) -> None:
    engine = create_database_engine()
    worker_id = worker_id or f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    try:
        while True:
            try:
                initialize_database(engine)
                break
            except SQLAlchemyError:
                logger.error("Notification worker cannot reach its database; retrying startup.")
                await asyncio.sleep(poll_seconds)
        factory = session_factory_for(engine)
        logger.info("Incident notification worker started (worker_id=%s).", worker_id)
        while True:
            dispatch = asyncio.create_task(asyncio.to_thread(process_one_notification, factory, worker_id))
            try:
                # Let an in-flight bounded SMTP attempt finish before disposing
                # the engine; the stable Message-ID helps downstream dedupe.
                did_work = await asyncio.shield(dispatch)
            except asyncio.CancelledError:
                try:
                    await asyncio.shield(dispatch)
                except Exception:
                    pass
                raise
            except SQLAlchemyError:
                logger.error("Notification worker database operation failed; retrying.")
                did_work = False
            except Exception:
                logger.error("Notification worker encountered an unexpected error; retrying.")
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
        logger.info("Incident notification worker stopped.")
