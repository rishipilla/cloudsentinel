import asyncio
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy import select

from database.models import IncidentNotification, MonitoringCheck, MonitoringIncident, MonitoringSchedule, NotificationAttempt
from services.api import main, notifications, scheduler
from services.api import worker as combined_worker


@pytest.fixture(autouse=True)
def production_gateway_secret(monkeypatch):
    monkeypatch.setenv("CLOUDSENTINEL_GATEWAY_SECRET", "v8Nq5rT2xW7cM1pL4zA9hF6dK3sB0yE2")


def _result(failed=False):
    value = {
        "url": "https://alerts.example.com/health",
        "status": "down" if failed else "healthy",
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    value.update({"error": "Request timed out"} if failed else {"status_code": 200, "latency_ms": 8})
    return value


def test_incident_open_and_resolution_enqueue_once_and_delivery_retries(monkeypatch):
    app = main.create_app("sqlite+pysqlite:///:memory:")
    config = {
        "host": "smtp.example.test", "port": 587, "username": "user", "password": "secret",
        "sender": "alerts@example.test", "recipient": "ops@example.test", "starttls": True,
        "dev_mode": False, "resolve_enabled": True,
        "provider": "resend_api", "resend_api_key": "test-api-key",
    }
    with TestClient(app) as client:
        response = client.post("/api/v1/schedules", json={
            "url": "https://alerts.example.com/health", "interval_seconds": 60,
            "failure_threshold": 1,
        })
        schedule_id = response.json()["id"]
        for _ in range(2):
            with app.state.session_factory.begin() as session:
                session.get(MonitoringSchedule, schedule_id).next_run_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            assert asyncio.run(scheduler.run_one_due_check(
                app.state.session_factory, "notify-worker", AsyncMock(return_value=_result(True))
            ))
        with app.state.session_factory() as session:
            events = session.scalars(select(IncidentNotification)).all()
        assert [(event.event_type, event.status) for event in events] == [("opened", "pending")]

        # SMTP sender is synchronous by design; use a simple mock callable.
        attempts = {"count": 0}
        retry_keys = []
        def fail_once_then_send(message, settings):
            attempts["count"] += 1
            retry_keys.append(message["X-CloudSentinel-Event-Key"])
            if attempts["count"] == 1:
                raise OSError("smtp details must not be persisted")
        monkeypatch.setattr(notifications, "send_email", fail_once_then_send)
        assert notifications.process_one_notification(app.state.session_factory, "mail-worker", config)
        with app.state.session_factory.begin() as session:
            event = session.scalar(select(IncidentNotification))
            assert event.status == "pending"
            assert event.attempt_count == 1
            assert event.last_error == "Email provider unavailable"
            event.next_attempt_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        assert notifications.process_one_notification(app.state.session_factory, "mail-worker", config)
        with app.state.session_factory() as session:
            event = session.scalar(select(IncidentNotification))
            incident = session.scalar(select(MonitoringIncident))
        assert event.status == "delivered"
        assert event.attempt_count == 2
        assert retry_keys[0] == retry_keys[1]
        assert incident.resolved_at is None
        history = client.get("/api/v1/notifications").json()["notifications"]
        opened = next(item for item in history if item["event_type"] == "opened")
        assert opened["status"] == "delivered"
        assert [attempt["status"] for attempt in opened["attempts"]] == ["delivered", "retrying"]
        # A repeated poll after delivery must not send a second copy.
        assert notifications.process_one_notification(app.state.session_factory, "mail-worker", config) is False
        assert attempts["count"] == 2

        with app.state.session_factory.begin() as session:
            session.get(MonitoringSchedule, schedule_id).next_run_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        assert asyncio.run(scheduler.run_one_due_check(
            app.state.session_factory, "notify-worker", AsyncMock(return_value=_result(False))
        ))
        with app.state.session_factory() as session:
            rows = session.scalars(select(IncidentNotification).order_by(IncidentNotification.id)).all()
        assert [row.event_type for row in rows] == ["opened", "resolved"]
        assert notifications.process_one_notification(app.state.session_factory, "mail-worker", config)
        with app.state.session_factory() as session:
            resolved = session.scalar(select(IncidentNotification).where(IncidentNotification.event_type == "resolved"))
        assert resolved.status == "delivered"
        assert attempts["count"] == 3

        # A failure after recovery opens a distinct incident and lifecycle event.
        with app.state.session_factory.begin() as session:
            session.get(MonitoringSchedule, schedule_id).next_run_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        assert asyncio.run(scheduler.run_one_due_check(
            app.state.session_factory, "notify-worker", AsyncMock(return_value=_result(True))
        ))
        with app.state.session_factory() as session:
            rows = session.scalars(select(IncidentNotification).order_by(IncidentNotification.id)).all()
        assert [row.event_type for row in rows] == ["opened", "resolved", "opened"]
        assert rows[0].incident_id != rows[2].incident_id
        assert notifications.process_one_notification(app.state.session_factory, "mail-worker", config)
        assert attempts["count"] == 4


def test_development_mode_suppresses_email_without_provider_call(monkeypatch):
    app = main.create_app("sqlite+pysqlite:///:memory:")
    with TestClient(app) as client:
        schedule_id = client.post("/api/v1/schedules", json={
            "url": "https://alerts.example.com/health", "interval_seconds": 60,
            "failure_threshold": 1,
        }).json()["id"]
        with app.state.session_factory.begin() as session:
            session.get(MonitoringSchedule, schedule_id).next_run_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        asyncio.run(scheduler.run_one_due_check(app.state.session_factory, "worker", AsyncMock(return_value=_result(True))))
        send = AsyncMock(side_effect=AssertionError("must not send"))
        monkeypatch.setattr(notifications, "send_email", send)
        assert notifications.process_one_notification(app.state.session_factory, "mail-worker", {"dev_mode": True, "resolve_enabled": False})
        with app.state.session_factory() as session:
            event = session.scalar(select(IncidentNotification))
        assert event.status == "suppressed"
        send.assert_not_awaited()


def test_notification_delivery_stops_after_bounded_attempts(monkeypatch):
    app = main.create_app("sqlite+pysqlite:///:memory:")
    config = {
        "host": "smtp.example.test", "port": 587, "username": "", "password": "",
        "sender": "alerts@example.test", "recipient": "ops@example.test", "starttls": True,
        "dev_mode": False, "resolve_enabled": True,
        "provider": "resend_api", "resend_api_key": "test-api-key",
    }
    with TestClient(app) as client:
        schedule_id = client.post("/api/v1/schedules", json={
            "url": "https://alerts.example.com/health", "interval_seconds": 60,
            "failure_threshold": 1,
        }).json()["id"]
        with app.state.session_factory.begin() as session:
            session.get(MonitoringSchedule, schedule_id).next_run_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        asyncio.run(scheduler.run_one_due_check(app.state.session_factory, "worker", AsyncMock(return_value=_result(True))))

        calls = {"count": 0}
        def unavailable(message, settings):
            calls["count"] += 1
            raise OSError("private provider response")
        monkeypatch.setattr(notifications, "send_email", unavailable)
        for attempt in range(notifications.MAX_ATTEMPTS):
            assert notifications.process_one_notification(app.state.session_factory, "mail-worker", config)
            with app.state.session_factory.begin() as session:
                event = session.scalar(select(IncidentNotification))
                if event.status == "pending":
                    event.next_attempt_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        with app.state.session_factory() as session:
            event = session.scalar(select(IncidentNotification))
        assert event.status == "failed"
        assert event.attempt_count == notifications.MAX_ATTEMPTS
        assert event.last_error == "Delivery failed after retry limit"
        assert calls["count"] == notifications.MAX_ATTEMPTS


def test_api_token_protects_api_but_health_is_available(monkeypatch):
    monkeypatch.setenv("CLOUDSENTINEL_API_TOKEN", "test-token")
    app = main.create_app("sqlite+pysqlite:///:memory:")
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/api/v1/schedules").status_code == 401
        assert client.get("/api/v1/schedules", headers={"Authorization": "Bearer wrong"}).status_code == 401
        assert client.get("/api/v1/schedules", headers={"Authorization": "Bearer test-token"}).status_code == 200


def test_bearer_authentication_covers_every_api_route(monkeypatch):
    monkeypatch.setenv("CLOUDSENTINEL_API_TOKEN", "test-token")
    monkeypatch.setenv("CLOUDSENTINEL_AUTH_RATE_LIMIT", "100")
    app = main.create_app("sqlite+pysqlite:///:memory:")
    routes = [
        ("POST", "/api/v1/reputation"),
        ("GET", "/api/v1/notifications"),
        ("GET", "/api/v1/checks"),
        ("POST", "/api/v1/schedules"),
        ("GET", "/api/v1/schedules"),
        ("GET", "/api/v1/schedules/1/history"),
        ("GET", "/api/v1/schedules/1"),
        ("PATCH", "/api/v1/schedules/1"),
        ("DELETE", "/api/v1/schedules/1"),
        ("GET", "/api/v1/incidents"),
        ("POST", "/api/v1/check"),
    ]

    with TestClient(app) as client:
        missing_responses = [client.request(method, path) for method, path in routes]
        invalid_responses = [
            client.request(method, path, headers={"Authorization": "Bearer invalid-token"})
            for method, path in routes
        ]

    assert [response.status_code for response in missing_responses] == [401] * len(routes)
    assert [response.status_code for response in invalid_responses] == [401] * len(routes)


def test_production_api_fails_closed_when_token_missing(monkeypatch):
    monkeypatch.setenv("CLOUDSENTINEL_ENV", "production")
    monkeypatch.setenv("CLOUDSENTINEL_ALLOWED_HOSTS", "testserver")
    monkeypatch.setenv("CLOUDSENTINEL_TARGET_ALLOWLIST", "example.com")
    monkeypatch.delenv("CLOUDSENTINEL_API_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="CLOUDSENTINEL_API_TOKEN must be set"):
        main.create_app("sqlite+pysqlite:///:memory:")


def test_production_trusts_render_hostname_without_wildcard(monkeypatch):
    monkeypatch.setenv("CLOUDSENTINEL_ENV", "production")
    monkeypatch.delenv("CLOUDSENTINEL_ALLOWED_HOSTS", raising=False)
    monkeypatch.setenv("RENDER_EXTERNAL_HOSTNAME", "cloudsentinel-web.onrender.com")
    monkeypatch.setenv("CLOUDSENTINEL_API_TOKEN", "test-deployment-token-0123456789abcdef")
    monkeypatch.setenv("CLOUDSENTINEL_TARGET_ALLOWLIST", "example.com")
    app = main.create_app("sqlite+pysqlite:///:memory:")
    with TestClient(app) as client:
        assert client.get(
            "/health", headers={"Host": "cloudsentinel-web.onrender.com"},
        ).status_code == 200
        assert client.get(
            "/health", headers={"Host": "attacker.example"},
        ).status_code == 400


def test_production_rejects_wildcard_allowed_hosts(monkeypatch):
    monkeypatch.setenv("CLOUDSENTINEL_ENV", "production")
    monkeypatch.setenv("CLOUDSENTINEL_API_TOKEN", "test-deployment-token-0123456789abcdef")
    monkeypatch.setenv("CLOUDSENTINEL_ALLOWED_HOSTS", "*")
    monkeypatch.delenv("RENDER_EXTERNAL_HOSTNAME", raising=False)
    with pytest.raises(RuntimeError, match="Wildcard hosts"):
        main.create_app("sqlite+pysqlite:///:memory:")


def test_production_rejects_short_api_tokens(monkeypatch):
    monkeypatch.setenv("CLOUDSENTINEL_ENV", "production")
    monkeypatch.setenv("CLOUDSENTINEL_API_TOKEN", "weak-token")
    monkeypatch.setenv("CLOUDSENTINEL_ALLOWED_HOSTS", "testserver")
    with pytest.raises(RuntimeError, match="strong, non-default secret"):
        main.create_app("sqlite+pysqlite:///:memory:")


@pytest.mark.parametrize("token", ["change-me", "a" * 48, "please-change-me-before-production-12345"])
def test_production_rejects_default_or_low_diversity_tokens(monkeypatch, token):
    monkeypatch.setenv("CLOUDSENTINEL_ENV", "production")
    monkeypatch.setenv("CLOUDSENTINEL_API_TOKEN", token)
    monkeypatch.setenv("CLOUDSENTINEL_ALLOWED_HOSTS", "testserver")
    monkeypatch.setenv("CLOUDSENTINEL_TARGET_ALLOWLIST", "example.com")
    with pytest.raises(RuntimeError, match="strong, non-default secret"):
        main.create_app("sqlite+pysqlite:///:memory:")


def test_production_rejects_missing_host_configuration(monkeypatch):
    monkeypatch.setenv("CLOUDSENTINEL_ENV", "production")
    monkeypatch.setenv("CLOUDSENTINEL_API_TOKEN", "test-deployment-token-0123456789abcdef")
    monkeypatch.delenv("CLOUDSENTINEL_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("RENDER_EXTERNAL_HOSTNAME", raising=False)
    monkeypatch.setenv("CLOUDSENTINEL_TARGET_ALLOWLIST", "example.com")
    with pytest.raises(RuntimeError, match="CLOUDSENTINEL_ALLOWED_HOSTS"):
        main.create_app("sqlite+pysqlite:///:memory:")


@pytest.mark.parametrize("origin", ["*", "https://*.example.com", "http://dashboard.example.com", "https://dashboard.example.com/path"])
def test_production_rejects_wildcard_or_non_origin_cors_values(monkeypatch, origin):
    monkeypatch.setenv("CLOUDSENTINEL_ENV", "production")
    monkeypatch.setenv("CLOUDSENTINEL_API_TOKEN", "test-deployment-token-0123456789abcdef")
    monkeypatch.setenv("CLOUDSENTINEL_ALLOWED_HOSTS", "testserver")
    monkeypatch.setenv("CLOUDSENTINEL_TARGET_ALLOWLIST", "example.com")
    monkeypatch.setenv("CLOUDSENTINEL_CORS_ORIGINS", origin)
    with pytest.raises(RuntimeError, match="CLOUDSENTINEL_CORS_ORIGINS"):
        main.create_app("sqlite+pysqlite:///:memory:")


def test_production_cors_allows_only_the_explicit_https_origin(monkeypatch):
    monkeypatch.setenv("CLOUDSENTINEL_ENV", "production")
    monkeypatch.setenv("CLOUDSENTINEL_API_TOKEN", "test-deployment-token-0123456789abcdef")
    monkeypatch.setenv("CLOUDSENTINEL_ALLOWED_HOSTS", "testserver")
    monkeypatch.setenv("CLOUDSENTINEL_TARGET_ALLOWLIST", "example.com")
    monkeypatch.setenv("CLOUDSENTINEL_CORS_ORIGINS", "https://dashboard.example.com")
    app = main.create_app("sqlite+pysqlite:///:memory:")

    with TestClient(app) as client:
        approved = client.get("/health", headers={"Origin": "https://dashboard.example.com"})
        unapproved = client.get("/health", headers={"Origin": "https://attacker.example"})

    assert approved.headers["access-control-allow-origin"] == "https://dashboard.example.com"
    assert "access-control-allow-origin" not in unapproved.headers


def test_health_endpoints_return_only_health_state(monkeypatch):
    monkeypatch.setenv("CLOUDSENTINEL_ENV", "production")
    monkeypatch.setenv("CLOUDSENTINEL_API_TOKEN", "test-deployment-token-0123456789abcdef")
    monkeypatch.setenv("CLOUDSENTINEL_ALLOWED_HOSTS", "testserver")
    monkeypatch.setenv("CLOUDSENTINEL_TARGET_ALLOWLIST", "example.com")
    app = main.create_app("sqlite+pysqlite:///:memory:")

    with TestClient(app) as client:
        liveness = client.get("/health")
        readiness = client.get(
            "/health/ready",
            headers={"X-CloudSentinel-Gateway-Secret": "v8Nq5rT2xW7cM1pL4zA9hF6dK3sB0yE2"},
        )

    assert app.debug is False
    assert liveness.json() == {"status": "healthy"}
    assert readiness.json() == {"status": "ready", "database": "ready"}


def test_production_requires_an_explicit_target_allowlist(monkeypatch):
    monkeypatch.setenv("CLOUDSENTINEL_ENV", "production")
    monkeypatch.setenv("CLOUDSENTINEL_ALLOWED_HOSTS", "testserver")
    monkeypatch.setenv("CLOUDSENTINEL_API_TOKEN", "test-deployment-token-0123456789abcdef")
    monkeypatch.delenv("CLOUDSENTINEL_TARGET_ALLOWLIST", raising=False)
    with pytest.raises(RuntimeError, match="CLOUDSENTINEL_TARGET_ALLOWLIST"):
        main.create_app("sqlite+pysqlite:///:memory:")


def test_render_blueprint_wires_runtime_variables_to_correct_services():
    blueprint = yaml.safe_load((Path(__file__).resolve().parents[1] / "render.yaml").read_text())
    services = {service["type"]: service for service in blueprint["services"]}
    web_vars = {item["key"]: item for item in services["web"]["envVars"]}
    worker_vars = {item["key"]: item for item in services["worker"]["envVars"]}
    database = blueprint["databases"][0]

    assert services["web"]["startCommand"] == "python -m uvicorn services.api.main:app --host 0.0.0.0 --port $PORT"
    assert services["web"]["healthCheckPath"] == "/health"
    assert services["worker"]["startCommand"] == "python -m services.api.worker"
    assert web_vars["DATABASE_URL"]["fromDatabase"]["name"] == database["name"]
    assert worker_vars["DATABASE_URL"]["fromDatabase"]["name"] == database["name"]
    assert web_vars["CLOUDSENTINEL_ENV"]["value"] == "production"
    assert worker_vars["CLOUDSENTINEL_ENV"]["value"] == "production"
    assert web_vars["CLOUDSENTINEL_TARGET_ALLOWLIST"]["sync"] is False
    assert worker_vars["CLOUDSENTINEL_TARGET_ALLOWLIST"]["sync"] is False
    assert web_vars["CLOUDSENTINEL_API_TOKEN"]["sync"] is False
    assert web_vars["CLOUDSENTINEL_GATEWAY_SECRET"]["sync"] is False
    assert web_vars["CLOUDSENTINEL_GATEWAY_RATE_LIMIT"]["value"] == "120"
    assert "CLOUDSENTINEL_API_TOKEN" not in worker_vars
    assert web_vars["CLOUDSENTINEL_REPUTATION_RATE_LIMIT"]["value"] == "30"
    assert web_vars["VIRUSTOTAL_API_KEY"]["sync"] is False
    assert "VIRUSTOTAL_API_KEY" not in worker_vars
    assert database["ipAllowList"] == []
    assert database["diskSizeGB"] == 1


def test_notification_worker_shutdown_disposes_resources(monkeypatch):
    class FakeEngine:
        disposed = False
        def dispose(self):
            self.disposed = True

    engine = FakeEngine()
    monkeypatch.setattr(notifications, "create_database_engine", lambda: engine)
    monkeypatch.setattr(notifications, "initialize_database", lambda current: None)
    monkeypatch.setattr(notifications, "session_factory_for", lambda current: object())
    monkeypatch.setattr(notifications, "process_one_notification", lambda *args: False)

    async def cancel_worker():
        task = asyncio.create_task(notifications.run_worker(poll_seconds=60, worker_id="shutdown-test"))
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(cancel_worker())
    assert engine.disposed is True


def test_resend_api_uses_stable_idempotency_and_parses_multiple_recipients(monkeypatch):
    requests = []

    class Response:
        def raise_for_status(self):
            return None

    class Client:
        def __init__(self, **options):
            assert options["timeout"] == 10.0
            assert options["trust_env"] is False
            assert options["follow_redirects"] is False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def post(self, url, **options):
            requests.append((url, options))
            return Response()

    monkeypatch.setattr(httpx, "Client", Client)
    message = EmailMessage()
    message["From"] = "CloudSentinel <alerts@example.test>"
    message["To"] = "ops@example.test, oncall@example.test"
    message["Subject"] = "Incident opened"
    message["X-CloudSentinel-Event-Key"] = "incident-42-opened"
    message.set_content("Availability incident.")
    notifications.send_email(message, {"provider": "resend_api", "resend_api_key": "test-key"})

    url, options = requests[0]
    assert url == "https://api.resend.com/emails"
    assert options["headers"]["Idempotency-Key"] == "incident-42-opened"
    assert options["json"]["to"] == ["ops@example.test", "oncall@example.test"]


def test_outbox_event_key_is_stable_for_retries_but_unique_across_fresh_databases():
    app = main.create_app("sqlite+pysqlite:///:memory:")
    config = {
        "sender": "alerts@example.test", "recipient": "ops@example.test",
    }
    with TestClient(app):
        schedule = MonitoringSchedule(
            target_url="https://alerts.example.com/health", interval_seconds=60,
            timeout_seconds=5, failure_threshold=1, enabled=True,
            created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc),
            next_run_at=datetime.now(timezone.utc), consecutive_failures=0,
        )
        with app.state.session_factory.begin() as session:
            session.add(schedule)
            session.flush()
            check = MonitoringCheck(
                checked_url=schedule.target_url, checked_at=datetime.now(timezone.utc),
                is_success=False, status_code=None, latency_ms=None,
                error_detail="Request timed out",
            )
            session.add(check)
            session.flush()
            incident = MonitoringIncident(
                schedule_id=schedule.id, started_at=datetime.now(timezone.utc),
                failure_count=1, latest_error="Request timed out", latest_check_id=check.id,
            )
            session.add(incident)
            session.flush()
            event = IncidentNotification(
                incident_id=incident.id, event_type="opened", status="pending",
                attempt_count=0, created_at=datetime.now(timezone.utc),
                next_attempt_at=datetime.now(timezone.utc),
            )
            session.add(event)
            session.flush()
            first = notifications._message(session, event, config)
            same_event_retry = notifications._message(session, event, config)
            assert first["X-CloudSentinel-Event-Key"] == same_event_retry["X-CloudSentinel-Event-Key"]
            assert first["Message-ID"] == same_event_retry["Message-ID"]

            # A separate database can have the same integer IDs; its event
            # creation time still produces an independent provider key.
            event.created_at += timedelta(seconds=1)
            separate_event = notifications._message(session, event, config)
            assert separate_event["X-CloudSentinel-Event-Key"] != first["X-CloudSentinel-Event-Key"]


def test_combined_worker_gracefully_cancels_both_loops(monkeypatch):
    stopped = []

    async def wait_for_shutdown(name):
        try:
            await asyncio.Event().wait()
        finally:
            stopped.append(name)

    monkeypatch.setattr(combined_worker, "run_scheduler_worker", lambda: wait_for_shutdown("scheduler"))
    monkeypatch.setattr(combined_worker, "run_notification_worker", lambda: wait_for_shutdown("notifications"))

    async def exercise():
        signal_event = asyncio.Event()
        task = asyncio.create_task(combined_worker.run_worker(signal_event))
        await asyncio.sleep(0)
        signal_event.set()
        await task

    asyncio.run(exercise())
    assert sorted(stopped) == ["notifications", "scheduler"]


def test_uncertain_smtp_outcome_is_not_retried(monkeypatch):
    app = main.create_app("sqlite+pysqlite:///:memory:")
    with TestClient(app) as client:
        schedule_id = client.post("/api/v1/schedules", json={
            "url": "https://alerts.example.com/health", "interval_seconds": 60,
            "failure_threshold": 1,
        }).json()["id"]
        with app.state.session_factory.begin() as session:
            session.get(MonitoringSchedule, schedule_id).next_run_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        asyncio.run(scheduler.run_one_due_check(
            app.state.session_factory, "worker", AsyncMock(return_value=_result(True)),
        ))
        def uncertain(*_args):
            raise notifications.DeliveryOutcomeUncertain()

        monkeypatch.setattr(notifications, "send_email", uncertain)
        smtp_config = {
            "host": "127.0.0.1", "port": 1025, "username": "", "password": "",
            "sender": "alerts@example.test", "recipient": "ops@example.test",
            "starttls": False, "dev_mode": False, "resolve_enabled": False,
            "provider": "smtp", "environment": "development",
        }
        assert notifications.process_one_notification(app.state.session_factory, "mail-worker", smtp_config)
        assert notifications.process_one_notification(app.state.session_factory, "mail-worker", smtp_config) is False
        history = client.get("/api/v1/notifications").json()["notifications"][0]
        assert history["status"] == "uncertain"
        assert history["attempt_count"] == 1
        assert history["attempts"][0]["status"] == "uncertain"


def test_crashed_smtp_worker_lease_is_terminally_uncertain():
    app = main.create_app("sqlite+pysqlite:///:memory:")
    with TestClient(app):
        schedule = MonitoringSchedule(
            target_url="https://alerts.example.com/health",
            interval_seconds=60,
            timeout_seconds=5,
            failure_threshold=1,
            enabled=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            next_run_at=datetime.now(timezone.utc),
            consecutive_failures=0,
        )
        with app.state.session_factory.begin() as session:
            session.add(schedule)
            session.flush()
            check = MonitoringCheck(
                checked_url=schedule.target_url,
                checked_at=datetime.now(timezone.utc),
                is_success=False,
                status_code=None,
                latency_ms=None,
                error_detail="Request timed out",
            )
            session.add(check)
            session.flush()
            incident = MonitoringIncident(
                schedule_id=schedule.id,
                started_at=datetime.now(timezone.utc),
                failure_count=1,
                latest_error="Request timed out",
                latest_check_id=check.id,
            )
            session.add(incident)
            session.flush()
            event = IncidentNotification(
                incident_id=incident.id,
                event_type="opened",
                status="pending",
                attempt_count=0,
                created_at=datetime.now(timezone.utc),
                next_attempt_at=datetime.now(timezone.utc) - timedelta(seconds=1),
            )
            session.add(event)
            session.flush()
            event_id = event.id

        claimed = notifications.claim_notification(app.state.session_factory, "smtp-crash", provider="smtp")
        assert claimed is not None and claimed["id"] == event_id
        recovered = notifications.claim_notification(
            app.state.session_factory,
            "smtp-recovery",
            provider="smtp",
            now=claimed["claimed_at"] + timedelta(seconds=notifications.LEASE_SECONDS + 1),
        )
        assert recovered is None
        with app.state.session_factory() as session:
            event = session.get(IncidentNotification, event_id)
            attempt = session.scalar(select(NotificationAttempt).where(NotificationAttempt.notification_id == event_id))
        assert event.status == "uncertain"
        assert event.attempt_count == 1
        assert attempt.status == "uncertain"


def test_expired_resend_idempotency_window_is_not_replayed():
    app = main.create_app("sqlite+pysqlite:///:memory:")
    now = datetime.now(timezone.utc)
    with TestClient(app):
        schedule = MonitoringSchedule(
            target_url="https://alerts.example.com/health", interval_seconds=60,
            timeout_seconds=5, failure_threshold=1, enabled=True,
            created_at=now, updated_at=now, next_run_at=now, consecutive_failures=0,
        )
        with app.state.session_factory.begin() as session:
            session.add(schedule)
            session.flush()
            check = MonitoringCheck(
                checked_url=schedule.target_url, checked_at=now, is_success=False,
                status_code=None, latency_ms=None, error_detail="Request timed out",
            )
            session.add(check)
            session.flush()
            incident = MonitoringIncident(
                schedule_id=schedule.id, started_at=now, failure_count=1,
                latest_error="Request timed out", latest_check_id=check.id,
            )
            session.add(incident)
            session.flush()
            event = IncidentNotification(
                incident_id=incident.id, event_type="opened", status="sending",
                attempt_count=1, created_at=now - timedelta(hours=25),
                next_attempt_at=now - timedelta(hours=25), lease_owner="crashed-worker",
                lease_expires_at=now - timedelta(seconds=1), lease_provider="resend_api",
            )
            session.add(event)
            session.flush()
            session.add(NotificationAttempt(
                notification_id=event.id, attempt_number=1, provider="resend_api",
                status="sending", started_at=now - timedelta(hours=25), completed_at=None,
            ))
            event_id = event.id

        assert notifications.claim_notification(
            app.state.session_factory, "recovery-worker", provider="resend_api", now=now,
        ) is None
        with app.state.session_factory() as session:
            event = session.get(IncidentNotification, event_id)
            attempt = session.scalar(select(NotificationAttempt).where(
                NotificationAttempt.notification_id == event_id,
            ))
        assert event.status == "uncertain"
        assert "idempotency window expired" in event.last_error
        assert event.attempt_count == 1
        assert attempt.status == "uncertain"
