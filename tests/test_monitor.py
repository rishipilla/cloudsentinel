import asyncio
import os
import secrets
import threading
from datetime import datetime, timezone
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from database.models import IncidentNotification, MonitoringCheck, MonitoringIncident, MonitoringSchedule
from database.session import database_url_from_environment
from services.api import main


def make_result(
    *,
    url: str = "https://service.example/health",
    status: str = "healthy",
    status_code: int | None = 200,
    latency_ms: float | None = 23.4,
    error: str | None = None,
) -> dict:
    result = {
        "url": url,
        "status": status,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    if status_code is not None:
        result["status_code"] = status_code
    if latency_ms is not None:
        result["latency_ms"] = latency_ms
    if error is not None:
        result["error"] = error
    return result


def test_successful_probe_is_persisted_and_response_is_unchanged(monkeypatch):
    result = make_result()
    probe = AsyncMock(return_value=result)
    monkeypatch.setattr(main, "check_endpoint", probe)
    app = main.create_app("sqlite+pysqlite:///:memory:")

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/check",
            json={"url": result["url"], "timeout_seconds": 2.5},
        )
        assert response.status_code == 200
        assert response.json() == result
        probe.assert_awaited_once_with(result["url"], timeout_seconds=2.5)

        with app.state.session_factory() as session:
            saved = session.scalar(select(MonitoringCheck))

    assert saved is not None
    assert saved.checked_url == result["url"]
    assert saved.is_success is True
    assert saved.status_code == 200
    assert saved.latency_ms == 23.4
    assert saved.error_detail is None
    assert saved.checked_at is not None


def test_failed_probe_is_persisted_without_sensitive_url_values(monkeypatch):
    result = make_result(
        url="https://service.example/check?access_token=secret&region=west",
        status="down",
        status_code=None,
        latency_ms=None,
        error="Request timed out",
    )
    monkeypatch.setattr(main, "check_endpoint", AsyncMock(return_value=result))
    app = main.create_app("sqlite+pysqlite:///:memory:")

    with TestClient(app) as client:
        response = client.post("/api/v1/check", json={"url": result["url"]})
        assert response.status_code == 200
        assert response.json() == {
            **result,
            "url": "https://service.example/check?access_token=%5BREDACTED%5D&region=west",
        }
        assert "secret" not in response.text

        with app.state.session_factory() as session:
            saved = session.scalar(select(MonitoringCheck))

    assert saved is not None
    assert saved.checked_url == (
        "https://service.example/check?access_token=%5BREDACTED%5D&region=west"
    )
    assert saved.is_success is False
    assert saved.status_code is None
    assert saved.latency_ms is None
    assert saved.error_detail == "Request timed out"


def test_http_error_response_is_recorded_as_failure(monkeypatch):
    result = make_result(status="down", status_code=503)
    monkeypatch.setattr(main, "check_endpoint", AsyncMock(return_value=result))
    app = main.create_app("sqlite+pysqlite:///:memory:")

    with TestClient(app) as client:
        response = client.post("/api/v1/check", json={"url": result["url"]})
        assert response.status_code == 200
        with app.state.session_factory() as session:
            saved = session.scalar(select(MonitoringCheck))

    assert saved is not None
    assert saved.is_success is False
    assert saved.error_detail == "HTTP response status 503"


def test_unrecognized_error_detail_is_not_stored(monkeypatch):
    result = make_result(
        status="down",
        status_code=None,
        latency_ms=None,
        error="Request failed with token=secret-value",
    )
    monkeypatch.setattr(main, "check_endpoint", AsyncMock(return_value=result))
    app = main.create_app("sqlite+pysqlite:///:memory:")

    with TestClient(app) as client:
        response = client.post("/api/v1/check", json={"url": result["url"]})
        assert response.status_code == 200
        with app.state.session_factory() as session:
            saved = session.scalar(select(MonitoringCheck))

    assert saved is not None
    assert saved.error_detail == "Endpoint probe failed"
    assert "secret-value" not in saved.error_detail


def test_persistence_error_does_not_return_success(monkeypatch):
    result = make_result()
    monkeypatch.setattr(main, "check_endpoint", AsyncMock(return_value=result))

    def fail_persist(*args, **kwargs):
        assert len(args) == 2
        assert not kwargs
        raise SQLAlchemyError("database unavailable")

    monkeypatch.setattr(main, "persist_check", fail_persist)
    app = main.create_app("sqlite+pysqlite:///:memory:")

    with TestClient(app) as client:
        response = client.post("/api/v1/check", json={"url": result["url"]})

    assert response.status_code == 503
    assert response.json() == {
        "detail": "Endpoint check completed but its result could not be saved."
    }


def test_liveness_and_database_readiness_are_distinct(monkeypatch):
    app = main.create_app("sqlite+pysqlite:///:memory:")

    with TestClient(app) as client:
        assert client.get("/health").json() == {"status": "healthy"}
        assert client.get("/health/ready").json() == {
            "status": "ready",
            "database": "ready",
        }

        def fail_readiness(engine):
            assert engine is not None
            raise SQLAlchemyError("database unavailable")

        monkeypatch.setattr(main, "database_is_ready", fail_readiness)
        assert client.get("/health").status_code == 200
        readiness = client.get("/health/ready")

    assert readiness.status_code == 503
    assert readiness.json() == {"detail": "Database is not ready."}


def test_history_returns_real_summary_and_latest_checks(monkeypatch):
    app = main.create_app("sqlite+pysqlite:///:memory:")
    results = [
        make_result(status_code=200, latency_ms=20.0),
        make_result(
            url="https://other.example/",
            status="down",
            status_code=503,
            latency_ms=80.0,
        ),
    ]
    monkeypatch.setattr(main, "check_endpoint", AsyncMock(side_effect=results))

    with TestClient(app) as client:
        for result in results:
            assert client.post("/api/v1/check", json={"url": result["url"]}).status_code == 200
        response = client.get("/api/v1/checks?limit=1")
        assert response.status_code == 200
        payload = response.json()

    assert payload["summary"] == {
        "total_checks": 2,
        "successful_checks": 1,
        "failed_checks": 1,
        "average_latency_ms": 50.0,
    }
    assert len(payload["checks"]) == 1
    assert payload["checks"][0]["url"] == "https://other.example/"
    assert payload["checks"][0]["status"] == "down"
    assert payload["checks"][0]["status_code"] == 503
    assert payload["checks"][0]["error"] == "HTTP response status 503"


def test_empty_history_and_dashboard_assets_are_available():
    app = main.create_app("sqlite+pysqlite:///:memory:")
    with TestClient(app) as client:
        dashboard = client.get("/")
        history = client.get("/api/v1/checks")
        stylesheet = client.get("/static/styles.css")
        frontend_script = client.get("/static/app.js")

    assert dashboard.status_code == 200
    assert "CloudSentinel" in dashboard.text
    assert stylesheet.status_code == 200
    assert frontend_script.status_code == 200
    assert 'getJson("/api/v1/checks?limit=100")' in frontend_script.text
    assert 'getJson("/api/v1/check"' in frontend_script.text
    assert 'check.error || "—"' in frontend_script.text
    assert "Details</th>" in dashboard.text
    assert 'id="schedule-form"' in dashboard.text
    assert 'id="incidents"' in dashboard.text
    assert 'id="notification-delivery"' in dashboard.text
    assert 'id="reputation-form"' in dashboard.text
    assert 'getJson("/api/v1/schedules?limit=100")' in frontend_script.text
    assert 'getJson("/api/v1/incidents?limit=100")' in frontend_script.text
    assert 'getJson("/api/v1/notifications?limit=100")' in frontend_script.text
    assert 'getJson("/api/v1/reputation"' in frontend_script.text
    assert "timeout_seconds: Number(elements.timeout.value)" in frontend_script.text
    assert history.json() == {
        "summary": {
            "total_checks": 0,
            "successful_checks": 0,
            "failed_checks": 0,
            "average_latency_ms": None,
        },
        "checks": [],
    }


def test_production_target_allowlist_matches_domains_and_rejects_lookalikes(monkeypatch):
    from services.api.monitor import TargetRejectedError, validate_target_url

    monkeypatch.setenv("CLOUDSENTINEL_ENV", "production")
    monkeypatch.setenv("CLOUDSENTINEL_TARGET_ALLOWLIST", "example.com,health.example.net")
    validate_target_url("https://api.example.com/health")
    validate_target_url("https://example.com/health")
    with pytest.raises(TargetRejectedError):
        validate_target_url("https://notexample.com/health")


def test_production_target_allowlist_is_closed_when_empty(monkeypatch):
    from services.api.monitor import TargetRejectedError, validate_target_url

    monkeypatch.setenv("CLOUDSENTINEL_ENV", "production")
    monkeypatch.delenv("CLOUDSENTINEL_TARGET_ALLOWLIST", raising=False)
    with pytest.raises(TargetRejectedError):
        validate_target_url("https://example.com/health")


def test_probe_stream_stops_reading_after_response_size_limit(monkeypatch):
    from services.api import monitor

    monkeypatch.setenv("CLOUDSENTINEL_ENV", "development")

    class FakeResponse:
        status_code = 200

        def __init__(self):
            self.chunks_read = 0

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def aiter_bytes(self):
            self.chunks_read += 1
            yield b"x" * (monitor.MAX_RESPONSE_BYTES + 1)
            self.chunks_read += 1
            yield b"this chunk must not be consumed"

    response = FakeResponse()

    class FakeClient:
        def __init__(self, **kwargs):
            self.options = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def stream(self, method, url):
            assert method == "GET"
            assert url == "https://response.example/health"
            return response

    monkeypatch.setattr(monitor.httpx, "AsyncClient", FakeClient)
    result = asyncio.run(monitor.check_endpoint("https://response.example/health"))

    assert result["status_code"] == 200
    assert response.chunks_read == 1


def test_production_target_allowlist_is_enforced_at_schedule_api(monkeypatch):
    test_token = "K9vR2xM5cT8nP1qD4wB7fH3jL6sA0zE9pY"
    monkeypatch.setenv("CLOUDSENTINEL_ENV", "production")
    monkeypatch.setenv("CLOUDSENTINEL_API_TOKEN", test_token)
    monkeypatch.setenv("CLOUDSENTINEL_GATEWAY_SECRET", "v8Nq5rT2xW7cM1pL4zA9hF6dK3sB0yE2")
    monkeypatch.setenv("CLOUDSENTINEL_ALLOWED_HOSTS", "testserver")
    monkeypatch.setenv("CLOUDSENTINEL_TARGET_ALLOWLIST", "approved.example")
    app = main.create_app("sqlite+pysqlite:///:memory:")

    with TestClient(app) as client:
        headers = {
            "Authorization": f"Bearer {test_token}",
            "X-CloudSentinel-Gateway-Secret": "v8Nq5rT2xW7cM1pL4zA9hF6dK3sB0yE2",
        }
        approved = client.post("/api/v1/schedules", headers=headers, json={
            "url": "https://health.approved.example/health", "interval_seconds": 60,
        })
        rejected = client.post("/api/v1/schedules", headers=headers, json={
            "url": "https://other.example/health", "interval_seconds": 60,
        })

    assert approved.status_code == 201
    assert rejected.status_code == 422


def test_production_gateway_secret_is_required_and_checked(monkeypatch):
    token = "K9vR2xM5cT8nP1qD4wB7fH3jL6sA0zE9pY"
    gateway_secret = secrets.token_urlsafe(32)
    monkeypatch.setenv("CLOUDSENTINEL_ENV", "production")
    monkeypatch.setenv("CLOUDSENTINEL_API_TOKEN", token)
    monkeypatch.setenv("CLOUDSENTINEL_ALLOWED_HOSTS", "testserver")
    monkeypatch.setenv("CLOUDSENTINEL_TARGET_ALLOWLIST", "approved.example")
    monkeypatch.delenv("CLOUDSENTINEL_GATEWAY_SECRET", raising=False)
    with pytest.raises(RuntimeError, match="CLOUDSENTINEL_GATEWAY_SECRET"):
        main.create_app("sqlite+pysqlite:///:memory:")

    monkeypatch.setenv("CLOUDSENTINEL_GATEWAY_SECRET", gateway_secret)
    app = main.create_app("sqlite+pysqlite:///:memory:")
    with TestClient(app) as client:
        assert client.get("/api/v1/checks").status_code == 404
        missing_secret = client.get(
            "/api/v1/checks",
        )
        assert missing_secret.headers["cache-control"] == "no-store, private"
        invalid_secret = client.get(
            "/api/v1/checks",
            headers={"X-CloudSentinel-Gateway-Secret": "invalid-gateway-secret"},
        )
        assert invalid_secret.status_code == 404
        assert invalid_secret.headers["cache-control"] == "no-store, private"
        assert client.get("/").status_code == 404
        assert client.get("/health/ready").status_code == 404
        liveness = client.get("/health")
        assert liveness.json() == {"status": "healthy"}
        assert liveness.headers["cache-control"] == "no-store, private"

        gateway_headers = {"X-CloudSentinel-Gateway-Secret": gateway_secret}
        assert client.get("/api/v1/checks", headers=gateway_headers).status_code == 401
        authenticated_headers = {
            **gateway_headers,
            "Authorization": f"Bearer {token}",
        }
        history = client.get("/api/v1/checks", headers=authenticated_headers)
        assert history.status_code == 200
        assert history.headers["cache-control"] == "no-store, private"


def test_authentication_failures_are_rate_limited(monkeypatch):
    monkeypatch.setenv("CLOUDSENTINEL_API_TOKEN", "test-token")
    monkeypatch.setenv("CLOUDSENTINEL_AUTH_RATE_LIMIT", "1")
    app = main.create_app("sqlite+pysqlite:///:memory:")

    with TestClient(app) as client:
        first = client.get("/api/v1/checks")
        second = client.get("/api/v1/checks")

    assert first.status_code == 401
    assert second.status_code == 429
    assert second.headers["retry-after"] == "60"


def test_on_demand_checks_are_rate_limited(monkeypatch):
    monkeypatch.delenv("CLOUDSENTINEL_API_TOKEN", raising=False)
    monkeypatch.setenv("CLOUDSENTINEL_CHECK_RATE_LIMIT", "1")
    result = make_result()
    monkeypatch.setattr(main, "check_endpoint", AsyncMock(return_value=result))
    app = main.create_app("sqlite+pysqlite:///:memory:")

    with TestClient(app) as client:
        first = client.post("/api/v1/check", json={"url": result["url"]})
        second = client.post("/api/v1/check", json={"url": result["url"]})

    assert first.status_code == 200
    assert second.status_code == 429


def test_schedule_creation_is_rate_limited(monkeypatch):
    monkeypatch.delenv("CLOUDSENTINEL_API_TOKEN", raising=False)
    monkeypatch.setenv("CLOUDSENTINEL_SCHEDULE_RATE_LIMIT", "1")
    app = main.create_app("sqlite+pysqlite:///:memory:")
    body = {"url": "https://example.com/health", "interval_seconds": 60}

    with TestClient(app) as client:
        first = client.post("/api/v1/schedules", json=body)
        second = client.post("/api/v1/schedules", json=body)

    assert first.status_code == 201
    assert second.status_code == 429


def test_schedule_updates_and_deletes_share_sensitive_rate_limit(monkeypatch):
    monkeypatch.delenv("CLOUDSENTINEL_API_TOKEN", raising=False)
    monkeypatch.setenv("CLOUDSENTINEL_SCHEDULE_RATE_LIMIT", "1")
    app = main.create_app("sqlite+pysqlite:///:memory:")
    body = {"url": "https://example.com/health", "interval_seconds": 60}

    with TestClient(app) as client:
        created = client.post("/api/v1/schedules", json=body)
        assert created.status_code == 201
        # Creation consumed the one request allowed in the rolling minute.
        updated = client.patch(f"/api/v1/schedules/{created.json()['id']}", json={"enabled": False})

    assert updated.status_code == 429


def test_reputation_lookups_are_rate_limited(monkeypatch):
    monkeypatch.delenv("CLOUDSENTINEL_API_TOKEN", raising=False)
    monkeypatch.setenv("CLOUDSENTINEL_REPUTATION_RATE_LIMIT", "1")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(main.VirusTotalProvider, "lookup", AsyncMock(return_value={"score": 0, "cached": False}))
    app = main.create_app("sqlite+pysqlite:///:memory:")

    with TestClient(app) as client:
        first = client.post("/api/v1/reputation", json={"indicator_type": "ip", "indicator": "8.8.8.8"})
        second = client.post("/api/v1/reputation", json={"indicator_type": "ip", "indicator": "1.1.1.1"})

    assert first.status_code == 200
    assert second.status_code == 429


def test_check_history_survives_api_restart(monkeypatch, tmp_path):
    result = make_result()
    monkeypatch.setattr(main, "check_endpoint", AsyncMock(return_value=result))
    database_path = tmp_path / "persistent-checks.sqlite3"
    database_url = f"sqlite+pysqlite:///{database_path.as_posix()}"

    first_app = main.create_app(database_url)
    with TestClient(first_app) as first_client:
        response = first_client.post("/api/v1/check", json={"url": result["url"]})
        assert response.status_code == 200

    restarted_app = main.create_app(database_url)
    with TestClient(restarted_app) as restarted_client:
        history = restarted_client.get("/api/v1/checks")

    assert history.status_code == 200
    assert history.json()["summary"]["total_checks"] == 1
    assert history.json()["checks"][0]["url"] == result["url"]


@pytest.mark.skipif(
    os.getenv("CLOUDSENTINEL_TEST_POSTGRES") != "1",
    reason="Set CLOUDSENTINEL_TEST_POSTGRES=1 to write one check to the configured PostgreSQL database.",
)
def test_postgres_check_history_survives_api_restart(monkeypatch):
    database_url = database_url_from_environment()
    assert database_url.get_backend_name() == "postgresql"
    result = make_result(url=f"https://postgres-integration.example/{uuid4()}")
    monkeypatch.setattr(main, "check_endpoint", AsyncMock(return_value=result))

    first_app = main.create_app(database_url)
    with TestClient(first_app) as first_client:
        response = first_client.post("/api/v1/check", json={"url": result["url"]})
        assert response.status_code == 200
        history = first_client.get("/api/v1/checks?limit=500").json()
        assert any(row["url"] == result["url"] for row in history["checks"])

    restarted_app = main.create_app(database_url)
    with TestClient(restarted_app) as restarted_client:
        history = restarted_client.get("/api/v1/checks?limit=500").json()

    saved = [row for row in history["checks"] if row["url"] == result["url"]]
    assert len(saved) == 1
    assert saved[0]["status"] == "healthy"


@pytest.mark.skipif(
    os.getenv("CLOUDSENTINEL_TEST_POSTGRES") != "1",
    reason="Set CLOUDSENTINEL_TEST_POSTGRES=1 to exercise PostgreSQL schedule locking.",
)
def test_postgres_concurrent_workers_claim_one_due_schedule():
    from services.api.scheduler import LEASE_SECONDS, claim_next_schedule

    database_url = database_url_from_environment()
    app = main.create_app(database_url)
    with TestClient(app) as client:
        now = datetime.now(timezone.utc)
        with app.state.session_factory.begin() as session:
            prior_test_schedules = session.scalars(
                select(MonitoringSchedule).where(
                    MonitoringSchedule.target_url.like("https://postgres-lock.example/%"),
                    MonitoringSchedule.deleted_at.is_(None),
                )
            ).all()
            for prior in prior_test_schedules:
                prior.enabled = False
                prior.deleted_at = now
                prior.updated_at = now
        created = client.post(
            "/api/v1/schedules",
            json={
                "url": f"https://postgres-lock.example/{uuid4()}",
                "interval_seconds": 60,
            },
        )
        assert created.status_code == 201
        schedule_id = created.json()["id"]
        # Keep the synthetic slot ahead of any real due schedules in this dev database.
        due_at = datetime(2000, 1, 1, tzinfo=timezone.utc)
        with app.state.session_factory.begin() as session:
            schedule = session.get(MonitoringSchedule, schedule_id)
            schedule.next_run_at = due_at

        barrier = threading.Barrier(2)

        def claim(worker_id):
            barrier.wait()
            return claim_next_schedule(app.state.session_factory, worker_id)

        with ThreadPoolExecutor(max_workers=2) as pool:
            claims = list(pool.map(claim, ("postgres-worker-a", "postgres-worker-b")))
        claimed_for_schedule = [
            item for item in claims
            if item is not None and item["schedule_id"] == schedule_id
        ]
        assert len(claimed_for_schedule) == 1

        expired = claim_next_schedule(
            app.state.session_factory,
            "postgres-worker-recovery",
            now=datetime.now(timezone.utc) + timedelta(seconds=LEASE_SECONDS + 1),
        )
        assert expired is not None
        assert expired["schedule_id"] == schedule_id
        assert client.delete(f"/api/v1/schedules/{schedule_id}").status_code == 204


@pytest.mark.skipif(
    os.getenv("CLOUDSENTINEL_TEST_POSTGRES") != "1",
    reason="Set CLOUDSENTINEL_TEST_POSTGRES=1 to persist a synthetic notification in PostgreSQL.",
)
def test_postgres_incident_notification_survives_worker_restart():
    from services.api.notifications import LEASE_SECONDS, _finish_attempt, claim_notification
    from services.api.scheduler import run_one_due_check

    database_url = database_url_from_environment()
    target = f"https://postgres-notification.example/{uuid4()}"
    app = main.create_app(database_url)
    with TestClient(app) as client:
        # Retire only this test's prior synthetic outbox rows so the two
        # concurrent claims below contend for exactly the current test event.
        with app.state.session_factory.begin() as session:
            prior_events = session.scalars(
                select(IncidentNotification)
                .join(MonitoringIncident, MonitoringIncident.id == IncidentNotification.incident_id)
                .join(MonitoringSchedule, MonitoringSchedule.id == MonitoringIncident.schedule_id)
                .where(MonitoringSchedule.target_url.like("https://postgres-notification.example/%"))
            ).all()
            for prior in prior_events:
                prior.status = "suppressed"
                prior.lease_owner = None
                prior.lease_expires_at = None
        created = client.post("/api/v1/schedules", json={
            "url": target, "interval_seconds": 60, "failure_threshold": 1,
        })
        assert created.status_code == 201
        schedule_id = created.json()["id"]
        with app.state.session_factory.begin() as session:
            session.get(MonitoringSchedule, schedule_id).next_run_at = datetime(2000, 1, 1, tzinfo=timezone.utc)
        failure = make_result(url=target, status="down", status_code=None, latency_ms=None, error="Request timed out")
        assert asyncio.run(run_one_due_check(
            app.state.session_factory, "postgres-notification-test", AsyncMock(return_value=failure)
        ))
        assert client.delete(f"/api/v1/schedules/{schedule_id}").status_code == 204

    restarted = main.create_app(database_url)
    with TestClient(restarted):
        with restarted.state.session_factory() as session:
            event = session.scalar(
                select(IncidentNotification)
                .join(MonitoringIncident, MonitoringIncident.id == IncidentNotification.incident_id)
                .join(MonitoringSchedule, MonitoringSchedule.id == MonitoringIncident.schedule_id)
                .where(MonitoringSchedule.target_url == target)
            )
        assert event is not None
        assert event.event_type == "opened"
        assert event.status == "pending"

        barrier = threading.Barrier(2)
        def claim(worker_id):
            barrier.wait()
            return claim_notification(restarted.state.session_factory, worker_id, provider="resend_api")
        with ThreadPoolExecutor(max_workers=2) as pool:
            claims = list(pool.map(claim, ("mail-worker-a", "mail-worker-b")))
        claimed = [item for item in claims if item is not None]
        assert len(claimed) == 1
        recovered = claim_notification(
            restarted.state.session_factory,
            "mail-worker-recovery",
            provider="resend_api",
            now=datetime.now(timezone.utc) + timedelta(seconds=LEASE_SECONDS + 1),
        )
        assert recovered is not None
        assert recovered["id"] == event.id
        _finish_attempt(
            restarted.state.session_factory,
            recovered,
            None,
            provider="resend_api",
            now=recovered["claimed_at"] + timedelta(seconds=1),
        )
        # Once the lifecycle event is delivered, repeated workers cannot claim
        # it again. PostgreSQL row locking above also proved only one of the
        # concurrently-started workers claimed the initial delivery.
        assert claim_notification(
            restarted.state.session_factory,
            "mail-worker-after-delivery",
            provider="resend_api",
        ) is None

    after_attempt_restart = main.create_app(database_url)
    with TestClient(after_attempt_restart) as client:
        persisted = next(
            item for item in client.get("/api/v1/notifications").json()["notifications"]
            if item["id"] == event.id
        )
        assert persisted["status"] == "delivered"
        assert persisted["attempts"][0]["status"] == "delivered"


def test_prohibited_dns_resolution_is_persisted_without_connecting(monkeypatch):
    from services.api import monitor
    from services.api.monitor import PinnedIPHTTPTransport

    class RecordingBackend:
        def __init__(self):
            self.connected_hosts = []

        async def connect_tcp(self, host, port, **kwargs):
            self.connected_hosts.append(host)
            raise AssertionError("A prohibited address must never be connected.")

        async def connect_unix_socket(self, path, **kwargs):
            raise AssertionError("Unix socket connections are not used.")

        async def sleep(self, seconds):
            return None

    backend = RecordingBackend()

    async def resolve_private(host, port):
        return ["10.1.2.3"]

    monkeypatch.setattr(
        monitor,
        "PinnedIPHTTPTransport",
        lambda: PinnedIPHTTPTransport(
            resolver=resolve_private,
            network_backend=backend,
        ),
    )
    app = main.create_app("sqlite+pysqlite:///:memory:")
    url = "https://probe.example/health"

    with TestClient(app) as client:
        response = client.post("/api/v1/check", json={"url": url})
        assert response.status_code == 200
        assert response.json()["status"] == "down"
        assert response.json()["error"] == "Target address is not permitted"
        with app.state.session_factory() as session:
            saved = session.scalar(select(MonitoringCheck))

    assert backend.connected_hosts == []
    assert saved is not None
    assert saved.is_success is False
    assert saved.error_detail == "Target address is not permitted"


def test_invalid_targets_are_rejected_before_probe(monkeypatch):
    embedded_secret = "not-a-real-password"
    invalid_urls = [
        "http://localhost/health",
        "http://127.0.0.1/health",
        "http://10.0.0.1/health",
        "http://169.254.1.1/health",
        "http://[::1]/health",
        "http://[fd00::1]/health",
        f"http://user:{embedded_secret}@service.example/health",
        "http://[::ffff:127.0.0.1]/health",
        "ftp://service.example/health",
        "http://bad_host/health",
    ]
    probe = AsyncMock()
    monkeypatch.setattr(main, "check_endpoint", probe)
    app = main.create_app("sqlite+pysqlite:///:memory:")

    with TestClient(app) as client:
        for url in invalid_urls:
            response = client.post("/api/v1/check", json={"url": url})
            assert response.status_code == 422, (url, response.text)
            assert embedded_secret not in response.text

    probe.assert_not_awaited()


def test_mapped_ipv6_private_address_is_rejected(monkeypatch):
    from services.api import monitor

    class RecordingBackend:
        def __init__(self):
            self.connected_hosts = []

        async def connect_tcp(self, host, port, **kwargs):
            self.connected_hosts.append(host)
            raise AssertionError("Mapped private address must not be connected.")

        async def connect_unix_socket(self, path, **kwargs):
            raise AssertionError("Unix socket connections are not used.")

        async def sleep(self, seconds):
            return None

    backend = RecordingBackend()

    async def resolve_mapped_private(host, port):
        return ["::ffff:192.168.1.10"]

    validating_backend = monitor.ValidatingNetworkBackend(
        resolver=resolve_mapped_private,
        network_backend=backend,
    )
    with pytest.raises(monitor.TargetRejectedError):
        asyncio.run(
            validating_backend.connect_tcp(
                "service.example",
                443,
                timeout=1,
            )
        )
    assert backend.connected_hosts == []


def test_public_dns_address_is_the_actual_connection_destination():
    from services.api.monitor import ValidatingNetworkBackend

    class RecordingBackend:
        def __init__(self):
            self.connected_hosts = []

        async def connect_tcp(self, host, port, **kwargs):
            self.connected_hosts.append((host, port))
            return object()

        async def connect_unix_socket(self, path, **kwargs):
            raise AssertionError("Unix socket connections are not used.")

        async def sleep(self, seconds):
            return None

    backend = RecordingBackend()
    resolver_calls = []

    async def resolve_public(host, port):
        resolver_calls.append((host, port))
        return ["93.184.216.34"]

    async def run_connect():
        validating_backend = ValidatingNetworkBackend(
            resolver=resolve_public,
            network_backend=backend,
        )
        await validating_backend.connect_tcp("service.example", 443, timeout=1)

    asyncio.run(run_connect())
    assert backend.connected_hosts == [("93.184.216.34", 443)]
    assert resolver_calls == [("service.example", 443)]


@pytest.mark.parametrize(
    "resolved_addresses",
    [
        ["127.0.0.1"],
        ["10.1.2.3"],
        ["169.254.169.254"],
        ["::1"],
        ["fd00::1"],
        ["93.184.216.34", "192.168.1.20"],
    ],
)
def test_hostname_with_any_prohibited_dns_answer_is_never_connected(
    resolved_addresses,
):
    from services.api.monitor import TargetRejectedError, ValidatingNetworkBackend

    class RecordingBackend:
        def __init__(self):
            self.connected_hosts = []

        async def connect_tcp(self, host, port, **kwargs):
            self.connected_hosts.append(host)
            raise AssertionError("A hostname with a prohibited answer must not connect.")

        async def connect_unix_socket(self, path, **kwargs):
            raise AssertionError("Unix socket connections are not used.")

        async def sleep(self, seconds):
            return None

    backend = RecordingBackend()

    async def resolve(host, port):
        return resolved_addresses

    validating_backend = ValidatingNetworkBackend(
        resolver=resolve,
        network_backend=backend,
    )
    with pytest.raises(TargetRejectedError):
        asyncio.run(
            validating_backend.connect_tcp(
                "service.example",
                443,
                timeout=1,
            )
        )
    assert backend.connected_hosts == []


def test_redirect_to_prohibited_target_is_not_followed(monkeypatch):
    from services.api import monitor

    requests = []

    async def redirect_handler(request):
        requests.append(request)
        return httpx.Response(
            status_code=302,
            headers={"Location": "http://127.0.0.1/admin"},
            request=request,
        )

    monkeypatch.setattr(
        monitor,
        "PinnedIPHTTPTransport",
        lambda: httpx.MockTransport(redirect_handler),
    )
    result = asyncio.run(monitor.check_endpoint("https://service.example/health"))

    assert result["status_code"] == 302
    assert len(requests) == 1
    assert str(requests[0].url) == "https://service.example/health"


def test_ipv6_link_local_and_unspecified_targets_are_rejected():
    from services.api.monitor import TargetRejectedError, validate_target_url
    for url in ("http://[fe80::1]/", "http://[::]/", "http://[ff02::1]/"):
        with pytest.raises(TargetRejectedError):
            validate_target_url(url)


def test_timeout_is_bounded():
    from services.api.monitor import check_endpoint

    with pytest.raises(ValueError, match="no more than 30"):
        asyncio.run(check_endpoint("https://service.example/", timeout_seconds=30.1))
