import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

from fastapi.testclient import TestClient
from sqlalchemy import select

from database.models import MonitoringIncident, MonitoringSchedule, ScheduledExecution
from services.api import main, scheduler


def _app():
    return main.create_app("sqlite+pysqlite:///:memory:")


def _create_schedule(client, *, failure_threshold=2):
    response = client.post("/api/v1/schedules", json={
        "url": "https://health.example.com/ready",
        "interval_seconds": 60,
        "timeout_seconds": 2,
        "failure_threshold": failure_threshold,
    })
    assert response.status_code == 201, response.text
    return response.json()


def _mark_due(app, schedule_id, due_at=None):
    due_at = due_at or datetime.now(timezone.utc) - timedelta(seconds=1)
    with app.state.session_factory.begin() as session:
        session.get(MonitoringSchedule, schedule_id).next_run_at = due_at
    return due_at


def _check_result(status_code=200, error=None):
    result = {
        "url": "https://health.example.com/ready",
        "status": "healthy" if status_code is not None and status_code < 400 and error is None else "down",
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    if status_code is not None:
        result["status_code"] = status_code
        result["latency_ms"] = 12.5
    if error:
        result["error"] = error
    return result


def test_schedule_crud_soft_delete_and_url_validation():
    app = _app()
    with TestClient(app) as client:
        assert client.post("/api/v1/schedules", json={
            "url": "http://127.0.0.1/", "interval_seconds": 60,
        }).status_code == 422
        assert client.post("/api/v1/schedules", json={
            "url": "https://health.example.com/", "interval_seconds": 59,
        }).status_code == 422
        secret_response = client.post("/api/v1/schedules", json={
            "url": "https://health.example.com/health?api_key=do-not-echo-this",
            "interval_seconds": 60,
        })
        assert secret_response.status_code == 422
        assert "do-not-echo-this" not in secret_response.text
        created = _create_schedule(client)
        assert created["enabled"] is True
        assert created["failure_threshold"] == 2
        assert created["last_run_at"] is None
        assert created["next_run_at"] is not None

        updated = client.patch(f"/api/v1/schedules/{created['id']}", json={
            "interval_seconds": 120, "failure_threshold": 4,
        })
        assert updated.status_code == 200
        assert updated.json()["interval_seconds"] == 120
        assert updated.json()["failure_threshold"] == 4
        assert client.patch(f"/api/v1/schedules/{created['id']}", json={"enabled": False}).json()["enabled"] is False
        assert client.patch(f"/api/v1/schedules/{created['id']}", json={"enabled": True}).json()["enabled"] is True
        assert client.delete(f"/api/v1/schedules/{created['id']}").status_code == 204
        assert client.get("/api/v1/schedules").json()["schedules"] == []
        retained = client.get(f"/api/v1/schedules/{created['id']}")
        assert retained.status_code == 200
        assert retained.json()["deleted_at"] is not None


def test_schedule_patch_rejects_ssrf_targets():
    app = _app()
    with TestClient(app) as client:
        schedule = _create_schedule(client)
        rejected = client.patch(f"/api/v1/schedules/{schedule['id']}", json={
            "url": "http://169.254.169.254/latest/meta-data/",
        })
        assert rejected.status_code == 422
        assert client.get(f"/api/v1/schedules/{schedule['id']}").json()["url"] == schedule["url"]


def test_claim_prevents_duplicate_workers_and_expired_lease_recovers():
    app = _app()
    with TestClient(app) as client:
        schedule = _create_schedule(client)
        due_at = _mark_due(app, schedule["id"])
        claim_time = due_at + timedelta(seconds=1)
        first = scheduler.claim_next_schedule(app.state.session_factory, "worker-a", now=claim_time)
        second = scheduler.claim_next_schedule(app.state.session_factory, "worker-b", now=claim_time)
        assert first is not None
        assert second is None
        recovered = scheduler.claim_next_schedule(
            app.state.session_factory, "worker-b",
            now=claim_time + timedelta(seconds=scheduler.LEASE_SECONDS + 1),
        )
        assert recovered is not None
        assert recovered["schedule_id"] == first["schedule_id"]
        assert scheduler.persist_scheduled_result(
            app.state.session_factory, first, _check_result(),
            completed_at=claim_time + timedelta(seconds=2),
        ) is False


def test_worker_persists_check_and_incident_threshold_then_resolves():
    app = _app()
    with TestClient(app) as client:
        schedule = _create_schedule(client, failure_threshold=2)
        failures = AsyncMock(side_effect=[
            _check_result(status_code=None, error="Request timed out"),
            _check_result(status_code=None, error="Request timed out"),
            _check_result(status_code=None, error="Request timed out"),
        ])
        for _ in range(3):
            _mark_due(app, schedule["id"])
            assert asyncio.run(scheduler.run_one_due_check(app.state.session_factory, "worker-test", failures))
        with app.state.session_factory() as session:
            incidents = session.scalars(select(MonitoringIncident)).all()
            executions = session.scalars(select(ScheduledExecution)).all()
            state = session.get(MonitoringSchedule, schedule["id"])
        assert len(incidents) == 1
        assert incidents[0].resolved_at is None
        assert incidents[0].failure_count == 3
        assert state.consecutive_failures == 3
        assert len(executions) == 3

        healthy = AsyncMock(return_value=_check_result())
        _mark_due(app, schedule["id"])
        assert asyncio.run(scheduler.run_one_due_check(app.state.session_factory, "worker-test", healthy))
        with app.state.session_factory() as session:
            incident = session.scalar(select(MonitoringIncident))
            state = session.get(MonitoringSchedule, schedule["id"])
        assert incident.resolved_at is not None
        assert state.consecutive_failures == 0
        incident_list = client.get("/api/v1/incidents").json()["incidents"]
        schedule_detail = client.get(f"/api/v1/schedules/{schedule['id']}").json()
        schedule_history = client.get(f"/api/v1/schedules/{schedule['id']}/history").json()
    assert incident_list[0]["status"] == "resolved"
    assert len(schedule_detail["history"]) == 4
    assert len(schedule_history["checks"]) == 4


def test_unexpected_checker_exception_is_recorded_as_failed_execution():
    app = _app()
    with TestClient(app) as client:
        schedule = _create_schedule(client)
        _mark_due(app, schedule["id"])
        checker = AsyncMock(side_effect=RuntimeError("private diagnostic details"))
        assert asyncio.run(scheduler.run_one_due_check(app.state.session_factory, "worker-test", checker))
        with app.state.session_factory() as session:
            execution = session.scalar(select(ScheduledExecution))
            schedule_row = session.get(MonitoringSchedule, schedule["id"])
        assert execution is not None
        assert schedule_row.last_error == "Connection failed"


def test_graceful_cancellation_releases_lease_and_leaves_due_slot():
    app = _app()
    with TestClient(app) as client:
        schedule = _create_schedule(client)
        due_at = _mark_due(app, schedule["id"])
        entered = asyncio.Event()
        never = asyncio.Event()

        async def slow_check(*args, **kwargs):
            entered.set()
            await never.wait()

        async def run_and_cancel():
            task = asyncio.create_task(scheduler.run_one_due_check(app.state.session_factory, "shutdown-worker", slow_check))
            await entered.wait()
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(run_and_cancel())
        with app.state.session_factory() as session:
            row = session.get(MonitoringSchedule, schedule["id"])
            assert row.lease_owner is None
            assert row.next_run_at.replace(tzinfo=timezone.utc) == due_at.replace(tzinfo=timezone.utc)


def test_pause_while_check_runs_does_not_rearm_schedule():
    app = _app()
    client = TestClient(app)
    client.__enter__()
    try:
        schedule = _create_schedule(client)
        _mark_due(app, schedule["id"])
        entered = asyncio.Event()
        release = asyncio.Event()

        async def slow_check(*args, **kwargs):
            entered.set()
            await release.wait()
            return _check_result()

        async def run_check():
            task = asyncio.create_task(scheduler.run_one_due_check(app.state.session_factory, "pause-worker", slow_check))
            await entered.wait()
            assert client.patch(f"/api/v1/schedules/{schedule['id']}", json={"enabled": False}).status_code == 200
            release.set()
            await task

        assert asyncio.run(run_check()) is None  # inner coroutine only coordinates the checker task
        with app.state.session_factory() as session:
            row = session.get(MonitoringSchedule, schedule["id"])
            assert row.enabled is False
            assert row.next_run_at.replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc)
            assert row.lease_owner is None
    finally:
        client.__exit__(None, None, None)
