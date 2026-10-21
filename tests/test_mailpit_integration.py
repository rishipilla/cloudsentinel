"""Opt-in local Mailpit SMTP integration; never sends to a public mail server."""

import asyncio
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from database.models import IncidentNotification, MonitoringSchedule
from services.api import main, notifications, scheduler


@pytest.mark.skipif(
    os.getenv("CLOUDSENTINEL_TEST_MAILPIT") != "1",
    reason="Set CLOUDSENTINEL_TEST_MAILPIT=1 to deliver one synthetic message to local Mailpit.",
)
def test_incident_notification_is_delivered_to_local_mailpit():
    base_url = os.getenv("MAILPIT_API_URL", "http://127.0.0.1:8025")
    smtp_host = os.getenv("MAILPIT_SMTP_HOST", "127.0.0.1")
    smtp_port = int(os.getenv("MAILPIT_SMTP_PORT", "1025"))
    before_response = httpx.get(f"{base_url}/api/v1/messages?limit=100", timeout=3)
    before_response.raise_for_status()
    before_ids = {item["ID"] for item in before_response.json()["messages"]}

    app = main.create_app("sqlite+pysqlite:///:memory:")
    config = {
        "host": smtp_host, "port": smtp_port, "username": "", "password": "",
        "sender": "cloudsentinel@example.test", "recipient": "operator@example.test",
        "starttls": False, "dev_mode": False, "resolve_enabled": False,
        "provider": "smtp", "environment": "development",
    }
    with TestClient(app) as client:
        created = client.post("/api/v1/schedules", json={
            "url": "https://mailpit-check.example/health",
            "interval_seconds": 60,
            "failure_threshold": 1,
        })
        assert created.status_code == 201
        schedule_id = created.json()["id"]
        with app.state.session_factory.begin() as session:
            session.get(MonitoringSchedule, schedule_id).next_run_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        failed_check = {
            "url": "https://mailpit-check.example/health",
            "status": "down",
            "error": "Request timed out",
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
        assert asyncio.run(scheduler.run_one_due_check(
            app.state.session_factory,
            "mailpit-integration-worker",
            AsyncMock(return_value=failed_check),
        ))
        with app.state.session_factory() as session:
            notification = session.scalar(select(IncidentNotification))
            notification_id = notification.id
        assert notifications.process_one_notification(
            app.state.session_factory, "mailpit-integration-worker", config,
        )
        history = client.get("/api/v1/notifications").json()["notifications"]
        delivered = next(item for item in history if item["id"] == notification_id)
        assert delivered["status"] == "delivered"
        assert delivered["attempts"][0]["status"] == "delivered"

    after_response = httpx.get(f"{base_url}/api/v1/messages?limit=100", timeout=3)
    after_response.raise_for_status()
    after_ids = {item["ID"] for item in after_response.json()["messages"]}
    assert after_ids - before_ids, "The delivery was accepted but no new message appeared in Mailpit."
