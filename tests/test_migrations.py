from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _upgrade(database_url: str) -> None:
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    # Avoid changing process environment: Alembic env reads the URL from it.
    import os

    previous = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = database_url
    try:
        command.upgrade(config, "head")
    finally:
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous


def test_fresh_database_migration_is_repeatable(tmp_path):
    path = tmp_path / "fresh.sqlite3"
    url = f"sqlite:///{path.as_posix()}"
    _upgrade(url)
    _upgrade(url)
    engine = create_engine(url)
    try:
        tables = set(inspect(engine).get_table_names())
        assert {
            "alembic_version",
            "monitoring_checks",
            "monitoring_schedules",
            "scheduled_executions",
            "monitoring_incidents",
            "incident_notifications",
            "notification_attempts",
            "threat_intel_cache",
            "threat_intel_rate_locks",
        } <= tables
    finally:
        engine.dispose()

def test_migration_adopts_legacy_history_without_deleting_it(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    url = f"sqlite:///{path.as_posix()}"
    engine = create_engine(url)
    try:
        with engine.begin() as connection:
            connection.execute(text(
                "CREATE TABLE monitoring_checks ("
                "id INTEGER PRIMARY KEY, checked_url VARCHAR(2083) NOT NULL, "
                "checked_at DATETIME NOT NULL, is_success BOOLEAN NOT NULL, "
                "status_code INTEGER, latency_ms FLOAT, error_detail VARCHAR(500))"
            ))
            connection.execute(text(
                "INSERT INTO monitoring_checks "
                "(id, checked_url, checked_at, is_success, status_code) "
                "VALUES (77, 'https://legacy.example/health', '2025-01-01', 1, 200)"
            ))
    finally:
        engine.dispose()

    _upgrade(url)
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            row = connection.execute(text(
                "SELECT id, checked_url, status_code FROM monitoring_checks WHERE id=77"
            )).one()
            assert tuple(row) == (77, "https://legacy.example/health", 200)
            assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == "0001_current_schema"
            assert "ix_monitoring_checks_checked_at" in {
                item["name"] for item in inspect(connection).get_indexes("monitoring_checks")
            }
    finally:
        engine.dispose()


def test_postgres_migration_preserves_existing_row_counts():
    import os

    import pytest
    from sqlalchemy import func, select

    from database.models import (
        IncidentNotification,
        MonitoringCheck,
        MonitoringIncident,
        MonitoringSchedule,
        NotificationAttempt,
        ScheduledExecution,
        ThreatIntelCache,
        ThreatIntelRateLock,
    )
    from database.session import create_database_engine, database_url_from_environment

    if os.getenv("CLOUDSENTINEL_TEST_POSTGRES") != "1":
        pytest.skip("Set CLOUDSENTINEL_TEST_POSTGRES=1 to apply the additive baseline to PostgreSQL.")
    database_url = database_url_from_environment()
    assert database_url.get_backend_name() == "postgresql"
    engine = create_database_engine(database_url)
    models = (
        MonitoringCheck,
        MonitoringSchedule,
        ScheduledExecution,
        MonitoringIncident,
        IncidentNotification,
        NotificationAttempt,
        ThreatIntelCache,
        ThreatIntelRateLock,
    )
    try:
        with engine.connect() as connection:
            before = {
                model.__tablename__: connection.scalar(select(func.count()).select_from(model))
                for model in models
            }
    finally:
        engine.dispose()

    _upgrade(database_url.render_as_string(hide_password=False))

    engine = create_database_engine(database_url)
    try:
        with engine.connect() as connection:
            after = {
                model.__tablename__: connection.scalar(select(func.count()).select_from(model))
                for model in models
            }
        assert after == before
        assert "alembic_version" in inspect(engine).get_table_names()
    finally:
        engine.dispose()

