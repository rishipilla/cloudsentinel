import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from dotenv import load_dotenv
from sqlalchemy import URL, Engine, create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from database.models import Base, MonitoringCheck, ThreatIntelRateLock

MAX_ERROR_DETAIL_LENGTH = 500
SENSITIVE_QUERY_PARTS = (
    "token",
    "key",
    "password",
    "passwd",
    "secret",
    "auth",
    "signature",
    "credential",
)
SAFE_ERROR_DETAILS = {
    "Request timed out",
    "Connection failed",
    "Target address is not permitted",
}
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def database_url_from_environment() -> URL:
    load_dotenv(PROJECT_ROOT / ".env")

    configured_url = os.environ.get("DATABASE_URL")
    if configured_url:
        url = make_url(configured_url)
        if url.get_backend_name() == "postgresql" and url.drivername == "postgresql":
            url = url.set(drivername="postgresql+psycopg")
        if url.get_backend_name() not in {"postgresql", "sqlite"}:
            raise RuntimeError("DATABASE_URL must use PostgreSQL or SQLite.")
        return url

    password = os.environ.get("POSTGRES_PASSWORD")
    if not password:
        raise RuntimeError("POSTGRES_PASSWORD must be set to connect to PostgreSQL.")

    return URL.create(
        drivername="postgresql+psycopg",
        username=os.environ.get("POSTGRES_USER", "sentinel"),
        password=password,
        host=os.environ.get("POSTGRES_HOST", "127.0.0.1"),
        port=int(os.environ.get("POSTGRES_HOST_PORT", "5432")),
        database=os.environ.get("POSTGRES_DB", "cloudsentinel"),
    )


def create_database_engine(database_url: str | URL | None = None) -> Engine:
    url = database_url or database_url_from_environment()
    if isinstance(url, str):
        url = make_url(url)

    engine_options: dict[str, object] = {"pool_pre_ping": True}
    if url.get_backend_name() == "postgresql":
        # Bound connect hangs so API and worker can retry/report an outage.
        engine_options["connect_args"] = {
            "connect_timeout": 5,
            "options": "-c statement_timeout=10000 -c lock_timeout=5000",
        }
        engine_options["pool_timeout"] = 10
    if url.get_backend_name() == "sqlite":
        engine_options["connect_args"] = {"check_same_thread": False}
        if url.database in (None, "", ":memory:"):
            engine_options["poolclass"] = StaticPool

    return create_engine(url, **engine_options)


def initialize_database(engine: Engine) -> None:
    if engine.dialect.name == "postgresql":
        # Serialize additive table creation when API and both workers start together.
        with engine.begin() as connection:
            connection.execute(text("SELECT pg_advisory_xact_lock(734829104)"))
            Base.metadata.create_all(connection)
            # Older development databases created this table with only its key.
            # Extend it additively in place; retain every existing row and table.
            connection.execute(text(
                "ALTER TABLE threat_intel_rate_locks "
                "ADD COLUMN IF NOT EXISTS recent_requests VARCHAR(1000) NOT NULL DEFAULT '[]'"
            ))
            connection.execute(text(
                "ALTER TABLE threat_intel_rate_locks "
                "ADD COLUMN IF NOT EXISTS daily_window VARCHAR(10)"
            ))
            connection.execute(text(
                "ALTER TABLE threat_intel_rate_locks "
                "ADD COLUMN IF NOT EXISTS daily_count INTEGER NOT NULL DEFAULT 0"
            ))
            connection.execute(text(
                "ALTER TABLE incident_notifications "
                "ADD COLUMN IF NOT EXISTS lease_provider VARCHAR(32)"
            ))
            connection.execute(text(
                "ALTER TABLE notification_attempts "
                "ALTER COLUMN completed_at DROP NOT NULL"
            ))
    else:
        Base.metadata.create_all(engine)
    with engine.begin() as connection:
        if engine.dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as dialect_insert
        elif engine.dialect.name == "sqlite":
            from sqlalchemy.dialects.sqlite import insert as dialect_insert
        else:
            return
        statement = dialect_insert(ThreatIntelRateLock).values(provider="virustotal")
        connection.execute(statement.on_conflict_do_nothing(index_elements=["provider"]))


def database_is_ready(engine: Engine) -> None:
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))


def session_factory_for(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


def sanitize_checked_url(url: str) -> str:
    parts = urlsplit(url)
    hostname = parts.hostname or ""
    if ":" in hostname:
        hostname = f"[{hostname}]"
    if parts.port is not None:
        hostname = f"{hostname}:{parts.port}"

    query = [
        (key, "[REDACTED]" if any(part in key.lower() for part in SENSITIVE_QUERY_PARTS) else value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
    ]
    return urlunsplit(
        (parts.scheme, hostname, parts.path, urlencode(query, doseq=True), "")
    )


def persist_check(session_factory: sessionmaker[Session], result: dict) -> None:
    session = session_factory()
    try:
        session.add(monitoring_check_from_result(result))
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def monitoring_check_from_result(result: dict) -> MonitoringCheck:
    status_code = result.get("status_code")
    error_detail = result.get("error")
    if error_detail is not None and error_detail not in SAFE_ERROR_DETAILS:
        error_detail = "Endpoint probe failed"
    if error_detail is None and status_code is not None and status_code >= 400:
        error_detail = f"HTTP response status {status_code}"

    checked_at = datetime.fromisoformat(result["checked_at"].replace("Z", "+00:00"))
    if checked_at.tzinfo is None:
        checked_at = checked_at.replace(tzinfo=timezone.utc)
    else:
        checked_at = checked_at.astimezone(timezone.utc)

    return MonitoringCheck(
        checked_url=sanitize_checked_url(result["url"]),
        checked_at=checked_at,
        is_success=status_code is not None
        and status_code < 400
        and error_detail is None,
        status_code=status_code,
        latency_ms=result.get("latency_ms"),
        error_detail=(
            str(error_detail)[:MAX_ERROR_DETAIL_LENGTH]
            if error_detail is not None
            else None
        )
    )
