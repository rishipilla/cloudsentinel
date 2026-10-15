import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from dotenv import load_dotenv
from sqlalchemy import URL, Engine, create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from database.models import Base, MonitoringCheck

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
    if url.get_backend_name() == "sqlite":
        engine_options["connect_args"] = {"check_same_thread": False}
        if url.database in (None, "", ":memory:"):
            engine_options["poolclass"] = StaticPool

    return create_engine(url, **engine_options)


def initialize_database(engine: Engine) -> None:
    Base.metadata.create_all(engine)


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
    status_code = result.get("status_code")
    error_detail = result.get("error")
    if error_detail is not None and error_detail not in SAFE_ERROR_DETAILS:
        error_detail = "Endpoint probe failed"
    if error_detail is None and status_code is not None and status_code >= 400:
        error_detail = f"HTTP response status {status_code}"

    session = session_factory()
    try:
        checked_at = datetime.fromisoformat(result["checked_at"].replace("Z", "+00:00"))
        if checked_at.tzinfo is None:
            checked_at = checked_at.replace(tzinfo=timezone.utc)
        else:
            checked_at = checked_at.astimezone(timezone.utc)

        session.add(
            MonitoringCheck(
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
                ),
            )
        )
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
