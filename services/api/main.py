
from contextlib import asynccontextmanager
import hmac
import ipaddress
import json
import logging
import os
import threading
import time
from collections import defaultdict, deque
from collections.abc import AsyncGenerator
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qsl, urlsplit

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from pydantic import BaseModel, Field, HttpUrl, field_validator
from sqlalchemy import Integer, case, cast, func, select
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool
from starlette.responses import HTMLResponse, JSONResponse
from starlette.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from database.models import (
    IncidentNotification,
    MonitoringCheck,
    MonitoringIncident,
    MonitoringSchedule,
    NotificationAttempt,
    ScheduledExecution,
    ThreatIntelCache,
)
from database.session import (
    SENSITIVE_QUERY_PARTS,
    create_database_engine,
    database_is_ready,
    initialize_database,
    persist_check,
    session_factory_for,
    sanitize_checked_url,
)
from services.api.threat_intel import (
    CACHE_SECONDS,
    ReputationRateLimited,
    ReputationTargetRejected,
    VirusTotalProvider,
    _cache_lookup,
    _cache_store,
    _take_quota_slot,
    ensure_public_domain_resolves,
    normalize_indicator,
)
from services.api.monitor import (
    MAX_TIMEOUT_SECONDS,
    TargetRejectedError,
    check_endpoint,
    validate_target_url,
)

logger = logging.getLogger(__name__)
MIN_SCHEDULE_INTERVAL_SECONDS = 60
MAX_SCHEDULE_INTERVAL_SECONDS = 86400
MAX_FAILURE_THRESHOLD = 10


def validate_scheduled_url(value: object) -> object:
    if isinstance(value, str):
        if len(value) > 2083:
            raise ValueError("Scheduled URL is too long.")
        try:
            validate_target_url(value)
        except (TargetRejectedError, ValueError) as exc:
            raise ValueError(str(exc)) from exc
        sensitive_keys = {
            key.lower()
            for key, _ in parse_qsl(urlsplit(value).query, keep_blank_values=True)
            if any(part in key.lower() for part in SENSITIVE_QUERY_PARTS)
        }
        if sensitive_keys:
            raise ValueError("Scheduled URLs cannot contain secret query parameters.")
    return value


class ScheduleCreate(BaseModel):
    url: HttpUrl
    interval_seconds: int = Field(ge=MIN_SCHEDULE_INTERVAL_SECONDS, le=MAX_SCHEDULE_INTERVAL_SECONDS)
    timeout_seconds: float = Field(default=5.0, gt=0, le=MAX_TIMEOUT_SECONDS)
    failure_threshold: int = Field(default=3, ge=1, le=MAX_FAILURE_THRESHOLD)

    @field_validator("url", mode="before")
    @classmethod
    def validate_url_safety(cls, value: object) -> object:
        return validate_scheduled_url(value)


class ScheduleUpdate(BaseModel):
    url: HttpUrl | None = None
    interval_seconds: int | None = Field(default=None, ge=MIN_SCHEDULE_INTERVAL_SECONDS, le=MAX_SCHEDULE_INTERVAL_SECONDS)
    timeout_seconds: float | None = Field(default=None, gt=0, le=MAX_TIMEOUT_SECONDS)
    failure_threshold: int | None = Field(default=None, ge=1, le=MAX_FAILURE_THRESHOLD)
    enabled: bool | None = None

    @field_validator("url", mode="before")
    @classmethod
    def validate_url_safety(cls, value: object) -> object:
        return validate_scheduled_url(value)


class ReputationRequest(BaseModel):
    indicator_type: Literal["domain", "ip"]
    indicator: str = Field(min_length=1, max_length=253)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _check_response(row: MonitoringCheck) -> dict:
    return {
        "id": row.id,
        "url": row.checked_url,
        "status": "healthy" if row.is_success else "degraded" if row.status_code is not None and row.status_code < 500 else "down",
        "status_code": row.status_code,
        "latency_ms": row.latency_ms,
        "checked_at": _iso(row.checked_at),
        "error": row.error_detail,
    }


def _incident_response(row: MonitoringIncident, target_url: str | None = None) -> dict:
    return {
        "id": row.id,
        "schedule_id": row.schedule_id,
        "url": sanitize_checked_url(target_url) if target_url else None,
        "started_at": _iso(row.started_at),
        "resolved_at": _iso(row.resolved_at),
        "failure_count": row.failure_count,
        "latest_error": row.latest_error,
        "latest_check_id": row.latest_check_id,
        "status": "open" if row.resolved_at is None else "resolved",
    }


def _schedule_response(session, row: MonitoringSchedule, history_limit: int = 1) -> dict:
    executions = session.execute(
        select(ScheduledExecution, MonitoringCheck)
        .join(MonitoringCheck, ScheduledExecution.check_id == MonitoringCheck.id)
        .where(ScheduledExecution.schedule_id == row.id)
        .order_by(ScheduledExecution.completed_at.desc(), ScheduledExecution.id.desc())
        .limit(history_limit)
    ).all()
    latest = _check_response(executions[0][1]) if executions else None
    incidents = session.scalars(
        select(MonitoringIncident)
        .where(MonitoringIncident.schedule_id == row.id)
        .order_by(MonitoringIncident.started_at.desc(), MonitoringIncident.id.desc())
        .limit(20)
    ).all()
    return {
        "id": row.id,
        "url": sanitize_checked_url(row.target_url),
        "interval_seconds": row.interval_seconds,
        "timeout_seconds": row.timeout_seconds,
        "failure_threshold": row.failure_threshold,
        "consecutive_failures": row.consecutive_failures,
        "enabled": row.enabled,
        "created_at": _iso(row.created_at),
        "updated_at": _iso(row.updated_at),
        "next_run_at": _iso(row.next_run_at),
        "last_run_at": _iso(row.last_run_at),
        "last_status": row.last_status,
        "last_error": row.last_error,
        "deleted_at": _iso(row.deleted_at),
        "latest_check": latest,
        "history": [_check_response(check) for _, check in executions] if history_limit > 1 else [],
        "incidents": [_incident_response(incident, row.target_url) for incident in incidents],
    }


def create_app(database_url: str | None = None) -> FastAPI:
    load_dotenv(Path(__file__).resolve().parents[2] / ".env")
    environment = os.getenv("CLOUDSENTINEL_ENV", "development").strip().lower()
    if environment not in {"development", "production"}:
        raise RuntimeError("CLOUDSENTINEL_ENV must be either development or production.")
    production = environment == "production"
    configured_api_token = os.getenv("CLOUDSENTINEL_API_TOKEN", "").strip()
    if production and not configured_api_token:
        raise RuntimeError("CLOUDSENTINEL_API_TOKEN must be set in production.")
    insecure_token_defaults = {
        "changeme",
        "change-me",
        "your-api-token",
        "your-secret-here",
        "replace-me",
        "default-token",
        "example-token",
        "development-token",
    }
    insecure_token_markers = (
        "change-me",
        "changeme",
        "replace-me",
        "your-api-token",
        "your-secret",
        "default-token",
        "example-token",
        "development-token",
        "test-token",
    )
    if production and (
        len(configured_api_token) < 32
        or len(set(configured_api_token)) < 16
        or configured_api_token.casefold() in insecure_token_defaults
        or any(marker in configured_api_token.casefold() for marker in insecure_token_markers)
    ):
        raise RuntimeError(
            "CLOUDSENTINEL_API_TOKEN must be a strong, non-default secret of at least 32 characters in production."
        )
    configured_gateway_secret = os.getenv("CLOUDSENTINEL_GATEWAY_SECRET", "").strip()
    if production and (
        len(configured_gateway_secret) < 32
        or len(set(configured_gateway_secret)) < 16
        or configured_gateway_secret.casefold() in insecure_token_defaults
        or any(marker in configured_gateway_secret.casefold() for marker in insecure_token_markers)
    ):
        raise RuntimeError(
            "CLOUDSENTINEL_GATEWAY_SECRET must be a strong, non-default secret of at least 32 characters in production."
        )
    allowed_hosts = [
        host.strip()
        for host in os.getenv("CLOUDSENTINEL_ALLOWED_HOSTS", "").split(",")
        if host.strip()
    ]
    render_hostname = os.getenv("RENDER_EXTERNAL_HOSTNAME", "").strip()
    if render_hostname:
        allowed_hosts.append(render_hostname)
    if production and any(host == "*" or host.startswith("*.") for host in allowed_hosts):
        raise RuntimeError("Wildcard hosts are not permitted in production.")
    if production and not allowed_hosts:
        raise RuntimeError("CLOUDSENTINEL_ALLOWED_HOSTS must be configured in production.")
    if production and not any(
        value.strip() for value in os.getenv("CLOUDSENTINEL_TARGET_ALLOWLIST", "").split(",")
    ):
        raise RuntimeError("CLOUDSENTINEL_TARGET_ALLOWLIST must approve at least one monitoring target in production.")

    cors_origins = [
        origin.strip()
        for origin in os.getenv("CLOUDSENTINEL_CORS_ORIGINS", "").split(",")
        if origin.strip()
    ]
    if production:
        for origin in cors_origins:
            parsed_origin = urlsplit(origin)
            if (
                parsed_origin.scheme != "https"
                or not parsed_origin.hostname
                or parsed_origin.path
                or parsed_origin.query
                or parsed_origin.fragment
                or parsed_origin.username is not None
                or parsed_origin.password is not None
                or "*" in parsed_origin.netloc
            ):
                raise RuntimeError(
                    "CLOUDSENTINEL_CORS_ORIGINS must contain only explicit HTTPS origins without paths."
                )

    def configured_limit(variable: str, default: int) -> int:
        try:
            value = int(os.getenv(variable, str(default)))
        except ValueError as exc:
            raise RuntimeError(f"{variable} must be a positive integer.") from exc
        if value < 1 or value > 10000:
            raise RuntimeError(f"{variable} must be between 1 and 10000.")
        return value

    rate_limits = {
        "gateway": configured_limit("CLOUDSENTINEL_GATEWAY_RATE_LIMIT", 120),
        "auth": configured_limit("CLOUDSENTINEL_AUTH_RATE_LIMIT", 10),
        "check": configured_limit("CLOUDSENTINEL_CHECK_RATE_LIMIT", 60),
        "schedule": configured_limit("CLOUDSENTINEL_SCHEDULE_RATE_LIMIT", 20),
        "reputation": configured_limit("CLOUDSENTINEL_REPUTATION_RATE_LIMIT", 30),
    }
    rate_buckets: dict[tuple[str, str], deque[float]] = defaultdict(deque)
    rate_lock = threading.Lock()

    def consume_rate_limit(bucket: str, client_key: str) -> bool:
        now = time.monotonic()
        key = (bucket, client_key)
        with rate_lock:
            if key not in rate_buckets and len(rate_buckets) >= 10000:
                for stale_key, stale_events in list(rate_buckets.items()):
                    while stale_events and stale_events[0] <= now - 60:
                        stale_events.popleft()
                    if not stale_events:
                        rate_buckets.pop(stale_key, None)
                if len(rate_buckets) >= 10000:
                    # Bound memory under spoofed/very high-cardinality source IPs.
                    key = (bucket, "__rate_limit_overflow__")
            events = rate_buckets[key]
            while events and events[0] <= now - 60:
                events.popleft()
            if len(events) >= rate_limits[bucket]:
                return False
            events.append(now)
            return True

    def prevent_response_caching(response):
        response.headers["Cache-Control"] = "no-store, private"
        return response

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        engine = create_database_engine(database_url)
        try:
            await run_in_threadpool(initialize_database, engine)
            app.state.engine = engine
            app.state.session_factory = session_factory_for(engine)
            yield
        finally:
            await run_in_threadpool(engine.dispose)

    app = FastAPI(title="CloudSentinel", debug=False, lifespan=lifespan)
    if allowed_hosts:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
    static_path = Path(__file__).resolve().parent / "static"
    app.mount("/static", StaticFiles(directory=static_path), name="static")

    @app.middleware("http")
    async def request_security_guard(request: Request, call_next):
        expected = os.getenv("CLOUDSENTINEL_API_TOKEN", "").strip()
        protected_api = request.url.path.startswith("/api/")
        public_liveness = request.method == "GET" and request.url.path == "/health"
        if production and not public_liveness:
            supplied_gateway_secret = request.headers.get("x-cloudsentinel-gateway-secret", "")
            if not supplied_gateway_secret or not hmac.compare_digest(
                supplied_gateway_secret, configured_gateway_secret
            ):
                client_key = request.client.host if request.client else "unknown"
                if not consume_rate_limit("gateway", client_key):
                    return prevent_response_caching(JSONResponse(
                        status_code=429,
                        content={"detail": "Request rate limit exceeded."},
                        headers={"Retry-After": "60"},
                    ))
                return prevent_response_caching(
                    JSONResponse(status_code=404, content={"detail": "Not found."})
                )
        if protected_api and os.getenv("CLOUDSENTINEL_ENV", "development").lower() == "production" and not expected:
            return prevent_response_caching(
                JSONResponse(status_code=503, content={"detail": "API access is not configured."})
            )
        if protected_api and expected:
            supplied = request.headers.get("authorization", "")
            token = supplied[7:] if supplied.lower().startswith("bearer ") else ""
            if not token or not hmac.compare_digest(token, expected):
                client_key = request.client.host if request.client else "unknown"
                if not consume_rate_limit("auth", client_key):
                    return prevent_response_caching(JSONResponse(
                        status_code=429,
                        content={"detail": "Too many authentication attempts."},
                        headers={"Retry-After": "60"},
                    ))
                return prevent_response_caching(JSONResponse(
                    status_code=401,
                    content={"detail": "Authentication required."},
                    headers={"WWW-Authenticate": "Bearer"},
                ))
        if protected_api:
            client_key = request.client.host if request.client else "unknown"
            bucket = None
            if request.method == "POST" and request.url.path == "/api/v1/check":
                bucket = "check"
            elif request.url.path == "/api/v1/reputation" and request.method == "POST":
                bucket = "reputation"
            elif request.url.path.startswith("/api/v1/schedules") and request.method in {"POST", "PATCH", "DELETE"}:
                bucket = "schedule"
            if bucket and not consume_rate_limit(bucket, client_key):
                return prevent_response_caching(JSONResponse(
                    status_code=429,
                    content={"detail": "Request rate limit exceeded."},
                    headers={"Retry-After": "60"},
                ))
        return prevent_response_caching(await call_next(request))

    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            allow_headers=["Content-Type", "Authorization"],
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        errors = [
            {
                key: value
                for key, value in error.items()
                if key not in {"input", "ctx"}
            }
            for error in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": errors})

    @app.get("/", response_class=HTMLResponse)
    async def dashboard() -> HTMLResponse:
        dashboard_path = Path(__file__).resolve().parent / "static" / "index.html"
        html = dashboard_path.read_text(encoding="utf-8")
        api_base_url = os.getenv("CLOUDSENTINEL_API_BASE_URL", "").rstrip("/")
        html = html.replace(
            "__CLOUDSENTINEL_API_BASE_URL__",
            escape(api_base_url, quote=True),
        )
        return HTMLResponse(html)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "healthy"}

    @app.get("/health/ready")
    async def readiness(request: Request) -> dict[str, str]:
        if production and not os.getenv("CLOUDSENTINEL_API_TOKEN", "").strip():
            raise HTTPException(status_code=503, detail="API access is not configured.")
        try:
            await run_in_threadpool(database_is_ready, request.app.state.engine)
        except SQLAlchemyError as exc:
            logger.error("Database readiness check failed.")
            raise HTTPException(
                status_code=503,
                detail="Database is not ready.",
            ) from exc
        return {"status": "ready", "database": "ready"}

    @app.post("/api/v1/reputation")
    async def lookup_reputation(body: ReputationRequest, request: Request) -> dict:
        api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        if not api_key:
            raise HTTPException(status_code=503, detail="Reputation lookups are disabled.")
        try:
            indicator_type, indicator = normalize_indicator(body.indicator_type, body.indicator)
        except ReputationTargetRejected as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        now = datetime.now(timezone.utc)
        try:
            cached = await run_in_threadpool(
                _cache_lookup, request.app.state.session_factory, indicator_type, indicator, now=now
            )
        except SQLAlchemyError as exc:
            logger.error("Reputation cache read failed.")
            raise HTTPException(status_code=503, detail="Reputation cache is unavailable.") from exc
        if cached is not None:
            return cached

        if indicator_type == "domain":
            try:
                await ensure_public_domain_resolves(indicator)
            except ReputationTargetRejected as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc

        try:
            await run_in_threadpool(_take_quota_slot, request.app.state.session_factory, now=now)
        except ReputationRateLimited as exc:
            raise HTTPException(status_code=429, detail="VirusTotal lookup quota reached; try later.") from exc
        except SQLAlchemyError as exc:
            logger.error("Reputation rate-limit storage failed.")
            raise HTTPException(status_code=503, detail="Reputation service is unavailable.") from exc

        try:
            provider = VirusTotalProvider(api_key)
            result = await provider.lookup(indicator_type, indicator)
        except Exception as exc:
            # Provider response bodies may contain data; never include them in API errors or logs.
            logger.warning("VirusTotal lookup failed.")
            raise HTTPException(status_code=502, detail="VirusTotal lookup failed.") from exc
        try:
            await run_in_threadpool(
                _cache_store,
                request.app.state.session_factory,
                indicator_type,
                indicator,
                result,
            )
        except SQLAlchemyError as exc:
            logger.error("Reputation cache write failed.")
            raise HTTPException(status_code=503, detail="Reputation result could not be saved.") from exc
        result["cached"] = False
        return result

    @app.get("/api/v1/notifications")
    async def notification_history(
        request: Request,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> dict:
        def read_notifications() -> dict:
            with request.app.state.session_factory() as session:
                rows = session.scalars(
                    select(IncidentNotification)
                    .order_by(IncidentNotification.created_at.desc(), IncidentNotification.id.desc())
                    .limit(limit)
                ).all()
                output = []
                for row in rows:
                    attempts = session.scalars(
                        select(NotificationAttempt)
                        .where(NotificationAttempt.notification_id == row.id)
                        .order_by(NotificationAttempt.attempt_number.desc())
                    ).all()
                    output.append({
                        "id": row.id,
                        "incident_id": row.incident_id,
                        "event_type": row.event_type,
                        "status": row.status,
                        "attempt_count": row.attempt_count,
                        "created_at": _iso(row.created_at),
                        "delivered_at": _iso(row.delivered_at),
                        "last_error": row.last_error,
                        "attempts": [{
                            "number": attempt.attempt_number,
                            "provider": attempt.provider,
                            "status": attempt.status,
                            "started_at": _iso(attempt.started_at),
                            "completed_at": _iso(attempt.completed_at),
                            "error": attempt.error_summary,
                        } for attempt in attempts],
                    })
                return {"notifications": output}

        try:
            return await run_in_threadpool(read_notifications)
        except SQLAlchemyError as exc:
            logger.error("Notification history read failed.")
            raise HTTPException(status_code=503, detail="Notification history is unavailable.") from exc

    @app.get("/api/v1/checks")
    async def check_history(
        request: Request,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> dict:
        try:
            def read_history() -> dict:
                with request.app.state.session_factory() as session:
                    total, successful, failed, average_latency = session.execute(
                        select(
                            func.count(MonitoringCheck.id),
                            func.coalesce(
                                func.sum(cast(MonitoringCheck.is_success, Integer)),
                                0,
                            ),
                            func.coalesce(
                                func.sum(
                                    case((MonitoringCheck.is_success.is_(False), 1), else_=0)
                                ),
                                0,
                            ),
                            func.avg(MonitoringCheck.latency_ms),
                        )
                    ).one()
                    rows = session.scalars(
                        select(MonitoringCheck)
                        .order_by(MonitoringCheck.checked_at.desc(), MonitoringCheck.id.desc())
                        .limit(limit)
                    ).all()
                    return {
                        "summary": {
                            "total_checks": total,
                            "successful_checks": successful,
                            "failed_checks": failed,
                            "average_latency_ms": (
                                round(average_latency, 2)
                                if average_latency is not None
                                else None
                            ),
                        },
                        "checks": [
                            {
                                "id": row.id,
                                "url": row.checked_url,
                                "status": (
                                    "healthy"
                                    if row.is_success
                                    else "degraded"
                                    if row.status_code is not None and row.status_code < 500
                                    else "down"
                                ),
                                "status_code": row.status_code,
                                "latency_ms": row.latency_ms,
                                "checked_at": (
                                    row.checked_at.replace(tzinfo=timezone.utc).isoformat()
                                    if row.checked_at.tzinfo is None
                                    else row.checked_at.astimezone(timezone.utc).isoformat()
                                ),
                                "error": row.error_detail,
                            }
                            for row in rows
                        ],
                    }

            return await run_in_threadpool(read_history)
        except SQLAlchemyError as exc:
            logger.error("Failed to read endpoint check history.")
            raise HTTPException(
                status_code=503,
                detail="Check history is unavailable.",
            ) from exc

    @app.post("/api/v1/schedules", status_code=201)
    async def create_schedule(body: ScheduleCreate, request: Request) -> dict:
        now = datetime.now(timezone.utc)

        def insert_schedule() -> dict:
            with request.app.state.session_factory.begin() as session:
                schedule = MonitoringSchedule(
                    target_url=str(body.url),
                    interval_seconds=body.interval_seconds,
                    timeout_seconds=body.timeout_seconds,
                    failure_threshold=body.failure_threshold,
                    enabled=True,
                    created_at=now,
                    updated_at=now,
                    next_run_at=now + timedelta(seconds=body.interval_seconds),
                    consecutive_failures=0,
                )
                session.add(schedule)
                session.flush()
                return _schedule_response(session, schedule)

        try:
            return await run_in_threadpool(insert_schedule)
        except SQLAlchemyError as exc:
            logger.error("Failed to create endpoint schedule.")
            raise HTTPException(status_code=503, detail="Schedule storage is unavailable.") from exc

    @app.get("/api/v1/schedules")
    async def list_schedules(
        request: Request,
        include_deleted: bool = False,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> dict:
        def read_schedules() -> dict:
            with request.app.state.session_factory() as session:
                statement = select(MonitoringSchedule).order_by(MonitoringSchedule.created_at.desc()).limit(limit)
                if not include_deleted:
                    statement = statement.where(MonitoringSchedule.deleted_at.is_(None))
                rows = session.scalars(statement).all()
                return {"schedules": [_schedule_response(session, row) for row in rows]}

        try:
            return await run_in_threadpool(read_schedules)
        except SQLAlchemyError as exc:
            logger.error("Failed to read endpoint schedules.")
            raise HTTPException(status_code=503, detail="Schedules are unavailable.") from exc

    @app.get("/api/v1/schedules/{schedule_id}/history")
    async def schedule_history(
        schedule_id: int,
        request: Request,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> dict:
        def read_schedule_history() -> dict | None:
            with request.app.state.session_factory() as session:
                schedule = session.get(MonitoringSchedule, schedule_id)
                if schedule is None:
                    return None
                rows = session.execute(
                    select(ScheduledExecution, MonitoringCheck)
                    .join(MonitoringCheck, ScheduledExecution.check_id == MonitoringCheck.id)
                    .where(ScheduledExecution.schedule_id == schedule_id)
                    .order_by(ScheduledExecution.completed_at.desc(), ScheduledExecution.id.desc())
                    .limit(limit)
                ).all()
                return {
                    "schedule_id": schedule_id,
                    "checks": [
                        {**_check_response(check), "scheduled_for": _iso(execution.scheduled_for)}
                        for execution, check in rows
                    ],
                }

        try:
            response = await run_in_threadpool(read_schedule_history)
        except SQLAlchemyError as exc:
            logger.error("Failed to read endpoint schedule history.")
            raise HTTPException(status_code=503, detail="Schedule history is unavailable.") from exc
        if response is None:
            raise HTTPException(status_code=404, detail="Schedule not found.")
        return response

    @app.get("/api/v1/schedules/{schedule_id}")
    async def get_schedule(schedule_id: int, request: Request) -> dict:
        def read_schedule() -> dict | None:
            with request.app.state.session_factory() as session:
                row = session.get(MonitoringSchedule, schedule_id)
                return _schedule_response(session, row, history_limit=20) if row else None

        try:
            response = await run_in_threadpool(read_schedule)
        except SQLAlchemyError as exc:
            logger.error("Failed to read endpoint schedule.")
            raise HTTPException(status_code=503, detail="Schedule is unavailable.") from exc
        if response is None:
            raise HTTPException(status_code=404, detail="Schedule not found.")
        return response

    @app.patch("/api/v1/schedules/{schedule_id}")
    async def update_schedule(schedule_id: int, body: ScheduleUpdate, request: Request) -> dict:
        now = datetime.now(timezone.utc)

        def modify_schedule() -> dict | None:
            with request.app.state.session_factory.begin() as session:
                row = session.scalar(
                    select(MonitoringSchedule)
                    .where(MonitoringSchedule.id == schedule_id)
                    .with_for_update()
                )
                if row is None or row.deleted_at is not None:
                    return None
                values = body.model_dump(exclude_unset=True)
                was_enabled = row.enabled
                interval_changed = "interval_seconds" in values and values["interval_seconds"] != row.interval_seconds
                for key, value in values.items():
                    if value is not None:
                        setattr(row, "target_url" if key == "url" else key, str(value) if key == "url" else value)
                if body.enabled is True and not was_enabled:
                    row.next_run_at = now
                elif interval_changed and row.enabled:
                    row.next_run_at = now + timedelta(seconds=row.interval_seconds)
                row.updated_at = now
                session.flush()
                return _schedule_response(session, row)

        try:
            response = await run_in_threadpool(modify_schedule)
        except SQLAlchemyError as exc:
            logger.error("Failed to update endpoint schedule.")
            raise HTTPException(status_code=503, detail="Schedule storage is unavailable.") from exc
        if response is None:
            raise HTTPException(status_code=404, detail="Schedule not found.")
        return response

    @app.delete("/api/v1/schedules/{schedule_id}", status_code=204)
    async def delete_schedule(schedule_id: int, request: Request) -> None:
        now = datetime.now(timezone.utc)

        def soft_delete() -> bool:
            with request.app.state.session_factory.begin() as session:
                row = session.scalar(
                    select(MonitoringSchedule)
                    .where(MonitoringSchedule.id == schedule_id)
                    .with_for_update()
                )
                if row is None:
                    return False
                row.enabled = False
                row.deleted_at = now
                row.updated_at = now
                return True

        try:
            found = await run_in_threadpool(soft_delete)
        except SQLAlchemyError as exc:
            logger.error("Failed to delete endpoint schedule.")
            raise HTTPException(status_code=503, detail="Schedule storage is unavailable.") from exc
        if not found:
            raise HTTPException(status_code=404, detail="Schedule not found.")

    @app.get("/api/v1/incidents")
    async def list_incidents(
        request: Request,
        open_only: bool = False,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> dict:
        def read_incidents() -> dict:
            with request.app.state.session_factory() as session:
                statement = select(MonitoringIncident, MonitoringSchedule.target_url).join(
                    MonitoringSchedule,
                    MonitoringIncident.schedule_id == MonitoringSchedule.id,
                ).order_by(
                    MonitoringIncident.started_at.desc(), MonitoringIncident.id.desc()
                ).limit(limit)
                if open_only:
                    statement = statement.where(MonitoringIncident.resolved_at.is_(None))
                rows = session.execute(statement).all()
                return {
                    "incidents": [
                        _incident_response(incident, target_url)
                        for incident, target_url in rows
                    ]
                }

        try:
            return await run_in_threadpool(read_incidents)
        except SQLAlchemyError as exc:
            logger.error("Failed to read endpoint incidents.")
            raise HTTPException(status_code=503, detail="Incidents are unavailable.") from exc

    class MonitorRequest(BaseModel):
        url: HttpUrl
        timeout_seconds: float = Field(default=5.0, gt=0, le=MAX_TIMEOUT_SECONDS)

        @field_validator("url", mode="before")
        @classmethod
        def validate_url_safety(cls, value: object) -> object:
            if isinstance(value, str):
                try:
                    validate_target_url(value)
                except (TargetRejectedError, ValueError) as exc:
                    raise ValueError(str(exc)) from exc
            return value

    @app.post("/api/v1/check")
    async def run_check(
        body: MonitorRequest,
        request: Request,
    ) -> dict:
        try:
            result = await check_endpoint(
                str(body.url),
                timeout_seconds=body.timeout_seconds,
            )
        except TargetRejectedError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        try:
            await run_in_threadpool(
                persist_check,
                request.app.state.session_factory,
                result,
            )
        except SQLAlchemyError as exc:
            logger.error("Failed to persist endpoint check result.")
            raise HTTPException(
                status_code=503,
                detail="Endpoint check completed but its result could not be saved.",
            ) from exc
        return {**result, "url": sanitize_checked_url(result["url"])}

    return app


app = create_app()
