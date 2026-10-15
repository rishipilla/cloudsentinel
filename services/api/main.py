
from contextlib import asynccontextmanager
import logging
import os
from collections.abc import AsyncGenerator
from datetime import timezone
from html import escape
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, HttpUrl, field_validator
from sqlalchemy import Integer, case, cast, func, select
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool
from starlette.responses import HTMLResponse, JSONResponse
from starlette.staticfiles import StaticFiles

from database.models import MonitoringCheck
from database.session import (
    create_database_engine,
    database_is_ready,
    initialize_database,
    persist_check,
    session_factory_for,
)
from services.api.monitor import (
    MAX_TIMEOUT_SECONDS,
    TargetRejectedError,
    check_endpoint,
    validate_target_url,
)

logger = logging.getLogger(__name__)


def create_app(database_url: str | None = None) -> FastAPI:
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

    app = FastAPI(title="CloudSentinel", lifespan=lifespan)
    static_path = Path(__file__).resolve().parent / "static"
    app.mount("/static", StaticFiles(directory=static_path), name="static")

    cors_origins = [
        origin.strip()
        for origin in os.getenv("CLOUDSENTINEL_CORS_ORIGINS", "").split(",")
        if origin.strip()
    ]
    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_methods=["GET", "POST"],
            allow_headers=["Content-Type"],
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
        try:
            await run_in_threadpool(database_is_ready, request.app.state.engine)
        except SQLAlchemyError as exc:
            logger.error("Database readiness check failed.")
            raise HTTPException(
                status_code=503,
                detail="Database is not ready.",
            ) from exc
        return {"status": "ready", "database": "ready"}

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
        return result

    return app


app = create_app()
