import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from database.models import MonitoringCheck
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
        assert response.json() == result

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
        make_result(url="https://other.example/", status="down", status_code=503, latency_ms=80.0),
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
