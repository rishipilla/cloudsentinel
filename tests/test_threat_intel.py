import asyncio
from unittest.mock import AsyncMock

import httpx
from fastapi.testclient import TestClient

from services.api import main
from services.api.threat_intel import (
    ReputationTargetRejected,
    VirusTotalProvider,
    _take_quota_slot,
    normalize_indicator,
)


def test_reputation_lookup_is_disabled_without_key(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    app = main.create_app("sqlite+pysqlite:///:memory:")
    with TestClient(app) as client:
        response = client.post("/api/v1/reputation", json={
            "indicator_type": "ip", "indicator": "8.8.8.8",
        })
    assert response.status_code == 503
    assert "disabled" in response.json()["detail"].lower()


def test_reputation_rejects_private_addresses_and_url_inputs():
    for kind, value in (("ip", "127.0.0.1"), ("domain", "https://example.com/path"), ("domain", "service.local")):
        try:
            normalize_indicator(kind, value)
        except ReputationTargetRejected:
            continue
        raise AssertionError(f"Unsafe reputation indicator was accepted: {kind}")


def test_mocked_virustotal_lookup_is_cached_and_marked_as_third_party_signal(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-only-key")
    lookup = AsyncMock(return_value={
        "provider": "virustotal",
        "indicator_type": "ip",
        "indicator": "8.8.8.8",
        "status": "found",
        "assessment": "no detections reported",
        "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 12, "undetected": 1},
        "community_reputation": 0,
        "looked_up_at": "2026-10-21T00:00:00+00:00",
        "signal_notice": "Third-party reputation data is an unverified signal, not proof of a threat.",
    })
    monkeypatch.setattr(VirusTotalProvider, "lookup", lookup)
    app = main.create_app("sqlite+pysqlite:///:memory:")
    with TestClient(app) as client:
        first = client.post("/api/v1/reputation", json={"indicator_type": "ip", "indicator": "8.8.8.8"})
        second = client.post("/api/v1/reputation", json={"indicator_type": "ip", "indicator": "8.8.8.8"})

    assert first.status_code == second.status_code == 200
    assert first.json()["cached"] is False
    assert second.json()["cached"] is True
    assert "unverified signal" in first.json()["signal_notice"]
    lookup.assert_awaited_once_with("ip", "8.8.8.8")


def test_reputation_does_not_disclose_domain_until_public_dns_validation(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-only-key")
    lookup = AsyncMock()
    monkeypatch.setattr(VirusTotalProvider, "lookup", lookup)
    monkeypatch.setattr(main, "ensure_public_domain_resolves", AsyncMock(side_effect=main.ReputationTargetRejected("private resolution")))
    app = main.create_app("sqlite+pysqlite:///:memory:")
    with TestClient(app) as client:
        response = client.post("/api/v1/reputation", json={"indicator_type": "domain", "indicator": "example.com"})
    assert response.status_code == 422
    lookup.assert_not_awaited()


def test_virustotal_adapter_uses_fixed_api_and_normalizes_mock_response():
    seen = []

    async def handler(request):
        seen.append(request)
        return httpx.Response(200, json={
            "data": {"attributes": {
                "last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 4, "undetected": 3},
                "reputation": -2,
            }},
        })

    transport = httpx.MockTransport(handler)
    provider = VirusTotalProvider(
        "test-api-key",
        client_factory=lambda **options: httpx.AsyncClient(transport=transport, **options),
    )
    result = asyncio.run(provider.lookup("domain", "example.com"))
    assert seen[0].url == "https://www.virustotal.com/api/v3/domains/example.com"
    assert seen[0].headers["x-apikey"] == "test-api-key"
    assert result["last_analysis_stats"]["malicious"] == 2
    assert result["assessment"] == "malicious reputation signal"


def test_virustotal_rate_limit_is_shared_in_database():
    app = main.create_app("sqlite+pysqlite:///:memory:")
    with TestClient(app):
        from datetime import datetime, timezone
        from services.api.threat_intel import ReputationRateLimited

        now = datetime.now(timezone.utc)
        for _ in range(4):
            _take_quota_slot(app.state.session_factory, now=now)
        try:
            _take_quota_slot(app.state.session_factory, now=now)
        except ReputationRateLimited:
            pass
        else:
            raise AssertionError("A fifth lookup inside one minute must be rate limited.")
