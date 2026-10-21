"""Explicit, optional VirusTotal reputation lookups for public domains/IPs."""

import asyncio
import ipaddress
import json
import os
import re
import socket
from datetime import datetime, timedelta, timezone
from typing import Protocol
from urllib.parse import quote

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from database.models import ThreatIntelCache, ThreatIntelRateLock
from services.api.monitor import TargetRejectedError, _validated_ip_address, validate_target_url

PROVIDER = "virustotal"
CACHE_SECONDS = 3600
MINUTE_LIMIT = 4
DAILY_LIMIT = 500
REQUEST_TIMEOUT_SECONDS = 10


class ReputationDisabled(Exception):
    pass


class ReputationRateLimited(Exception):
    pass


class ReputationTargetRejected(ValueError):
    pass


class ReputationProvider(Protocol):
    async def lookup(self, indicator_type: str, indicator: str) -> dict: ...


class VirusTotalProvider:
    """Read-only provider adapter; never submits/scans an artifact or URL."""

    def __init__(self, api_key: str, client_factory=httpx.AsyncClient):
        self.api_key = api_key
        self.client_factory = client_factory

    async def lookup(self, indicator_type: str, indicator: str) -> dict:
        resource = "domains" if indicator_type == "domain" else "ip_addresses"
        url = f"https://www.virustotal.com/api/v3/{resource}/{quote(indicator, safe='')}"
        async with self.client_factory(
            timeout=REQUEST_TIMEOUT_SECONDS,
            trust_env=False,
            follow_redirects=False,
        ) as client:
            response = await client.get(url, headers={"x-apikey": self.api_key})
        if response.status_code == 404:
            return _normalized_result(indicator_type, indicator, None, status="not_found")
        response.raise_for_status()
        return _normalized_result(indicator_type, indicator, response.json(), status="found")


def normalize_indicator(indicator_type: str, indicator: str) -> tuple[str, str]:
    if not isinstance(indicator, str):
        raise ReputationTargetRejected("Enter a public domain name or IP address.")
    value = indicator.strip()
    if not value or len(value) > 253 or any(char in value for char in "/?#@\\"):
        raise ReputationTargetRejected("Enter only a public domain name or IP address, without a URL or credentials.")
    if indicator_type == "ip":
        try:
            address = ipaddress.ip_address(value)
            _validated_ip_address(str(address))
        except (ValueError, TargetRejectedError) as exc:
            raise ReputationTargetRejected("Only globally routable public IP addresses are allowed.") from exc
        return "ip", str(address)
    if indicator_type != "domain":
        raise ReputationTargetRejected("Indicator type must be domain or ip.")
    try:
        normalized = value.rstrip(".").encode("idna").decode("ascii").lower()
        validate_target_url(f"https://{normalized}/")
    except (UnicodeError, TargetRejectedError, ValueError) as exc:
        raise ReputationTargetRejected("Only a public DNS domain is allowed.") from exc
    if ":" in normalized or re.fullmatch(r"[0-9.]+", normalized):
        raise ReputationTargetRejected("Enter an IP address using the IP indicator type.")
    return "domain", normalized


async def ensure_public_domain_resolves(domain: str) -> None:
    """Reject domains resolving to any non-public address before disclosure."""
    loop = asyncio.get_running_loop()
    try:
        records = await asyncio.wait_for(
            loop.getaddrinfo(domain, 443, type=socket.SOCK_STREAM), timeout=2.0
        )
        addresses = {record[4][0] for record in records}
        if not addresses:
            raise ValueError("No addresses")
        for address in addresses:
            _validated_ip_address(address)
    except (OSError, TimeoutError, ValueError, TargetRejectedError) as exc:
        raise ReputationTargetRejected("Domain did not resolve exclusively to public IP addresses.") from exc


def _normalized_result(indicator_type: str, indicator: str, body: dict | None, *, status: str) -> dict:
    attributes = (body or {}).get("data", {}).get("attributes", {})
    raw_stats = attributes.get("last_analysis_stats", {})
    stats = {
        key: int(raw_stats.get(key, 0))
        for key in ("malicious", "suspicious", "harmless", "undetected")
    }
    reputation = attributes.get("reputation")
    if status == "not_found":
        assessment = "no report available"
    elif stats["malicious"] or (isinstance(reputation, int) and reputation < 0):
        assessment = "malicious reputation signal"
    elif stats["suspicious"]:
        assessment = "suspicious reputation signal"
    else:
        assessment = "no detections reported"
    return {
        "provider": PROVIDER,
        "indicator_type": indicator_type,
        "indicator": indicator,
        "status": status,
        "assessment": assessment,
        "last_analysis_stats": stats,
        "community_reputation": reputation if isinstance(reputation, int) else None,
        "looked_up_at": datetime.now(timezone.utc).isoformat(),
        "signal_notice": "Third-party reputation data is an unverified signal, not proof of a threat.",
    }


def _cache_lookup(session_factory: sessionmaker[Session], indicator_type: str, indicator: str, *, now: datetime) -> dict | None:
    with session_factory() as session:
        row = session.scalar(select(ThreatIntelCache).where(
            ThreatIntelCache.provider == PROVIDER,
            ThreatIntelCache.indicator_type == indicator_type,
            ThreatIntelCache.indicator == indicator,
            ThreatIntelCache.cached_at >= now - timedelta(seconds=CACHE_SECONDS),
        ))
        if row is None:
            return None
        result = json.loads(row.result_json)
        result["cached"] = True
        return result


def _take_quota_slot(session_factory: sessionmaker[Session], *, now: datetime) -> None:
    minute_ago = now - timedelta(seconds=60)
    utc_day = now.astimezone(timezone.utc).date().isoformat()
    with session_factory.begin() as session:
        state = session.scalar(select(ThreatIntelRateLock).where(
            ThreatIntelRateLock.provider == PROVIDER,
        ).with_for_update())
        if state is None:
            state = ThreatIntelRateLock(provider=PROVIDER)
            session.add(state)
            session.flush()
        requests = [
            datetime.fromisoformat(value)
            for value in json.loads(state.recent_requests or "[]")
        ]
        requests = [value for value in requests if value > minute_ago]
        day_count = state.daily_count if state.daily_window == utc_day else 0
        if len(requests) >= MINUTE_LIMIT or day_count >= DAILY_LIMIT:
            raise ReputationRateLimited()
        requests.append(now)
        state.recent_requests = json.dumps([value.isoformat() for value in requests])
        state.daily_window = utc_day
        state.daily_count = day_count + 1


def _cache_store(session_factory: sessionmaker[Session], indicator_type: str, indicator: str, result: dict) -> None:
    with session_factory.begin() as session:
        row = session.scalar(select(ThreatIntelCache).where(
            ThreatIntelCache.provider == PROVIDER,
            ThreatIntelCache.indicator_type == indicator_type,
            ThreatIntelCache.indicator == indicator,
        ).with_for_update())
        if row is None:
            row = ThreatIntelCache(provider=PROVIDER, indicator_type=indicator_type, indicator=indicator, cached_at=datetime.now(timezone.utc), result_json=json.dumps(result))
            session.add(row)
        else:
            row.cached_at = datetime.now(timezone.utc)
            row.result_json = json.dumps(result)
