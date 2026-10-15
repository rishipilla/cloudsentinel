import asyncio
import ipaddress
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Awaitable, Callable, Iterable
from urllib.parse import urlsplit

import httpcore
import httpx

MAX_TIMEOUT_SECONDS = 30.0
MAX_DNS_ADDRESSES = 16
LOCAL_HOST_SUFFIXES = (
    ".localhost",
    ".local",
    ".localdomain",
    ".internal",
    ".lan",
    ".home",
    ".corp",
    ".test",
    ".onion",
)
BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata",
    "metadata.google.internal",
    "metadata.azure.com",
    "instance-data.ec2.internal",
}
HOST_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class TargetRejectedError(httpx.RequestError):
    """Raised when a target URL or its resolved address is not safe to probe."""


def _normalize_hostname(hostname: str) -> str:
    try:
        normalized = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("The target hostname is invalid.") from exc

    if not normalized or len(normalized) > 253:
        raise ValueError("The target hostname is invalid.")

    labels = normalized.split(".")
    if (
        any(not HOST_LABEL_PATTERN.fullmatch(label) for label in labels)
        or (len(labels) == 1 and normalized != "localhost")
    ):
        raise ValueError("The target hostname is invalid.")
    if normalized in BLOCKED_HOSTNAMES or normalized.endswith(LOCAL_HOST_SUFFIXES):
        raise TargetRejectedError("Target hostname is not permitted.")
    return normalized


def _validated_ip_address(address: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as exc:
        raise ValueError("The resolved target address is invalid.") from exc

    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    if (
        not parsed.is_global
        or parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_unspecified
        or parsed.is_reserved
    ):
        raise TargetRejectedError("Target address is not permitted.")
    return parsed


def validate_target_url(url: str) -> None:
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Only http and https URLs are supported.")
        if not parsed.netloc or not parsed.hostname:
            raise ValueError("A valid target hostname is required.")
        if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
            raise ValueError("Embedded URL credentials are not permitted.")
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(str(exc) or "The target URL is malformed.") from exc

    hostname = parsed.hostname
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        if re.fullmatch(r"[0-9.]+", hostname):
            raise ValueError("The target hostname is invalid.")
        _normalize_hostname(hostname)
    else:
        _validated_ip_address(str(address))


Resolver = Callable[[str, int], Awaitable[list[str]]]


async def _resolve_host(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        records = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise httpcore.ConnectError("Target hostname could not be resolved.") from exc
    return [record[4][0] for record in records]


class ValidatingNetworkBackend(httpcore.AsyncNetworkBackend):
    def __init__(
        self,
        resolver: Resolver = _resolve_host,
        network_backend: httpcore.AsyncNetworkBackend | None = None,
    ) -> None:
        self._resolver = resolver
        self._network_backend = network_backend or httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[tuple[int, int, int | bytes]] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        try:
            hostname = str(ipaddress.ip_address(host))
        except ValueError:
            hostname = _normalize_hostname(host)
            if timeout is None:
                addresses = await self._resolver(hostname, port)
            else:
                addresses = await asyncio.wait_for(
                    self._resolver(hostname, port),
                    timeout=timeout,
                )
            if not addresses or len(addresses) > MAX_DNS_ADDRESSES:
                raise TargetRejectedError("Target hostname resolved to an invalid number of addresses.")
            validated_addresses = [_validated_ip_address(address) for address in addresses]
            address = next(
                (
                    item
                    for item in validated_addresses
                    if isinstance(item, ipaddress.IPv4Address)
                ),
                validated_addresses[0],
            )
            hostname = str(address)
        else:
            _validated_ip_address(hostname)

        return await self._network_backend.connect_tcp(
            hostname,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[tuple[int, int, int | bytes]] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise httpcore.ConnectError("Unix socket connections are not permitted.")

    async def sleep(self, seconds: float) -> None:
        await self._network_backend.sleep(seconds)


class PinnedIPHTTPTransport(httpx.AsyncHTTPTransport):
    """HTTPX transport that connects only to validated, pinned public IPs."""

    def __init__(
        self,
        resolver: Resolver = _resolve_host,
        network_backend: httpcore.AsyncNetworkBackend | None = None,
    ) -> None:
        super().__init__(trust_env=False)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl.create_default_context(),
            max_connections=20,
            max_keepalive_connections=10,
            keepalive_expiry=5.0,
            network_backend=ValidatingNetworkBackend(
                resolver=resolver,
                network_backend=network_backend,
            ),
        )


async def check_endpoint(url: str, timeout_seconds: float = 5.0) -> dict:
    validate_target_url(url)
    if not 0 < timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise ValueError(f"Timeout must be greater than 0 and no more than {MAX_TIMEOUT_SECONDS:g} seconds.")

    started = time.perf_counter()

    try:
        async with httpx.AsyncClient(
            timeout=timeout_seconds,
            follow_redirects=False,
            transport=PinnedIPHTTPTransport(),
        ) as client:
            response = await client.get(url)

        latency_ms = round((time.perf_counter() - started) * 1000, 2)

        if response.status_code >= 500:
            status = "down"
        elif response.status_code >= 400 or latency_ms >= 1000:
            status = "degraded"
        else:
            status = "healthy"

        return {
            "url": url,
            "status": status,
            "status_code": response.status_code,
            "latency_ms": latency_ms,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    except TargetRejectedError:
        return {
            "url": url,
            "status": "down",
            "error": "Target address is not permitted",
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    except asyncio.TimeoutError:
        return {
            "url": url,
            "status": "down",
            "error": "Request timed out",
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    except httpx.TimeoutException:
        return {
            "url": url,
            "status": "down",
            "error": "Request timed out",
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    except httpx.RequestError:
        return {
            "url": url,
            "status": "down",
            "error": "Connection failed",
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }