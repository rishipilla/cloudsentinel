# CloudSentinel

CloudSentinel is a FastAPI endpoint-checking application with a responsive dashboard and PostgreSQL-backed check history. Checks run on demand; scheduled monitoring is not configured.

## Local setup

Use PowerShell from the project directory:

```powershell
Set-Location 'C:\Users\durga\OneDrive\Documents\CloudSentinel\cloudsentinel'
.\.venv\Scripts\Activate.ps1
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
docker compose up -d
python -m pip install -r requirements.txt
```

On first setup, edit `.env` and set a unique local `POSTGRES_PASSWORD`; the conditional copy above leaves an existing `.env` untouched. Keep `.env` private; it is excluded from Git. The database name, user, and host port should match the Compose configuration. `POSTGRES_HOST` defaults to `127.0.0.1` for the API running on the host.

Start the API:

```powershell
uvicorn services.api.main:app --reload
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) for the dashboard. It uses the same FastAPI origin by default, so no frontend build step or separate web server is needed. To point a separately hosted dashboard at an API, set `CLOUDSENTINEL_API_BASE_URL` to the API origin (for example, `https://api.example.com`) before starting the API that serves the dashboard. Set `CLOUDSENTINEL_CORS_ORIGINS` to a comma-separated allowlist of dashboard origins when they differ from the API origin; leave it empty for same-origin use. These settings contain URLs only, not secrets.

The API creates missing check-history tables during startup. This uses SQLAlchemy `create_all`, which is suitable for this initial schema but does not manage schema upgrades or downgrades. Use versioned Alembic migrations before evolving the schema or deploying multiple API instances.

## Health and endpoint checks

- `GET /health` reports API liveness and does not depend on PostgreSQL.
- `GET /health/ready` performs a database readiness query.
- `POST /api/v1/check` probes the requested URL, returns the existing probe response, and stores the check result before responding.
- `GET /api/v1/checks?limit=100` returns up to 500 latest saved check rows and summary counts/average latency aggregated over all saved rows.

The dashboard summary and table are loaded from saved data. The table shows up to the latest 100 checks; summary figures cover the full history. Response latency averages include checks with a recorded response time.

For example:

```powershell
Invoke-RestMethod -Method Post `
  -Uri 'http://127.0.0.1:8000/api/v1/check' `
  -ContentType 'application/json' `
  -Body '{"url":"https://example.com","timeout_seconds":5}'
```

Database failures are surfaced as HTTP 503 responses instead of reporting an unsaved check as successful. Saved URLs omit URL user information and redact common sensitive query parameters.

## Outbound target security

Endpoint checks accept only `http` and `https`, reject embedded credentials and local/internal hostnames, and block IP addresses that are not globally routable (including IPv4-mapped IPv6, loopback, private, link-local, multicast, reserved, and unspecified ranges). Hostnames are resolved by the connection backend; every returned address must pass validation, and the selected numeric IP is used for the socket connection so a later DNS answer cannot redirect that connection to a private address. Environment-configured HTTP proxies are disabled for probes.

Redirects are deliberately not followed. A 3xx response is returned as the response to the configured target, without making a request to its `Location`. Probe timeouts must be greater than zero and are capped at 30 seconds. DNS and socket operations are subject to these timeouts.

The pinned connection backend uses HTTPcore's network-backend interface with the project's pinned HTTPX/HTTPcore versions. Validation error responses omit request values to avoid echoing embedded credentials. Revalidate this integration when upgrading those dependencies. Application-level address checks cannot protect against a network that routes globally classified public addresses to private services, malicious system DNS/resolver behavior, or other host-level routing changes. Deploy with outbound firewall/egress controls that deny private and metadata ranges as defense in depth; do not treat this check endpoint as safe for unrestricted public exposure.

## Tests

```powershell
.\.venv\Scripts\Activate.ps1
python -m pytest -q
```

The persistence/API tests use an isolated in-memory SQLite database; they do not modify or reset the PostgreSQL development volume. SSRF tests mock DNS and socket backends, so they do not make requests to real external services.
