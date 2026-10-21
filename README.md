# CloudSentinel

CloudSentinel is a FastAPI endpoint-checking application with a responsive dashboard, PostgreSQL-backed check history, durable interval schedules, and endpoint-availability incidents.

## Local setup

Use PowerShell from the project directory:

```powershell
Set-Location 'C:\Users\durga\OneDrive\Documents\CloudSentinel\cloudsentinel'
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
# Edit .env and replace POSTGRES_PASSWORD with a unique local password.
docker compose up -d
python -m alembic upgrade head
```

On first setup, edit `.env` and set a unique local `POSTGRES_PASSWORD`; the conditional copy above leaves an existing `.env` untouched. Keep `.env` private; it is excluded from Git. The database name, user, and host port should match the Compose configuration. `POSTGRES_HOST` defaults to `127.0.0.1` for the API running on the host.

In development, leaving `CLOUDSENTINEL_API_TOKEN` empty keeps the dashboard/API convenient for local use. If set, all `/api/` requests require that shared bearer token and the dashboard prompts for it. Production requires a strong token. Development is a single trusted operator environment; do not expose it publicly.

Start the API:

```powershell
uvicorn services.api.main:app --reload
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) for the dashboard. It uses the same FastAPI origin by default, so no frontend build step or separate web server is needed. To point a separately hosted dashboard at an API, set `CLOUDSENTINEL_API_BASE_URL` to the API origin (for example, `https://api.example.com`) before starting the API that serves the dashboard. Set `CLOUDSENTINEL_CORS_ORIGINS` to a comma-separated allowlist of dashboard origins when they differ from the API origin; leave it empty for same-origin use. These settings contain URLs only, not secrets.

`POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, and `POSTGRES_HOST_PORT` configure the Compose PostgreSQL container. `POSTGRES_HOST` configures the API's database connection host and defaults to `127.0.0.1` for the host-run API. Set `DATABASE_URL` instead when using a managed database. `CLOUDSENTINEL_API_BASE_URL` and `CLOUDSENTINEL_CORS_ORIGINS` are optional and can remain empty for the normal same-origin dashboard. `CLOUDSENTINEL_ENV`, `CLOUDSENTINEL_API_TOKEN`, the `SMTP_*`/`ALERT_EMAIL_*` settings, and optional `VIRUSTOTAL_API_KEY` are described below.

The repository includes an Alembic migration baseline. Before starting a fresh database or upgrading an existing unversioned database, back up PostgreSQL and run `python -m alembic upgrade head`. The baseline creates missing tables and indexes, adopts existing tables without modifying their rows, and applies only additive PostgreSQL compatibility changes; it never drops or renames tables/columns. It intentionally cannot be downgraded because a downgrade could destroy history. API startup retains the existing additive `create_all` compatibility path for older installations; use Alembic for deployment schema changes and future revisions. Review each migration and back up before applying it.

## Health and endpoint checks

- `GET /health` reports API liveness and does not depend on PostgreSQL.
- `GET /health/ready` performs a database readiness query.
- `POST /api/v1/check` probes the requested URL, returns the existing probe response, and stores the check result before responding.
- `GET /api/v1/checks?limit=100` returns up to 500 latest saved check rows and summary counts/average latency aggregated over all saved rows.
- `POST /api/v1/schedules` creates a durable endpoint schedule.
- `GET /api/v1/schedules` lists schedules; `GET /api/v1/schedules/{id}` returns schedule state, recent checks, and incidents.
- `PATCH /api/v1/schedules/{id}` updates the target, interval, timeout, failure threshold, or enabled state. `DELETE` soft-deletes the schedule.
- `GET /api/v1/schedules/{id}/history` and `GET /api/v1/incidents` return scheduled check history and availability incidents.

Intervals are from 60 seconds through 86,400 seconds (one minute through one day). Request timeouts are greater than zero and at most 30 seconds. Incident thresholds are 1–10 consecutive failed checks. A successful HTTP response (status below 400) resets the consecutive-failure count and resolves an open incident; the configured threshold opens one incident, and subsequent failures update that incident rather than creating duplicates.

On-demand and scheduled targets must be public HTTP or HTTPS URLs. Internal, local, metadata, and credential-bearing URLs are rejected. Scheduled URLs with sensitive query parameter names are rejected; on-demand checks redact those parameter values from responses and persisted history. Store authenticated health endpoints outside this feature until a dedicated secret store and redaction policy are added.

Schedules persist their due time and lease in PostgreSQL. Run the scheduler as a separate process from the API. Workers claim due schedules with PostgreSQL `FOR UPDATE SKIP LOCKED` and a 60-second expiring lease; a worker crash leaves the due time intact for retry after lease expiry. The execution slot is unique per schedule and due time, and its check row, schedule state, and incident transition commit together. After downtime, a due schedule runs once and then resumes its interval; missed intervals are coalesced rather than replayed as a burst. Pause stops future claims; resume makes the schedule due immediately.

Start the API in one PowerShell terminal:

```powershell
python -m uvicorn services.api.main:app --reload
```

Start the worker in a second terminal from the project directory, using the same `.env` and Python environment:

```powershell
.\.venv\Scripts\Activate.ps1
python -m services.api.scheduler
```

The worker polls once per second, retries database outages, and handles check timeouts and unexpected checker failures without logging target URLs or exception details. It must be running for schedules to execute. Multiple workers may run concurrently; PostgreSQL row locks and leases coordinate claims.

Create a schedule through the API (or the dashboard). Its first run is due after the selected interval:

```powershell
$schedule = Invoke-RestMethod -Method Post `
  -Uri 'http://127.0.0.1:8000/api/v1/schedules' `
  -ContentType 'application/json' `
  -Body (@{
    url = 'https://example.com/health'
    interval_seconds = 60
    timeout_seconds = 5
    failure_threshold = 3
  } | ConvertTo-Json)

$schedule
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/schedules/$($schedule.id)"
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/schedules/$($schedule.id)/history"
```

Pause or resume with `PATCH /api/v1/schedules/{id}` and a JSON body of `{"enabled":false}` or `{"enabled":true}`. Resume makes it due immediately. Delete through the dashboard confirmation or `DELETE /api/v1/schedules/{id}`; deletion is soft and retains history.

The dashboard summary and table are loaded from saved data. The table shows up to the latest 100 checks; summary figures cover the full history. Response latency averages include checks with a recorded response time.

The dashboard shows API and PostgreSQL readiness, on-demand check totals, scheduled endpoints, recent scheduled results, incidents, email delivery status, and an optional VirusTotal reputation lookup. Scheduled results are real checks, not simulated telemetry; reputation is clearly labeled third-party information and is not joined to incidents. This is endpoint availability monitoring; it does not provide a network map, intrusion detection, or vulnerability scanning.

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

The default persistence/API and scheduler tests use isolated in-memory SQLite databases; they do not modify or reset the PostgreSQL development volume. SQLite exercises schedule and lease logic sequentially but does not verify PostgreSQL's concurrent row-lock behavior. SSRF tests mock DNS and socket backends, so they do not make requests to real external services.

Opt-in PostgreSQL integration tests use the database configured in `.env`. They intentionally leave one unique synthetic check row and a soft-deleted synthetic schedule in place; no existing data is removed. The tests cover persistence across app restarts, concurrent claims, and lease recovery:

```powershell
$env:CLOUDSENTINEL_TEST_POSTGRES = "1"
python -m pytest -q tests/test_monitor.py::test_postgres_check_history_survives_api_restart tests/test_monitor.py::test_postgres_concurrent_workers_claim_one_due_schedule
Remove-Item Env:CLOUDSENTINEL_TEST_POSTGRES
```

## Incident email notifications

Incident open and resolve transitions insert a notification outbox row in the same PostgreSQL transaction as the incident update. A unique `(incident_id, event_type)` key prevents duplicate outbox events. Run the notification worker separately from Uvicorn and the scheduler:

```powershell
.\.venv\Scripts\Activate.ps1
python -m services.api.notifications
```

`ALERT_EMAIL_DEV_MODE=true` (default) suppresses delivery and marks events `suppressed`; no SMTP or HTTP provider connection is made. Incident-opened email is queued after the configured consecutive-failure threshold. Resolution email is queued only when `ALERT_EMAIL_ON_RESOLVE=true` (default false). The unique `(incident_id, event_type)` outbox constraint prevents the same lifecycle event being enqueued twice. Attempts and generic delivery status are persisted in `notification_attempts` and shown in the dashboard.

For local delivery, `docker compose up -d mailpit` starts a local SMTP sink and web inbox. `.env.example` points host-run processes at `127.0.0.1:1025`; open [http://127.0.0.1:8025](http://127.0.0.1:8025) to inspect messages. Set `ALERT_EMAIL_DEV_MODE=false`, `SMTP_FROM=cloudsentinel@example.test`, and `ALERT_EMAIL_TO=operator@example.test` in the local `.env`. SMTP settings are `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `ALERT_EMAIL_TO`, and `SMTP_STARTTLS`. Credentials must be supplied together or both left empty. Unencrypted SMTP is permitted only to loopback or Mailpit in development. For production SMTP (including Resend SMTP), use STARTTLS on port 587 with provider-issued credentials.

Resend's API adapter is available with `EMAIL_PROVIDER=resend_api`, `RESEND_API_KEY`, a verified `SMTP_FROM`, and `ALERT_EMAIL_TO`. It uses a fixed HTTPS endpoint, a 10-second timeout, no redirects/proxy, and an idempotency key derived from the durable incident-event ID; [Resend documents a 24-hour idempotency window](https://resend.com/changelog/idempotency-keys). Retries reuse the same key and Message-ID. If recovery would retry after the provider's 24-hour guarantee expires, the event becomes `uncertain` for operator verification instead of risking a duplicate. Resend credentials are not required locally. Store credentials only in `.env` or the deployment secret manager. Messages contain incident and schedule IDs and the endpoint host; they omit URL paths, query strings, and probe error details.

Delivery is bounded to five attempts with exponential delay and a 120-second expiring claim. Each attempt is durably recorded as `sending` before provider I/O, so a restart can recover it. A stale Resend attempt retries using the same provider idempotency key; a stale SMTP attempt becomes `uncertain` and is never resent. Provider errors are reduced to generic status text and never include credentials, response bodies, or message content in logs or database state. SMTP connection/setup failures and explicit temporary rejections can retry safely. If SMTP fails during message acceptance and delivery is ambiguous, the event is recorded as `uncertain` and is not resent, avoiding a duplicate at the cost of requiring manual mailbox/provider verification. Explicit SMTP rejection is terminal. Track `incident_notifications` statuses (`pending`, `sending`, `delivered`, `suppressed`, `failed`, `uncertain`) and inspect per-attempt history in the dashboard.

Run the opt-in Mailpit test with a local container; it uses isolated SQLite and makes no real-provider requests:

```powershell
$env:CLOUDSENTINEL_TEST_MAILPIT = '1'
python -m pytest -q tests/test_mailpit_integration.py
Remove-Item Env:CLOUDSENTINEL_TEST_MAILPIT
```

For manual delivery, create a schedule for a public health endpoint you control that deliberately returns HTTP 5xx. Set `failure_threshold=1`, run the scheduler and notification workers, and inspect Mailpit. If resolution email is enabled, let that same endpoint return HTTP 2xx on the next check. Do not use an endpoint whose failure could trigger operational action.

## Production deployment and operations

Run the API and the combined scheduler/notification worker as separate supervised processes. For local Windows development, use separate PowerShell terminals from the repository root:

```powershell
# API
$env:CLOUDSENTINEL_ENV = 'development'
python -m uvicorn services.api.main:app --host 127.0.0.1 --port 8000

# Scheduler and notification outbox, in another terminal
python -m services.api.worker
```

For diagnosis or isolation, either loop can also be started separately with `python -m services.api.scheduler` or `python -m services.api.notifications`.

For deployment set `CLOUDSENTINEL_ENV=production` and a randomly generated `CLOUDSENTINEL_API_TOKEN` (at least 32 characters with sufficient character diversity). Generate it locally with `python -c "import secrets; print(secrets.token_urlsafe(32))"`, then put it directly in the hosting provider's secret environment settings. Do not put the generated value in source control, a deployment file, or a shared log. Production startup refuses a missing, short, default, or low-diversity token. The API automatically trusts Render's exact `RENDER_EXTERNAL_HOSTNAME`; for other hosts, set comma-separated `CLOUDSENTINEL_ALLOWED_HOSTS`. Wildcard hosts are rejected in production. Production startup fails if neither source supplies a host; requests with other Host headers are rejected. API routes return 401 if requests omit or provide an invalid token. The dashboard prompts for the bearer token and keeps it in session storage for that browser session. Use HTTPS. This is a single-tenant shared bearer token, not user accounts or role-based access: every authorized operator can access all schedules, history, and incidents. There are no per-user ownership checks; 403 role-denial behavior does not apply. Rotate the token through the secret manager and restart API processes.

Production probes require `CLOUDSENTINEL_TARGET_ALLOWLIST`, a comma-separated list of approved hostnames/domains. An entry such as `example.com` permits that exact hostname and its subdomains; both API and worker need the same value. With no entry, production checks are rejected. Public IP validation still rejects private, loopback, link-local, reserved, multicast, and metadata addresses after resolution; connections use the validated pinned IP and redirects are disabled. Probe responses are streamed with a 1 MiB read cap. In development, an empty allowlist preserves public endpoint testing; private addresses remain rejected. Approve only domains you control or are authorized to monitor.

For an isolated public smoke-test allowlist, `example.com` is a safe documentation domain:

```text
CLOUDSENTINEL_TARGET_ALLOWLIST=example.com
```

That entry also permits its subdomains. For real staging checks, replace it with only public hostnames/domains you own or are explicitly authorized to monitor. Add targets by updating the provider's `CLOUDSENTINEL_TARGET_ALLOWLIST` secret/config value with a comma-separated entry, reviewing the exact domain and its subdomain scope, then restarting/redeploying both API and worker with the same value. Remove a target by deleting its entry and restarting/redeploying both services. Existing schedules to removed targets remain stored but future probes are rejected by the runtime allowlist; delete or pause those schedules through the authenticated API.

Set `CLOUDSENTINEL_AUTH_RATE_LIMIT` (default 10 failed auth attempts), `CLOUDSENTINEL_CHECK_RATE_LIMIT` (default 60 on-demand checks), `CLOUDSENTINEL_SCHEDULE_RATE_LIMIT` (default 20 schedule create/update/delete operations), and `CLOUDSENTINEL_REPUTATION_RATE_LIMIT` (default 30 reputation lookups). Values are maximum requests per observed client IP in a rolling minute. These limits are process-local and reset on restart; they do not aggregate across replicas. Use upstream gateway limits for public or scaled deployments. Do not trust forwarding headers without an explicitly configured proxy chain.

The API currently has one shared bearer token and one shared data scope. Any holder of the configured token can read all check history, schedules, incidents, and notification records, and can change or delete any schedule. Do not issue this token to separate customers or tenants. Tenant isolation requires an ownership model and a data migration before this service can safely serve multiple parties.

PostgreSQL uses `POSTGRES_HOST`, `POSTGRES_HOST_PORT`, `POSTGRES_DB`, `POSTGRES_USER`, and `POSTGRES_PASSWORD` locally; Compose stores database files in the named `cloudsentinel_pgdata` volume. Use `DATABASE_URL` for a managed database connection. Back up with `pg_dump` or managed-provider backups, and periodically test restores into a separate database. Never use volume removal or database reset commands as deployment procedures. Apply reviewed migrations with `python -m alembic upgrade head` as a separate release step before starting API and worker services.

#### Safe PostgreSQL backup and restore check

For a local PostgreSQL instance, run `pg_dump` with the host, port, database, and user from `.env`; it prompts for the password instead of placing it in the command line. Keep the dump outside Git and restrict access to it:

```powershell
$backupDirectory = Join-Path $env:LOCALAPPDATA 'CloudSentinelBackups'
New-Item -ItemType Directory -Force $backupDirectory | Out-Null
$backupFile = Join-Path $backupDirectory "cloudsentinel-$(Get-Date -Format 'yyyyMMdd-HHmmss').dump"
pg_dump --format=custom --file $backupFile --host $env:POSTGRES_HOST --port $env:POSTGRES_HOST_PORT --username $env:POSTGRES_USER --dbname $env:POSTGRES_DB
if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL backup failed.' }
```

For a managed database, use its provider backup or its documented `pg_dump` connection process. Before an upgrade, confirm the dump exists, record `python -m alembic current` and `python -m alembic history`, and apply `python -m alembic upgrade head` only after reviewing the migration. The current baseline is additive and non-downgradable; do not treat downgrade as rollback.

To verify a dump, restore it into a newly created, separate empty database. Do not use `pg_restore --clean`, do not restore over the live database, and do not delete the Compose volume:

```powershell
createdb --host $env:POSTGRES_HOST --port $env:POSTGRES_HOST_PORT --username $env:POSTGRES_USER cloudsentinel_restore_verify
if ($LASTEXITCODE -ne 0) { throw 'Could not create the separate restore-verification database.' }
pg_restore --no-owner --host $env:POSTGRES_HOST --port $env:POSTGRES_HOST_PORT --username $env:POSTGRES_USER --dbname cloudsentinel_restore_verify $backupFile
if ($LASTEXITCODE -ne 0) { throw 'Restore verification failed.' }
```

Drop the temporary verification database only after the restore has been inspected and only through an explicit, separately reviewed maintenance procedure. Keep the original backup until recovery has been confirmed.

#### Staging deployment checklist

- **Ingress blocker:** the current Blueprint declares a public Render `web` service and does not configure an ingress allowlist or an access gateway. The dashboard and health endpoints are therefore publicly reachable, even though `/api/` operations require the bearer token. Do not create this Blueprint for restricted staging until a private access path or identity-aware gateway is configured and the direct Render hostname cannot bypass it. Keep the environment unprovisioned if that requirement is unmet.
- Create a separate staging service/database; do not point staging at the existing development or production database. Review the Blueprint diff to ensure it will not replace a database. Verify paid-plan and database costs, backup retention, and budget approval before creating any resources.
- Before the first schema upgrade, take a provider backup and verify restore to a separate empty staging database. Inspect `python -m alembic history` and `python -m alembic current`; then run `python -m alembic upgrade head` once against the staging database as a release step. Do not rely on API startup `create_all` as a migration system.
- Set `CLOUDSENTINEL_ENV=production`, `CLOUDSENTINEL_API_TOKEN` to a random secret of at least 32 characters, and `CLOUDSENTINEL_TARGET_ALLOWLIST` to only approved public domains. Render's exact `RENDER_EXTERNAL_HOSTNAME` is accepted for host validation; set `CLOUDSENTINEL_ALLOWED_HOSTS` for any additional custom host.
- Set `DATABASE_URL` on both web and worker services. Ensure the Render database ingress remains private.
- Keep `ALERT_EMAIL_DEV_MODE=true` until SMTP or Resend credentials and recipients are verified. Set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_STARTTLS`, and `ALERT_EMAIL_TO` for SMTP; or set `EMAIL_PROVIDER=resend_api`, `RESEND_API_KEY`, and `ALERT_EMAIL_TO` for Resend.
- `VIRUSTOTAL_API_KEY` is optional. Set the `CLOUDSENTINEL_*_RATE_LIMIT` values deliberately. Current API limits are per process, so put shared edge limits in front of multiple web instances.
- Render's Blueprint declares paid Starter web/worker services and a paid Basic PostgreSQL database. Review the Blueprint diff, plan, database replacement behavior, backup retention, health check, and expected spend before creating resources. This audit did not deploy or provision anything.
- Treat this release as single-tenant. Do not distribute the shared API token among separate customers; the application has no per-party row ownership or authorization yet.

Manual deployment sequence, once the ingress blocker is resolved:

1. Select a staging-only account/project and confirm plan prices, expected monthly spend, database retention, and a budget owner.
2. Configure private ingress or an identity-aware gateway before creating the app. Verify the direct Render hostname cannot bypass it. If this cannot be demonstrated, stop without creating resources.
3. Review `render.yaml` in the provider dashboard. Confirm it will create a new staging database and will not replace or attach any existing database. Keep database ingress private.
4. Add the required secret values to the provider secret store. Set the operator token, explicit target allowlist, and production environment. Keep alert delivery in dev/suppressed mode.
5. Create the staging database, take a provider backup, and verify restore into a second empty staging database. Record the current migration revision; apply `python -m alembic upgrade head` only to this new staging database.
6. Start the web and worker services. Confirm both resolve the same staging `DATABASE_URL`; confirm the worker stays running and the web health check passes.
7. Run the post-deployment smoke tests below, including an external-network attempt against both the gateway and direct Render hostname. Do not call staging restricted until both paths deny access outside the approved network.
8. Keep the prior application build and pre-upgrade backup available until the staging release is accepted. Follow the rollback procedure below if checks fail.

After the ingress gate is in place and staging is deliberately deployed, run these smoke checks from the authorized operator network. Use the actual staging origin and keep the token in a secret environment variable; do not paste it into logs or tickets:

1. Confirm `/health` returns 200 and `/health/ready` returns 200 after the database is ready. Confirm the worker process starts both scheduler and notification loops and remains healthy in its logs.
2. Confirm an unauthenticated `GET /api/v1/schedules` returns 401, a wrong bearer token returns 401, and the configured operator token succeeds.
3. Create a schedule for a host inside the target allowlist and confirm a host outside it is rejected with 422. Confirm the allowed check appears in history after a worker run.
4. Confirm a request from outside the approved access path is denied, including direct access to the Render hostname. A gateway that leaves a public bypass is not sufficient.
5. Confirm incident notifications remain suppressed while `ALERT_EMAIL_DEV_MODE=true`; do not enable real delivery until sender credentials and recipient are explicitly verified.

For application-only rollback, redeploy the last known-good build while leaving the database and its volume untouched. If a migration has already run, do not downgrade. Restore the pre-upgrade backup into a separate database, verify it, and only then point the staging services at that restored database. Preserve the original database and backup until recovery is confirmed; never use a reset, volume deletion, or in-place destructive restore as rollback.

The PostgreSQL engine uses connection timeout, pool checkout timeout, and pre-ping. `/health` is liveness; `/health/ready` runs `SELECT 1`. Capture process output with the host's log service; application logs intentionally omit targets, SMTP details, and exception payloads. Supervise and restart both API and combined worker processes. PostgreSQL recovers scheduled checks after the 60-second lease. After an email lease expires, Resend retries safely with the same idempotency key; SMTP is marked `uncertain` and is not resent. Worker liveness is not currently shown in the dashboard.

### Render deployment preparation

The restricted staging checklist, safe example target, backup/rollback guidance, and post-deployment smoke commands are in [STAGING.md](STAGING.md). Production also requires a server-side gateway secret; the sample Cloudflare Access Worker is in `gateway/`. Direct access to the public Render origin is rejected by the application unless this secret is present, while `/health` returns minimal liveness data for the provider health check.

[`render.yaml`](render.yaml) is a reviewable Render Blueprint and does not deploy anything by itself. It declares the FastAPI web service, one persistent background worker, and private PostgreSQL. The worker runs scheduler and notification outbox loops in one supervised process via `python -m services.api.worker`; each loop maintains its own DB connection pool. The database ingress allowlist is private. Email delivery starts suppressed (`ALERT_EMAIL_DEV_MODE=true`) so a first deployment cannot send messages unexpectedly.

Render's background workers require a paid compute plan. The free PostgreSQL tier expires after 30 days, so it is unsuitable for durable monitoring history. The Blueprint selects paid Starter compute for web and worker and a paid Basic PostgreSQL plan. Review [current Render pricing](https://render.com/pricing), [compute plans](https://render.com/docs/compute-plans), [free-tier limits](https://render.com/docs/free), and [Blueprint settings](https://render.com/docs/blueprint-spec) before provisioning; prices and plan IDs can change. A free web service can sleep and has restricted outbound SMTP ports. Prefer always-on paid compute and an HTTPS email provider such as Resend API if those restrictions apply. No Render account, service, or paid resource has been created.

At Blueprint setup, provide `CLOUDSENTINEL_API_TOKEN`; Render supplies the `onrender.com` hostname used by the API's exact-host check. Add any custom domain to `CLOUDSENTINEL_ALLOWED_HOSTS`. `sync: false` variables and provider credentials belong in Render's secret environment settings, never in Git. To enable email, deliberately change `ALERT_EMAIL_DEV_MODE=false` after configuring SMTP or Resend API and verifying the sender. `VIRUSTOTAL_API_KEY` is optional. Keep the database private and verify the Blueprint diff for any database replacement before applying it. Back up before rollout; retain provider-managed backups and periodically test a restore into a separate database. Use `/health` for liveness and `/health/ready` for database readiness. Review API and worker logs separately. Add explicit Alembic migrations before changing existing columns or coordinating production schema upgrades.

### Optional VirusTotal reputation lookups

`POST /api/v1/reputation` is disabled unless `VIRUSTOTAL_API_KEY` is configured. It reads existing public domain/IP reports only; ordinary endpoint monitoring never calls this provider. The caller explicitly supplies a public domain or global IP; URLs, credentials, local names, secret-like query data, and non-public addresses are rejected. Before a domain is sent to the provider, it must resolve exclusively to public IP addresses. Results are cached for one hour and the PostgreSQL quota state limits calls to four per rolling minute and 500 per UTC day. This is third-party reputation enrichment, separate from availability incidents and not proof of a threat. VirusTotal's [Public API policy](https://docs.virustotal.com/reference/public-vs-private-api) limits the public tier (4/minute, 500/day) to personal/non-commercial use; do not use that tier in a commercial service. Select a suitably licensed provider for commercial use. No API key or live external lookup is required for normal operation.

### Safe DNS and HTTPS diagnostics

Run these only for a public endpoint you are permitted to access. They test Windows DNS and outbound HTTPS independently from CloudSentinel:

```powershell
Resolve-DnsName example.com -Type A
Test-NetConnection example.com -Port 443 -InformationLevel Detailed
curl.exe --noproxy "*" -I --connect-timeout 5 --max-time 10 https://example.com/
```

If `Resolve-DnsName` fails, investigate host DNS/resolver configuration. If DNS succeeds but TCP 443 fails, investigate firewall, proxy, or outbound network policy. If those commands succeed while CloudSentinel fails, inspect API/worker logs and compare from the same host: probes intentionally pin validated public DNS addresses, ignore configured HTTP proxies, and do not follow redirects. Do not mark failed probes successful by weakening timeouts or validation.
