# CloudSentinel restricted staging runbook

Status: **deployment blocked pending infrastructure setup and external verification**. This repository's `render.yaml` creates a public Render web service. The application change below makes all requests except minimal `GET /health` reject a missing or invalid gateway credential in production. That is an application-level origin guard; the Render service still has a public network address, and no real gateway/origin pair has been configured or tested. Do not call it privately networked or staging-ready until the exact access path is configured and direct-origin bypass is checked.

No actual Render origin hostname, gateway hostname, or gateway configuration exists in the repository or current environment. Do not infer them from the service name. Use the actual hostname assigned by the provider when configuring the Worker. The proposed URLs are therefore placeholders: public gateway `https://<chosen-gateway-host>` and guarded origin `https://<actual-render-service>.onrender.com`.

## Recommended gateway architecture

Use Cloudflare Access in front of the Cloudflare Worker in [`gateway/worker.js`](gateway/worker.js). The Worker is a fixed-destination reverse proxy: it accepts only an HTTPS `*.onrender.com` `ORIGIN_URL`, overwrites any inbound `X-CloudSentinel-Gateway-Secret` header with its own secret binding, and forwards to that fixed Render origin. It never uses a browser-supplied destination. The Cloudflare Access policy should allow only the one operator's verified identity. Enable Worker-level Access and disable `workers.dev` and preview URLs; do not expose an alternate unprotected Worker route. Cloudflare documents that Access checks requests before a protected Worker runs and supports Worker-level protection across its associated routes and hostnames ([Cloudflare Access for Workers](https://developers.cloudflare.com/workers/configuration/cloudflare-access/)).

The app separately requires `CLOUDSENTINEL_GATEWAY_SECRET` for the dashboard, static assets, readiness, and every API path. It compares the header in constant time and returns a generic 404 for a missing or wrong value without logging it. Only exact `GET /health` is exempt so Render's platform health check can function; it returns only `{"status":"healthy"}`. Thus a direct-origin request can still reach that minimal liveness response, but cannot reach the dashboard, static files, readiness details, or API routes without the gateway credential. A correct gateway credential still does not replace `CLOUDSENTINEL_API_TOKEN` on `/api/` routes.

The browser uses the gateway hostname only. Cloudflare Access authenticates the operator before the Worker runs. The browser dashboard then uses the existing bearer-token prompt/session storage for API requests. The gateway secret exists only in the Render API service secret settings and the Cloudflare Worker Secret binding; the Worker deletes a caller-provided copy and injects the configured value server-side. It must never appear in HTML, browser requests, source files, or plain Worker variables. API, dashboard, and static assets share the gateway origin; the worker is a separate background service using the same private `DATABASE_URL` and target allowlist as the API. PostgreSQL remains private to Render's service network. The Worker uses `cache: "no-store"` for its origin fetch and forces `Cache-Control: no-store, private` on responses; the API also marks normal, authentication, rate-limit, and gateway rejection responses private and non-cacheable.

Render also supports inbound IP allowlists for web services, but its current documentation requires a Scale or Enterprise workspace plan. These rules block disallowed source IPs before requests reach the service ([Render inbound IP rules](https://render.com/docs/inbound-ip-rules), [Blueprint `ipAllowList`](https://render.com/docs/blueprint-spec)). The Blueprint uses the legacy `starter` plan, so this control is not available as configured. Cloudflare Worker egress is not a single operator IP to put into a CIDR allowlist. If a future gateway has stable egress IPs and the Render plan supports web-service rules, allow only those IPs as an additional network layer; retain the application secret check.

| Origin-protection option | Can a direct Render URL request reach protected routes? | Assessment |
|---|---|---|
| Authenticated gateway/reverse proxy only | **Yes**, unless the origin also enforces a restriction. | Not sufficient by itself; public DNS secrecy is not access control. |
| Gateway injects a secret header; application validates it | **No**, unless the header secret is exposed or compromised. | Chosen for this public-service setup. It blocks dashboard/static/API/readiness routes at app middleware, but the origin remains network-reachable and `/health` intentionally returns minimal liveness. |
| Render inbound IP allowlist | **No** from non-allowlisted source IPs. | Network-level control, but web-service rules require Scale or Enterprise. A gateway needs stable egress IPs; Worker egress is not a single fixed address. |
| Render private service plus Cloudflare Tunnel connector | **No public Render origin exists.** | Strongest network isolation. The API becomes a Render private service, and a long-running `cloudflared` connector in the same Render private network makes an outbound tunnel to Cloudflare; Access protects the tunnel hostname. This needs a new connector service/image and provider configuration, so it is a viable alternative architecture but not locally verified here. Render documents private services as private-network-only. |

### Gateway secret lifecycle

Generate a separate random value locally without echoing it to the terminal:

```powershell
$gatewaySecret = python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Set the same value as a **secret** named `CLOUDSENTINEL_GATEWAY_SECRET` on the Render API and Cloudflare Worker. Set `ORIGIN_URL` as a non-secret Worker variable to the exact HTTPS Render origin. Set neither in browser-facing settings. Store recovery copies in the operator's password manager. For rotation, generate a new value and update both secret stores in one planned maintenance window; while they differ, the Worker fails closed with 404. Verify the gateway, then remove local copies. If the value is lost, generate a replacement and update both sides; do not weaken or disable the guard. Rotate the bearer token independently through Render's secret settings and update the operator's password manager/session.

This is a single-operator, single-tenant deployment. It has one shared bearer token and no per-user ownership or authorization. Anyone holding the token can see or change all schedules, checks, incidents, and notification records.

## Approved target example

`staging-targets.example` contains one safe documentation-domain entry: `example.com`. It is suitable only as an isolated plumbing example; it is not a service you own or a target for availability guarantees. For real checks, replace it with exact public hostnames for services you own or have explicit permission to monitor. A domain entry approves that name and all its subdomains. Do not add a parent domain unless that entire subdomain scope is approved. Never add private, loopback, link-local, metadata, or otherwise unauthorized hosts.

Set the same comma-separated value as `CLOUDSENTINEL_TARGET_ALLOWLIST` on API and worker. To add a target, approve its ownership and exact hostname/subdomain scope, add only that domain entry, then restart/redeploy both services. To remove one, delete its entry, restart/redeploy both services, and pause/delete any schedule using it. Runtime checks enforce the allowlist again, so stale schedules cannot keep probing a removed target.

## Required environment settings

Configure these in the provider environment panel; secret values belong only in its secret store.

| Name | API | Worker | Setting |
|---|---:|---:|---|
| `CLOUDSENTINEL_ENV` | yes | yes | `production` |
| `CLOUDSENTINEL_API_TOKEN` | yes | no | Locally generated strong token, provider secret |
| `CLOUDSENTINEL_GATEWAY_SECRET` | yes | no | Same random secret in the Worker Secret binding and Render API secret |
| `CLOUDSENTINEL_TARGET_ALLOWLIST` | yes | yes | Explicit approved public domains only |
| `CLOUDSENTINEL_ALLOWED_HOSTS` | if not provider-injected | n/a | Exact API hostname(s); no wildcards |
| `DATABASE_URL` | yes | yes | Same new staging PostgreSQL instance, private connection URL; secret |
| `ALERT_EMAIL_DEV_MODE` | n/a | yes | `true` to suppress delivery |
| `ALERT_EMAIL_ON_RESOLVE` | n/a | yes | `false` |

Render injects `RENDER_EXTERNAL_HOSTNAME`, which this app adds as an exact trusted host. `CLOUDSENTINEL_CORS_ORIGINS` should be unset/empty for the same-origin dashboard. `debug` is hard-coded off. Keep `VIRUSTOTAL_API_KEY` unset; reputation checks are optional and disabled without it. Email provider credentials and recipient are not needed for smoke testing while dev mode is enabled. Do not add them unless delivery is separately approved and tested.

Optional rate settings are `CLOUDSENTINEL_GATEWAY_RATE_LIMIT`, `CLOUDSENTINEL_AUTH_RATE_LIMIT`, `CLOUDSENTINEL_CHECK_RATE_LIMIT`, `CLOUDSENTINEL_SCHEDULE_RATE_LIMIT`, and `CLOUDSENTINEL_REPUTATION_RATE_LIMIT`. The gateway-credential limit defaults to 120/minute; other defaults are documented in `.env.example`. All application limits are per observed IP per API process per rolling minute; they are not distributed controls. Apply an edge rate limit at Cloudflare as well, especially to authentication and check/schedule routes, and confirm the feature and cost in the account plan.

Generate the token on your workstation (do not print it into a build log, shell transcript, or report):

```powershell
$token = python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Paste `$token` directly into the provider's masked secret input for `CLOUDSENTINEL_API_TOKEN`, then clear the local variable when finished with `Remove-Variable token`. Do not put it in `.env.example`, `render.yaml`, source control, deployment output, or command-line arguments. Startup rejects missing, weak/default tokens and unknown environment names.

## Configuration and process review

The API command in the Blueprint is `python -m uvicorn services.api.main:app --host 0.0.0.0 --port $PORT`, with `/health` as Render's minimal liveness check. `/health/ready` is behind gateway-credential protection. The worker command is `python -m services.api.worker`; it runs the scheduler and notification loops together, handles termination signals, and closes database engines. Both services take `DATABASE_URL` from the same Blueprint database reference. Confirm the resolved connection targets the new staging database on both services before startup. PostgreSQL's `ipAllowList: []` means no public database ingress. Startup currently has additive `create_all` compatibility behavior; do not treat it as a substitute for reviewed migrations.

## Cost check before provisioning

The Blueprint currently declares two always-on `starter` compute services (web and worker) and one `basic-256mb` PostgreSQL instance with 1 GB disk. Expect charges for both compute services, database compute/storage, and any backup/retention or network overages selected. Render has changed compute plan naming; the current docs map legacy `starter` to `0.5c-512mb`. Exact monthly totals and database backup charges are account/region/plan dependent. Confirm each resource's current price and projected monthly total in the Render dashboard before any resource creation; see [Render pricing](https://render.com/pricing) and [compute plan mapping](https://render.com/docs/compute-plans). This runbook does not authorize provisioning.

## Safe manual deployment sequence (after the ingress blocker is fixed)

1. Choose an operator-controlled domain and gateway hostname; confirm actual hostnames with the providers. Create a Cloudflare Worker from `gateway/worker.js` and `gateway/wrangler.toml`. Keep `workers.dev` and previews disabled. Set `ORIGIN_URL` to the exact Render HTTPS origin and set the gateway secret as an encrypted Worker Secret. If you choose the private-service/Tunnel alternative, use a private Render service instead and configure the connector and Tunnel route; do not also leave a public web service serving the same app.
2. Attach the chosen hostname to the Worker. Create a Cloudflare Access application for the Worker and allow only the one operator identity. Enable Worker-level Access, verify Access runs before Worker code, and confirm there is no alternate unprotected Worker route. Apply an edge rate limit to the gateway. See [Cloudflare Worker Access](https://developers.cloudflare.com/workers/configuration/cloudflare-access/) and [Worker secrets](https://developers.cloudflare.com/workers/configuration/secrets/).
3. Use a separate Render staging project and new staging database. Inspect the Blueprint plan before applying it; confirm no existing database or volume is replaced or attached. Review current costs and backup retention. Record the exact generated Render origin; do not assume it from the service name.
4. Set the same gateway secret in Render's API service secret settings. Set the API token and production settings. Set the approved target list identically on API and worker. Leave VirusTotal unset and email suppressed. Render's health check should use `/health`; the service health check cannot send the gateway header.
5. Before any schema change, take a database backup and verify restoration into a separate empty database. Record `python -m alembic current` and `python -m alembic history`; inspect migrations. Apply `python -m alembic upgrade head` only to the new staging database. Do not run migrations against existing development data.
6. Start API and worker. Check readiness through the gateway, service logs, and that both use the same staging database and approved-target setting. Confirm there are no secret values in logs.
7. Run the checks below from the allowed operator path, then repeat from an unauthenticated network against both gateway and exact Render origin. Direct-origin requests to `/`, `/static/...`, `/health/ready`, and `/api/...` must fail without the gateway credential. `/health` alone is expected to return minimal liveness data. Do not use live email or VirusTotal for this smoke test.

## Backup, migration, and rollback

Before each migration, create a provider snapshot or `pg_dump --format=custom` backup without putting the database password in the command line. Record the active Alembic revision. Restore the dump into a separate empty database and verify it before relying on it. Keep the original backup and database untouched until recovery is proven.

Apply reviewed migrations with `python -m alembic upgrade head` only after backup verification. The baseline migration is non-downgradable. For an application-only failure, redeploy a previously reviewed build that still enforces the gateway secret and leave the database untouched. Never roll back to an application build that removes the origin guard while Render's origin is public. If a migration has run and data/schema recovery is needed, restore the pre-migration backup into a separate new database, validate it, then deliberately point staging services at that restored database. Never run downgrade, `pg_restore --clean`, reset, or volume deletion against the live database as rollback.

## Post-deployment smoke tests

Use the chosen gateway host after Access is configured. In PowerShell, set `$base` to that approved gateway URL and keep `$token` in a local session variable. The browser/application never receives the gateway secret. Avoid `-Verbose` and do not print the Authorization header.

```powershell
$base = 'https://<approved-staging-host>'
$headers = @{ Authorization = "Bearer $token" }

# Liveness/readiness and auth checks
Invoke-WebRequest "$base/health" -Method Get
Invoke-WebRequest "$base/health/ready" -Method Get
try { Invoke-WebRequest "$base/api/v1/schedules" -Method Get -ErrorAction Stop } catch { $_.Exception.Response.StatusCode.value__ }
$bad = @{ Authorization = 'Bearer invalid-test-token' }
try { Invoke-WebRequest "$base/api/v1/schedules" -Headers $bad -Method Get -ErrorAction Stop } catch { $_.Exception.Response.StatusCode.value__ }
Invoke-RestMethod "$base/api/v1/schedules" -Headers $headers

# Approved target: an allowed schedule is accepted; an unapproved hostname is rejected.
$approved = Invoke-RestMethod "$base/api/v1/schedules" -Headers $headers -Method Post -ContentType 'application/json' -Body (@{ url='https://example.com/'; interval_seconds=60; timeout_seconds=5; failure_threshold=1 } | ConvertTo-Json)
try { Invoke-RestMethod "$base/api/v1/schedules" -Headers $headers -Method Post -ContentType 'application/json' -Body (@{ url='https://iana.org/'; interval_seconds=60 } | ConvertTo-Json) } catch { $_.Exception.Response.StatusCode.value__ }

# Observe worker execution and durable history; inspect the schedule/history endpoints.
Start-Sleep -Seconds 75
Invoke-RestMethod "$base/api/v1/schedules/$($approved.id)" -Headers $headers
Invoke-RestMethod "$base/api/v1/schedules/$($approved.id)/history" -Headers $headers
```

For persistence across an API/worker restart, confirm the same schedule and completed check remain in history after restarting those services. For incident creation, use a separately approved public test endpoint you control that deliberately returns HTTP 5xx; set `failure_threshold=1`, wait for a worker run, and confirm one open incident appears. Do not use an endpoint where failure causes real operational action. Confirm email status is `suppressed`. From outside the approved access path, verify Cloudflare Access blocks the gateway before the Worker runs. At the exact Render origin, verify `/`, `/static/app.js`, `/health/ready`, and `/api/v1/schedules` return 404 without a gateway secret and with an invalid one. `/health` is the deliberate exception and should return only `{"status":"healthy"}`. Confirm no browser request or HTML/JavaScript response contains the gateway secret. The direct-origin route denial is a required acceptance gate.

## Remaining operational limit

Rate limiting is in-memory per API process. It resets on restart and does not coordinate replicas; source-IP attribution also depends on a correctly trusted proxy chain. Keep the gateway rate limit in front of the application and add distributed rate limiting before running multiple API instances or exposing broader access. The app's single shared token is suitable only for one trusted operator, not multiple users or tenants.
