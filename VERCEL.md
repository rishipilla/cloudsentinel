# Vercel Hobby deployment notes

Vercel can serve the existing `services.api.main:app` FastAPI application as one Python Function. `pyproject.toml` points Vercel at that existing ASGI instance, so no duplicate route shim is needed. `.python-version` selects Python 3.14, which matches local verification and is supported by Vercel's Python runtime. Local development remains:

```powershell
python -m uvicorn services.api.main:app --reload
```

## Deployment blockers

Do not deploy this project to a database until its existing data, endpoint, backup, and schema have been verified. API startup currently calls `initialize_database()`, which creates tables and applies additive PostgreSQL alterations. Deploying with production `DATABASE_URL` can therefore mutate a remote database during application startup. Do not deploy against an existing database until its backup is verified and the owner explicitly approves this schema operation. No remote database or Vercel environment has been configured or verified by this repository change.

Vercel does not provide durable local filesystem storage for application data. Configure `DATABASE_URL` to a persistent PostgreSQL service reachable from Vercel; do not use SQLite or a local file. The local Compose PostgreSQL volume is development data and is not available to Vercel. The Render PostgreSQL resource described by `render.yaml` is not proof of a deployed or externally reachable database.

## Vercel project environment variables

Set these in the Vercel project settings, never in source control:

- Required: `DATABASE_URL`, `CLOUDSENTINEL_ENV=production`, `CLOUDSENTINEL_API_TOKEN`, `CLOUDSENTINEL_GATEWAY_SECRET`, `CLOUDSENTINEL_ALLOWED_HOSTS`, and `CLOUDSENTINEL_TARGET_ALLOWLIST`.
- Optional rate limits: `CLOUDSENTINEL_AUTH_RATE_LIMIT`, `CLOUDSENTINEL_GATEWAY_RATE_LIMIT`, `CLOUDSENTINEL_CHECK_RATE_LIMIT`, `CLOUDSENTINEL_SCHEDULE_RATE_LIMIT`, and `CLOUDSENTINEL_REPUTATION_RATE_LIMIT`.
- Optional integrations: `VIRUSTOTAL_API_KEY`, email provider settings such as `EMAIL_PROVIDER`, `RESEND_API_KEY`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_STARTTLS`, and `ALERT_EMAIL_TO`.
- Set `CLOUDSENTINEL_CORS_ORIGINS` only if the dashboard is hosted on another origin. Add the exact Vercel hostname to `CLOUDSENTINEL_ALLOWED_HOSTS` after the project hostname is known.

The gateway secret is required by production startup and protects application routes from requests that bypass the approved gateway. The API bearer token remains a separate credential for API routes. Generate separate high-entropy values locally and enter them through Vercel's secret environment-variable UI. Never put either value in browser code or paste it into chat.

## Worker and scheduling limits

Do not run `python -m services.api.worker` as a Vercel process. Vercel Functions are request-driven, not persistent workers. Hobby Cron is limited to one invocation per day; that is insufficient for schedules configured with intervals shorter than one day. Supporting it requires a secured, idempotent HTTP cron endpoint that processes due work within the function execution limit, plus a `CRON_SECRET` stored in Vercel settings. The current project has no such HTTP trigger. A once-daily trigger also does not provide frequent monitoring; use a separately approved scheduler or a persistent worker host when checks need to run more frequently.

## Safe deployment sequence

1. Verify the Vercel account is on Hobby and review usage limits before deploying.
2. Choose and verify a persistent PostgreSQL service and network access from Vercel. Confirm an up-to-date backup and schema compatibility.
3. Obtain explicit approval before any remote schema migration or startup schema alteration. The current API startup performs database initialization, so this must be resolved before using an existing database.
4. In Vercel project settings, add the required production variables and secrets. Do not commit `.vercel` credentials or environment files.
5. Authenticate the Vercel CLI locally, link the project to the correct account, and use `vercel dev` to verify the app locally. A deploy from this working tree must include the uncommitted changes without committing or pushing them.
6. Before production use, test `/health`, missing and invalid gateway credentials, missing and invalid bearer tokens, a permitted target, a rejected private target, and database persistence. Treat scheduling as unavailable until an approved scheduler is configured and verified.

Rollback by directing the Vercel project back to the prior deployment using Vercel's dashboard or CLI. Do not roll back by dropping, resetting, or restoring over the active database. Database restoration requires a separately verified backup and explicit approval.
