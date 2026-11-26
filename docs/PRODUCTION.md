# Production deployment runbook — v0.7

## Architecture and release policy

Browser (Vercel static site, HTTPS) → direct HTTPS FastAPI API (Render Docker service) → private managed PostgreSQL. Same-origin Render frontend also works. The browser receives only the public API origin; API credentials and JWT signing secret never enter the Vercel build. No new infrastructure was provisioned in this task. Prefer a private staging deployment first. Render Blueprint chooses paid `standard` compute and `basic-256mb` database plans; verify current pricing and resource suitability before creating them. 2GB compute is a starting point for CV2, ML and Argon2; monitor memory and adjust, not a benchmark. Free plans may not support pre-deploy migration commands or have adequate resources. Avoid real sensitive inputs during tests.

## 1. GitHub

Create a repository; from root of extracted source:

```sh
git init
git add .
git commit -m "ScamShield AI Phase 7"
git branch -M main
git remote add origin https://github.com/YOUR-ACCOUNT/scamshield-ai.git
git push -u origin main
```

Check `.gitignore` first: `.env`, data dumps, model reports and secrets must not be committed. Enable required CI `test` checks and protect main against unreviewed changes. GitHub Actions CI runs on PR and main pushes: Python 3.12, English Tesseract, temporary PostgreSQL 16, regression tests, PostgreSQL-specific tests, JS syntax, static site build, Docker build, dependency audit. Audit may fail on vulnerable or unavailable dependencies; resolve before release, do not bypass. Dependency ranges remain unpinned; production releases should lock and audit dependencies and base image digests. No deployment tokens required in Actions; CD uses each platform's Git integration. Render is configured to deploy only when checks pass. Configure Vercel required Deployment Checks if your plan supports them; otherwise turn off automatic production promotion and deploy reviewed, green main commits manually. No Actions run or deployment was executed here. Never allow secrets into untrusted PR workflows.

## 2. Render backend and database

1. In Render Dashboard, New → Blueprint, select repository and main branch. `render.yaml` declares Docker service, PostgreSQL, pre-deploy migration, readiness health check and CI gate. Review selected plans/region and billing before applying. The two resources should be in the same region/private network.
2. Render generates `JWT_SECRET` and supplies internal `DATABASE_URL`. The backend normalizes `postgres://` and `postgresql://` to the Psycopg 3 dialect. Do not use a public database connection unless configured securely. Keep database public IP allowlist empty. Ensure the generated JWT secret is high entropy (at least 43 characters); set a random `secrets.token_urlsafe(48)` value manually if rejected. Do not rotate it unintentionally: invalidates existing tokens and resets HMAC-keyed quota buckets.
3. Enter an exact intended Vercel origin (e.g. `https://YOUR-PROJECT.vercel.app`) in `FRONTEND_ORIGINS`; you may initially use your intended project name and update after Vercel deploy. Multiple origins may be comma-separated; no wildcard/trailing slash. Set optional `GEMINI_API_KEY` and `VIRUSTOTAL_API_KEY` privately or leave blank. `GEMINI_MODEL` may be configured to a model available on your account. The existing default is configurable; verify provider entitlement. Do not put these values in Vercel.
4. First deploy executes `python -m alembic upgrade head` as a pre-deploy command. Confirm readiness and migration revision; never run multiple migrations concurrently. If pre-deploy commands are unavailable on your plan, use a trusted migration job or choose a suitable plan before starting. The application refuses startup if database revision is not current. Use `/api/health/ready` and `/api/health/live` checks. The Docker start script has one worker by default, no access logging, bounded concurrency, non-root user, and OCR executable.
5. `RENDER_EXTERNAL_HOSTNAME` is automatically allowlisted. If using a verified custom backend domain, add it to `ALLOWED_HOSTS` (exact names, no scheme/paths). For production security do not use `*`. `TRUSTED_PROXY_IPS` blank ignores forwarded headers; consequently IP-based quotas may aggregate clients behind a Render proxy. Before broad public use confirm the provider's trusted proxy CIDRs and ingress isolation, then set the exact comma-separated trusted IPs/CIDRs in `TRUSTED_PROXY_IPS`. Never use `*`, `0.0.0.0/0` or `::/0`; do not trust arbitrary X-Forwarded-For. Check spoofed headers and rate limits on staging. Per-user and shared provider quotas are independent of IP. A WAF/bot challenge, abuse monitoring and verified email are still required for broad anonymous registration.
6. Test the Render-hosted frontend directly, at `https://YOUR-SERVICE.onrender.com`. If using Vercel proceed below. For production set `REQUIRE_REAL_DATASET=1` only after building an image containing a properly sourced external dataset. `FETCH_UCI_DATASET=1` Docker build arg opts into fetching UCI at build time; for Render, configure build arg according to Render Docker docs (environment variable of same name) or explicitly change the Dockerfile ARG default after review. Network failures cause build failure, rather than quietly claiming validation. Data is not downloaded at runtime.

## 3. Vercel static frontend

New Project → Import GitHub repository → choose Other/framework preset (root = repository root). `vercel.json` runs `node scripts/build_frontend.mjs`, publishes only `dist`, adds security headers. Set `PUBLIC_API_ORIGIN=https://YOUR-SERVICE.onrender.com` (exact HTTPS Render origin, no slash); this is public, not secret. The build rejects missing or non-Render origins. Custom backend domain requires deliberately extending build validation and CSP connect-src. Redeploy after changing the public origin. If using Vercel preview sites, use a separate staging backend or add an exact preview origin temporarily; do not allow all `*.vercel.app` in API CORS. Update backend `FRONTEND_ORIGINS` to the exact production Vercel URL. Tokens travel in Authorization headers, stored only in JS memory; no cookies or credentialed CORS. Raw image uploads go directly to Render (not through Vercel Functions). Ensure production deployment checks or manual promotion are configured; verify green CI for intended commit.

References: https://render.com/docs/blueprint-spec ; https://render.com/docs/docker ; https://render.com/docs/health-checks ; https://vercel.com/docs/project-configuration/vercel-json ; https://vercel.com/docs/deployments ; https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments

## Environment variables

| Variable | Production value |
|---|---|
| APP_ENV | production |
| RATE_LIMIT_BACKEND | database (required in production) |
| JWT_SECRET | random >=43 characters, server only |
| DATABASE_URL | private PostgreSQL URL, server only |
| FRONTEND_ORIGINS | exact allowed frontend origins |
| ALLOWED_HOSTS | optional extra exact backend hostnames |
| TRUSTED_PROXY_IPS | optional operator-verified proxy IPs/CIDRs |
| VIRUSTOTAL_API_KEY / GEMINI_API_KEY | optional server-side secrets |
| GEMINI_MODEL | configured provider model |
| VIRUSTOTAL_DAILY_LIMIT | default 500, lower if account requires |
| GEMINI_DAILY_LIMIT | default 100, tune to budget |
| REQUIRE_REAL_DATASET | 0 demo; 1 requires external data |
| SMS_DATASET_PATH | optional path to authorized TSV inside image |
| PUBLIC_API_ORIGIN | Vercel only, public HTTPS Render API origin |

## Rate limits and privacy

Development defaults to legacy per-process sliding windows. Production uses atomic conditional upsert counters in PostgreSQL with fixed windows and automatic expiry cleanup. Identity keys are HMACed; raw email/IP not stored in counters. Per-account and per-IP limits remain: scan 20/min, image 6/min, login 20/IP/min and 5/email/min, registration 5/IP/min; production additionally caps register 30/min and login 120/min globally. Per-worker Argon2 operations limited to 2 concurrent. Provider limits shared across workers: VirusTotal 2/min (conservative fixed-window boundary behavior) and 500/UTC day; Gemini 5/min and 100/UTC day. Actual provider plans may have tighter limits, independent traffic and quotas; 429 falls back locally. Counters can allow boundary bursts, rely on synchronized clocks and shared secret/DB, and are not DDoS protection. DB limiter failure denies protected operations with 503; cloud calls are skipped if quota storage fails. Expired counter cleanup occurs on access. Monitor DB load and plan a Redis or equivalent dedicated limiter at higher volume. No raw scan content intentionally persisted; application telemetry logs request ID, method, status and elapsed time only. Hosting provider, network and cloud provider retention policies may differ; publish a real privacy notice before release.

## Monitoring, release checklist and rollback

- `GET /api/health/live` returns 200 when server responds; `/api/health/ready` checks schema and cached model, 503 on failure. Optional OCR/cloud outages do not make service unready. Render uses ready for health checks. Configure external uptime monitoring for both URLs and alerts for sustained failures, latency, memory, DB connections/storage and provider quota errors. No external monitor is configured here.
- Check health and `/api/model`; inspect dataset provenance, accuracy limitations and sample counts. Test registration, login/logout, cross-account history isolation, scan/clear history, OCR/QR upload, cloud opt-in and failures, community report moderation, account deletion and mobile UI. Verify CORS rejects unknown origin, HSTS, no-store and no secrets in static output. Check proxy behavior before public release. Inspect logs for failures without sensitive payloads.
- Make a database backup before each migration and test restore on a separate database. Keep the previous source commit/image. For v0.7 rollback, stop writers and roll back only if no newer changes depend on counters; `alembic downgrade 0002_community` drops rate counters (retains accounts/scans/community). If reverting to v0.6, understand old single-process limits; restore backup if needed. Never downgrade a live DB while v0.7 writers are active. Redeploy matching frontend/backend commit, retest, and avoid rollback if security fixes would be lost.
- Remaining gaps: live cloud credentials, live database and Docker validation, actual Vercel/Render deployment, browser UI verification, external dataset metrics, independent security audit, email verification/password recovery, moderation audit logging, bot protection, complete observability/alerting, dependency lockfiles and capacity/load testing. This is a deployment preparation package, not a certified production security release.
