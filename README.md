# Free hosting variant

This archive configures Render Free web and PostgreSQL plans in Singapore. Render serves both the frontend and API on the same origin. The Docker startup command runs Alembic before starting the single worker because free services cannot use the paid pre-deploy feature. Free Postgres expires after 30 days, and free web services have cold starts and resource limits. The previous production guide describes a paid deployment; do not use its paid plan values for this variant. Optional provider keys must be configured only in the Render dashboard. Vercel can be connected after the backend is verified.

# ScamShield AI v0.7 — Deployment preparation

A premium minimal, Python FastAPI full-stack scam-awareness application. Includes message/job/banking/URL detection, TF-IDF + logistic regression, optional Gemini explanations and VirusTotal existing-report lookups, OCR and QR recognition, JWT + Argon2id accounts, private scan metadata, community reports and moderation. This is an experimental risk indicator, not a guarantee of safety or proof of fraud. Do not enter credentials or private data.

Phase 7 adds production settings, database-backed distributed rate limits, request envelopes, exact CORS allowlists, host validation, restricted authentication concurrency, readiness/liveness, dataset import/evaluation, Docker, Render Blueprint, Vercel static build and GitHub CI with gated platform delivery. No live services are provisioned. See [production runbook](docs/PRODUCTION.md) and [legacy feature reference](docs/PHASE6_REFERENCE.md) (historical; Phase 7 instructions supersede setup, limits and migration version there).

## Run locally (Windows VS Code, Command Prompt)

Use Python 3.12 recommended. From extracted project root:

```cmd
py -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
copy .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Paste generated secret into `JWT_SECRET` in `.env`. Leave `DATABASE_URL` blank for SQLite; `APP_ENV=development`, `RATE_LIMIT_BACKEND=memory` are local defaults. Cloud keys optional. Install English Tesseract OCR separately from https://github.com/UB-Mannheim/tesseract/wiki and set `TESSERACT_CMD` if not on PATH. QR decoding does not require Tesseract.

```cmd
python -m alembic upgrade head
python -m uvicorn backend.main:app --reload
```

Open http://127.0.0.1:8000, register with a password of at least 12 characters, sign in and scan. Use `samples/demo-screenshot.png` for OCR/QR testing. API docs (development only): http://127.0.0.1:8000/docs. Health: `/api/health/live`, `/api/health/ready`. `GET /api/model` reports dataset type and metrics. Existing Gemini and VirusTotal features are opt-in and fall back locally if unavailable. Keys remain on backend; never share or commit `.env`.

### Upgrade from v0.6

Stop existing server, back up SQLite `scamshield.db` or PostgreSQL and retain your existing secret/configuration. Copy the database into v0.7 or keep the same connection string. Merge missing `.env.example` keys without overwriting existing secrets. Run `python -m alembic upgrade head`; new revision `0003_rate_counters` adds only a counter table. Do not create a fresh database if you want to keep your old history. Keep v0.6 source/backup for rollback. `python -m backend.manage_admin grant ACCOUNT_UUID` creates a moderator after registration; revoke with `revoke`. No default admin.

## Local Docker + PostgreSQL

Install Docker Desktop with Compose v2. Copy `.env.example` to `.env` and generate `JWT_SECRET` as above. Generate an independent database password `python -c "import secrets; print(secrets.token_hex(24))"` and set `POSTGRES_PASSWORD` to it (hex is URL-safe). Run:

```cmd
docker compose up --build
```

Compose starts PostgreSQL, runs migrations once, then starts FastAPI on localhost:8000. Data persists in `pgdata`. Shared limiter enabled. `docker compose down` retains the volume; `down -v` deletes data, so do not use it unless intended. Local Compose uses development mode and binds only to localhost, not a public production deployment. Docker image includes Tesseract. Docker is not installed in the development environment; actual build/Compose run pending. CI is configured to build it.

## Real-world dataset training

The bundled starter model trains offline on 100 authored synthetic examples, evaluated on 24 separate synthetic examples. Metrics are not real-world validation. UCI SMS Spam Collection (Almeida and Hidalgo, 2012, DOI: 10.24432/C5CC84) is licensed CC BY 4.0: https://archive.ics.uci.edu/dataset/228/sms+spam+collection . It is an older spam dataset, not a current India-specific scam corpus.

Download/import:

```cmd
python scripts/import_dataset.py
```

If blocked, download from the UCI dataset page, save the ZIP locally and run `python scripts/import_dataset.py --source path\to\sms.zip`. Optional `--sha256 HASH` verifies against a trusted independently obtained digest. The script reads only the named dataset member, checks class labels, size and duplicates, and writes `data/SMSSpamCollection`. No dataset is downloaded automatically at runtime. External dataset is ignored by Git to avoid redistributing raw messages. For other authorized ham/spam TSV datasets use `--source path\to\file.tsv`. External source marker is not proof of real provenance.

```cmd
python -m scripts.train_model --report model-report.json
```

The model trains from text on startup (no unsafe pickle). It uses deterministic stratified 80/20 splitting, normalized exact deduplication, synthetic augmentation excluding exact holdout matches, and reports accuracy, precision, recall, F1, confusion matrix, sample counts and SHA-256. Near-duplicate leakage is possible, and metrics are for spam classification, not the entire hybrid engine. Set `SMS_DATASET_PATH` for alternate absolute dataset path, and `REQUIRE_REAL_DATASET=1` to reject startup when no external dataset is available. This flag verifies presence, not provenance. No external data download succeeded in this environment (DNS blocked); import/training code was tested with generated fixtures only. In Docker use build argument `FETCH_UCI_DATASET=1` for explicit build-time download or provide authorized data in the build context. Review licensing/privacy before packaging raw data.

## Deploy (not yet deployed)

See [production runbook](docs/PRODUCTION.md) for GitHub, Render and Vercel steps, exact environment variables, CORS, proxy handling, costs, CI, smoke checks, monitoring, backup and known gaps. Render can serve both UI and API without Vercel; Vercel is optional static frontend hosting. The backend Docker image runs the complete API, ML and OCR.

## Tests

```cmd
python -m pytest -q
node --check frontend/app.js
```

GitHub Actions runs tests with a PostgreSQL service, static frontend build, Docker build and dependency audit. `CI_POSTGRES_URL` enables optional live PostgreSQL migration/concurrency/API checks (use only a disposable test DB). Local tests use temporary SQLite and simulated cloud APIs. Live providers, Docker, actual PostgreSQL and browser testing must be verified before public release.
