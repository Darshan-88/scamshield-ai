# ScamShield AI — v0.6 (Community threat intelligence)
A responsive premium minimal scanner with Python FastAPI, native HTML/CSS/JavaScript and a trained local scikit-learn NLP classifier. Local scanning requires no API keys; optional Gemini and VirusTotal integrations require your own keys.

## Run in VS Code (Windows)
Extract this ZIP to a new folder, open the inner `scamshield-ai-v6` folder in VS Code, then open a Command Prompt terminal. Python 3.11–3.13 recommended.

```cmd
py -m venv .venv
.venv\Scripts\activate.bat
python -m pip install -r requirements.txt
copy .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
```
Copy the generated random value into `JWT_SECRET` in `.env`. Leave `DATABASE_URL` blank for a local SQLite database or configure PostgreSQL below. Then run:

```cmd
python -m alembic upgrade head
python -m uvicorn backend.main:app --reload
```

Open http://127.0.0.1:8000. Swagger API docs: http://127.0.0.1:8000/docs. On macOS/Linux, use `python3 -m venv .venv` and `source .venv/bin/activate`.

## Phase 6: community reporting and moderation

### Upgrade an existing Version 5 installation
Stop the old server and back up its database. For the default SQLite setup, copy the existing `scamshield.db` into the new project folder after all old connections have closed (ensure any WAL is checkpointed); for PostgreSQL, back up and keep the same `DATABASE_URL`. Copy your existing local `.env` securely, adjust relative database paths if applicable, and keep the same JWT secret if you want existing tokens to remain valid. Never put `.env` or database backups into Git. Install dependencies and run `python -m alembic upgrade head` from the new directory. Migration `0002_community` preserves existing accounts and scan history. `python -m alembic current` should show `0002_community (head)`. Downgrading to `0001_accounts` destroys community records and admin flags, so back up first; native SQLite DROP COLUMN requires SQLite >= 3.35. For a new installation, use the setup commands above.

### Report and search
1. Sign in and scroll to **Community**. Choose a category and tactic. Optional domain field accepts a public-facing ASCII domain only (no full URL, IP, email, path, query or private hostname). Leave it blank if uncertain. Confirm publication consent and submit.
2. Report appears in **My reports** as Pending. You can withdraw it at any time. Pending and rejected reports are never returned by public search or analytics.
3. Public search works without signing in: filter by category, tactic or exact domain. Use ordinary dots in the search field; published domains are defanged (`example[.]com`) and never clickable. Results group identical category/tactic/domain combinations, with the count of currently approved submissions. Analytics counts only published reports. No match is not proof of safety; counts are not fraud incidence or victim counts.
4. A database unique constraint rejects duplicate normalized category/tactic/domain submissions by the same account (HTTP 409); different accounts can contribute the same indicator and are aggregated only after review. This is exact matching, not semantic similarity or Sybil/bot detection.

### Create a moderator (trusted server operator only)
Register a dedicated account and sign in. Copy the Account ID displayed in the account panel. Because email ownership is not verified, verify control of the exact account out of band before granting the role. In a trusted terminal with the same database configuration:

```cmd
python -m backend.manage_admin grant YOUR_ACCOUNT_UUID
```

Sign out and sign back in to display the **Review queue** under Community. No public admin registration, default admin password, or email-based auto-promotion exists. Registration cannot grant moderator rights. Revoke the role with `python -m backend.manage_admin revoke YOUR_ACCOUNT_UUID`. API permissions consult the database on every request, so revocation takes effect without waiting for JWT expiry. The UI may require a refresh/sign-in to update its display.

A moderator must independently check the indicator against trusted sources (e.g. an official advisory or reputable existing threat intelligence), not visit the suspicious domain, and ensure the indicator contains no private information. The app stores no free-form evidence or raw messages. Verify only if independent review supports publication; otherwise reject with a structured reason or leave pending. The system records the latest reviewer, time, reason and revision. Verification is a human attestation, not automated proof of fraud; moderators cannot review their own reports. Optimistic revision checks prevent stale decisions from silently overwriting a newer review. A verified report can be rejected or returned to pending to remove it from public search. The dashboard is empty until a moderator approves an actual submission; there are no fabricated community statistics.

### Community REST endpoints
| Method | Endpoint | Access |
|---|---|---|
| POST | `/api/community/reports` | Signed in; structured category, tactic, optional domain, consent |
| GET | `/api/community/mine` | Owner only; offset pagination and current admin flag |
| DELETE | `/api/community/reports/{id}` | Owner only; withdraw |
| GET | `/api/community/threats` | Public; category, tactic, domain, offset |
| GET | `/api/community/analytics` | Public; reviewed counts and category/tactic breakdowns |
| GET | `/api/community/admin/reports` | Moderator; status, offset |
| PATCH | `/api/community/admin/reports/{id}` | Moderator; status, reason, revision, independently_checked |

Example POST JSON: `{"category":"banking","tactic":"otp_request","domain":"","consent":true}`. Valid values and all schemas are listed in Swagger `/docs`. All list endpoints return at most 20 items and a `has_more` flag. Community limits per minute: submissions 5/account and 15/IP; own-list 60/account; withdrawals 20/account; public search and analytics 60/IP each; queue 60/moderator; review 30/moderator. Existing scan and authentication limits remain.

### Community privacy and limitations
Only structured category, tactic, optional normalized domain, account foreign key and review metadata are stored. Public responses omit email, account IDs, report IDs, reviewer details, and timestamps. Account deletion cascades submitted reports; deleting a moderator clears their reviewer reference on others’ reports without deleting those reports. Private data may still appear in a syntactically valid hostname: the domain filter is heuristic, not a public-suffix or DNS verification service. Do not submit or search private identifiers; infrastructure may log request URLs. Moderator review and explicit consent are required before public display. Account ownership is not verified and one account is not necessarily one person; duplicates across accounts may be abusive. A production service needs verified users, anti-abuse measures, moderation procedures, audit history, appeals/takedown handling and legal/privacy review. This feature is a community database, not an official fraud reporting portal, and never automatically adjusts the scanner score.

## Phase 5: database and accounts

### PostgreSQL setup (recommended for multi-user deployments)
Install PostgreSQL from https://www.postgresql.org/download/windows/ or use an existing PostgreSQL instance. In pgAdmin's Query Tool or psql, connect as an administrator and execute (use a unique strong password rather than the placeholder):

```sql
CREATE ROLE scamshield LOGIN PASSWORD 'replace-with-strong-password';
CREATE DATABASE scamshield OWNER scamshield;
```
Run `CREATE DATABASE` outside a transaction. Use the application role, not the database superuser, in `.env`:

```dotenv
DATABASE_URL=postgresql+psycopg://scamshield:replace-with-strong-password@localhost:5432/scamshield
JWT_SECRET=<your-generated-random-secret>
```
URL-encode reserved characters in username/password. For managed PostgreSQL, use its connection parameters and TLS settings (e.g. `?sslmode=require`, or verified TLS with the provider CA). The app accepts `postgresql://` and `postgres://` URLs and selects psycopg 3 explicitly. Blank `DATABASE_URL` uses the local `scamshield.db` file; SQLite is a convenience option, not a replacement for a PostgreSQL integration test. Run `python -m alembic upgrade head` whenever initializing or upgrading a database. `python -m alembic current` shows the current revision; `python -m alembic check` checks ORM/schema drift. `python -m alembic downgrade base` is destructive (drops all application tables); back up first. Do not run migrations concurrently from every server worker. For PostgreSQL SQL preview: `python -m alembic upgrade head --sql` after setting DATABASE_URL. The initial migration creates users, login_sessions and scan_records; revision 0002_community adds community_reports and the users.is_admin flag. No automatic migration of v0.4 anonymous browser history: the old storage key is removed on first launch to avoid assigning anonymous records to the wrong user.

### Use accounts and dashboard
1. Open the site, select Create an account, enter an email and a password of 12–128 characters. Email ownership is not verified yet.
2. Sign in to enable scan and extraction actions. The 30-minute access JWT is held in JavaScript memory only; refreshing the page requires signing in again. Server logout revokes the session; a failed network logout only clears the local session and the token may remain valid until expiration.
3. Save scan metadata (enabled by default, optional for each scan). Raw messages, URLs, screenshots, QR payloads and AI explanations are never deliberately persisted in history. Dashboard statistics aggregate saved scans for this account, not all users or overall scam prevalence.
4. Delete individual scans, clear all history or delete the account after confirming its password. Database foreign keys cascade-delete sessions, scans and submitted community reports. Backups/hosting logs are outside these deletion guarantees.

### Authentication and rate limits
Passwords use Argon2id; the server validates signed HS256 JWT issuer, audience, subject, session ID and expiry against a revocable database session. Use a random secret, HTTPS in production, and no permissive CORS. API calls use `Authorization: Bearer <access_token>` (Swagger: Authorize, paste the token). No refresh tokens or email verification/password reset are implemented. In-memory rate limits per 60 seconds: registration 5/IP, login 20/IP and 5/email, scan 20/account, image extraction 6/account, account deletion attempts 5/account. Provider budgets from Phase 3 remain in place. Limits are single-process and reset on restart; configure a shared distributed limiter and trusted reverse proxy before scaling. Registration rate limits are not bot protection. Email is a login identifier, not a verified identity. Avoid exposing the service publicly without additional abuse prevention.

| API | Method | Auth |
|---|---|---|
| /api/auth/register | POST | No; email/password JSON |
| /api/auth/login | POST | No; email/password JSON |
| /api/auth/me | GET | Bearer |
| /api/auth/logout | POST | Bearer |
| /api/auth/account | DELETE | Bearer + email/password JSON |
| /api/history | GET | Bearer; limit (1–100), offset |
| /api/history | DELETE | Bearer |
| /api/history/{id} | DELETE | Bearer; owner only |
| /api/dashboard | GET | Bearer |
| /api/scan | POST | Bearer; optional save_history boolean |
| /api/image/extract | POST | Bearer; raw image bytes |

Public health, model and configuration/capabilities endpoints expose no account information. API responses are marked no-store. The project is an educational prototype, not a production security service.

## Phase 4: screenshot and QR scanning

### Install Tesseract (optional for text OCR, not required for QR decoding)

- Windows: follow the upstream installation guide at https://tesseract-ocr.github.io/tessdoc/Installation.html and the linked UB Mannheim Windows installer. Install English language data. Add the installation folder to PATH, reopen VS Code, and run `tesseract --version` and `tesseract --list-langs` (look for `eng`). If the executable is not on PATH, copy `.env.example` to `.env` if needed and set `TESSERACT_CMD=C:/Program Files/Tesseract-OCR/tesseract.exe` (adjust to your actual path). Restart the server.
- Ubuntu/Debian: `sudo apt install tesseract-ocr tesseract-ocr-eng`.
- macOS: `brew install tesseract`.
- The Python dependencies install Pillow and headless OpenCV; they do not install the Tesseract executable. If Tesseract is missing, fails, or times out, QR recognition and manual text entry remain available.

### Use the scanner
1. Start the server as above and sign in. Select **Screenshot** in Threat scanner.
2. Choose a PNG, JPEG or WebP (maximum 8 MiB, 12 megapixels, 6000 pixels per side; static images only). The browser displays a temporary local preview.
3. Click **Extract text & QR**. OCR and QR decoding run on the FastAPI server. The image is never sent to Gemini or VirusTotal.
4. Review and correct the editable combined content. Decoded QR payloads appear as plain text, not clickable links. Remove personal details, credentials and private links. Do not open links or approve payments.
5. Optionally enable cloud checks after reviewing the content; both are unchecked when entering or extracting in screenshot mode. Click **Scan for threats**. The existing NLP model, rules and optional URL reputation engine analyze the reviewed text, not pixels. UPI payment or mandate URIs add a contextual warning, not proof of fraud. The first eligible HTTP(S) URL is the only URL checked with VirusTotal, and all recognized HTTP(S) URLs (up to 20) receive local inspection.
6. Clear image & text to remove the preview, extracted content and displayed result. History retains only scan mode, score, level and time; clear history separately. No raw scan content is deliberately persisted on the server or in local storage.

Try `samples/demo-screenshot.png` (synthetic banking scam text and a harmless example.com QR code). It does not contain real personal information. A high detected risk is expected from the banking message, not the QR destination.

### Image API
- `GET /api/image/capabilities`: reports executable availability (not a guarantee that English trained data works), formats and limits.
- `POST /api/image/extract`: send raw image bytes with Content-Type `image/png`, `image/jpeg` or `image/webp` (not multipart). Returns OCR text, QR payloads and recognition status, dimensions and truncation flags. Successful responses use `Cache-Control: no-store`.
- `POST /api/scan`: existing JSON contract now accepts `mode: screenshot`; pass reviewed text (including relevant QR payloads) up to 12,000 characters. Example: `{"text":"QR payload: https://example.com/", "mode":"screenshot", "use_gemini":false, "use_reputation":false}`.

### Privacy and safety details
Uploads are streamed with an 8 MiB limit, a 20-second upload timeout, and two concurrent image extraction slots per server process. Pillow validates actual format and dimensions and rejects animated images; metadata is discarded from the normalized image used for recognition. Tesseract receives normalized PNG bytes over stdin and returns text over stdout, with a 15-second subprocess timeout; no application-created temporary image files. OpenCV decodes up to five distinct QR payloads, each at most 3,000 characters. OCR output is capped at 8,000 characters. The combined review field is capped at 12,000 characters; truncation is indicated. Nothing is opened, fetched, executed or paid based on a decoded payload. This is not forensic deletion: server memory, operating system, reverse proxies and hosting logs may retain information. For privacy-sensitive use run locally and avoid cloud checks. Deploying publicly requires stronger per-client quotas, TLS, a hardened image-processing worker and resource/time isolation (OpenCV has no hard subprocess deadline here). No image bytes are shared with the cloud integrations; explicitly selected cloud services receive reviewed text or eligible URLs subject to existing Phase 3 filtering.

OCR is English-only and can miss small, blurred, rotated, handwritten, stylized or non-English text; QR decoding can miss damaged, tiny or complex codes. Non-QR barcodes and visual-only scam detection are not supported. Empty recognition is not evidence of safety. No image classification model is included.

## Model and evaluation
The bundled model trains once per server process on 100 authored synthetic examples (50 spam-like, 50 legitimate-like). Word unigram/bigram and character 3–5-gram TF-IDF features feed a logistic regression classifier. A separate 24-message authored synthetic smoke test yielded 22 correct: accuracy 91.67%, precision 85.71%, recall 100%, F1 92.31%; confusion matrix (ham, spam) [[10,2],[0,12]]. These are not real-world fraud-detection metrics. Both sets were authored in this development session and may share writing style and themes. No public dataset was downloaded in the development environment.

To reproduce the report or see actual metrics after changing data:

```cmd
python -m backend.ml
python -m pytest -q
```

## Upgrade training with a public dataset
1. Visit https://archive.ics.uci.edu/dataset/228/sms+spam+collection and download SMS Spam Collection.
2. Extract the dataset file named `SMSSpamCollection` into the project `data` folder (not the archive; no extension).
3. If the dataset is not UTF-8, convert it to UTF-8 before training.
4. Stop the running server, then run `python -m backend.ml` to evaluate and restart uvicorn. The app automatically trains using the local dataset when present. No external request is made by the server.

The external dataset is deduplicated by case/whitespace-normalized text, stratified into an 80/20 train/holdout split (seed 42), and augmented with synthetic starter examples on the training side only. Near duplicates can remain. The external dataset is historical SMS spam, not a representative modern fraud corpus. The training script does not claim fraud-specific performance. Source: Almeida, T. & Hidalgo, J. (2012), SMS Spam Collection, UCI Machine Learning Repository, https://doi.org/10.24432/C5CC84, CC BY 4.0. Public data is not bundled here.

## Enable cloud integrations (optional)

1. Create a Gemini API key at https://aistudio.google.com/apikey and a VirusTotal API key from your account at https://www.virustotal.com/gui/my-apikey. You can enable either provider independently. Check provider pricing, data handling, and usage terms first.
2. In the project root (next to requirements.txt), copy `.env.example` to `.env`:

```cmd
copy .env.example .env
```

On macOS/Linux: `cp .env.example .env`.

3. Edit `.env` with your real keys, leaving unused keys empty:

```dotenv
GEMINI_API_KEY=YOUR_GEMINI_KEY
GEMINI_MODEL=gemini-3.5-flash
VIRUSTOTAL_API_KEY=YOUR_VIRUSTOTAL_KEY
```

The default model is configurable; if it is unavailable to your account, use a supported text-generation model listed in your Google AI Studio account. Real keys never belong in frontend code, screenshots, chat, or GitHub. `.env` is ignored by Git; only the example is bundled. Existing environment variables take precedence over `.env`. Restart the server after editing. On the website, enable the relevant checkboxes before scanning; they are off by default. `GET /api/integrations` only reports whether keys are present, not whether they are valid.

## API
- `GET /api/health`: local engine status.
- `GET /api/model`: training dataset, evaluation type, metrics, confusion matrix.
- `GET /api/integrations`: boolean configuration flags, never secrets.
- `POST /api/scan`: JSON `{"text":"Share your OTP immediately","mode":"banking","use_gemini":false,"use_reputation":false}`; modes message, job, banking, url, screenshot. Requires a Bearer token; `save_history` defaults to true. Both cloud flags default to false, maintaining offline scanning without provider keys.

Example: use `https://example.com/` in URL mode and opt into reputation. A report may or may not exist. For a message scan, use an invented message with no personal information and opt into Gemini. Results contain `reputation` (status, counts, last analysis timestamp when available) and `explanation` (source, status, summary). Provider failures retain local output and never expose provider error bodies.

### Risk calculation
Hybrid score = max(rule score, ML contribution, reputation risk floor). Rule score is the sum of matched warning weights capped at 100. ML contribution = max(0, round((spam_score - 50) * 1.6)); spam_score is uncalibrated. VirusTotal report with any malicious detection sets a floor of 80; suspicious-only sets 50. No report or zero detections never reduces the local score. These weights are arbitrary conservative heuristics, not validated thresholds. Low <30, medium 30–59, high >=60. Gemini explains possible warning signs only; it cannot change the score or fixed safety advice. URL-only mode skips text ML.

### Reputation coverage and privacy
The backend retrieves an existing VirusTotal report via GET `/api/v3/urls/{id}`, not a new scan. The first distinct extracted HTTP(S) link (or the URL-mode input) is eligible; other extracted links receive local inspection (up to 20). It never opens submitted URLs, follows redirects or asks VirusTotal to submit/rescan them. Query-bearing URLs, credential-bearing URLs, nonpublic IP literals and obvious local hostnames are excluded from reputation lookups; fragments are stripped. This filter does not resolve DNS or guarantee anonymity. Even a path may contain private information: never submit confidential links. Existing reports may be stale, absent, or wrong. A zero detection result is not proof of safety. An optional check is a real-time query of an existing report, not a real-time crawl.

Gemini receives a best-effort redacted sample (up to 3,000 characters) and local indicators; URL-only mode omits the URL itself. Redaction is not anonymization and cannot remove every personal detail. Treat AI outputs as unverified; no tools or model instructions are executed. Both providers receive data only if the corresponding request flag is true and a key is configured. The backend uses fixed HTTPS provider endpoints, key headers, disabled redirects, bounded per-operation timeouts, no retry, and a process-local budget (VirusTotal 4/min, Gemini 10/min). Provider quotas may be lower or include daily limits. The budget resets when a process restarts and is not shared between workers. A cloud scan may be slower than a local scan.

### Provider documentation
- Gemini: https://ai.google.dev/api/generate-content and https://ai.google.dev/gemini-api/docs/models
- VirusTotal: https://docs.virustotal.com/reference/url-info and https://docs.virustotal.com/reference/public-vs-premium-api
- VirusTotal public API is restricted to eligible noncommercial/academic use; its documented default quota is 4 requests/minute and 500/day. Review the license before any public or commercial deployment. Gemini usage may be billed depending on your account and model.

## Tests
`python -m pytest -q` runs all Phase 6 and earlier regression tests (99 passed in the packaged version, including 30 new tests), including legacy API and model tests, simulated provider responses, timeout, rate limit, unknown report, privacy filter, and missing-key fallback tests, plus real OCR, single/multiple QR recognition, format validation, upload limits, UPI warnings, and offline extraction. `node --check frontend/app.js` checks JavaScript syntax. No real provider keys are bundled, and actual authenticated provider calls have not been tested. Mock responses demonstrate integration behavior, not live provider results. Tests use a temporary migrated SQLite database; PostgreSQL migration DDL is checked offline, but a live PostgreSQL server was not available. JavaScript syntax validation passed. Community tests cover report authorization, domain validation, structured-only submissions, duplicate normalization, moderation and stale-review protection, public visibility, analytics, withdrawal, role grant/revoke, account deletion and upgrade/downgrade preservation. Chromium navigation to the local test server was blocked again by the environment (ERR_BLOCKED_BY_ADMINISTRATOR), so browser interaction and visual rendering remain unverified.

## Privacy and limitations
English-oriented experimental model; may miss novel scams, other languages or obfuscations, and flag legitimate security messages. Spam is not the same as fraud. Email verification, password recovery, distributed quotas and production hardening are not included yet. Never rely on a score alone. Never submit OTPs, passwords, account numbers, or private data. The database stores account email, password hash, session identifiers and optional per-account scan metadata (mode, score, level, timestamp). The app does not deliberately log or persist message bodies, but providers and hosting infrastructure may have their own logging policies. Clear history removes the signed-in user’s database scan records. This is a local educational prototype, not a production security service.

## Deployment
Not deployed. A single Render Python service can use `pip install -r requirements.txt` and `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`. Set secrets in the host environment rather than committing `.env`. Run migrations once against the target database and set a strong JWT_SECRET. Before public deployment add distributed rate limiting, quota/billing controls, HTTPS, monitoring, abuse prevention and data protection; verify provider terms. Do not expose this prototype publicly with personal API keys without validating quotas, terms and abuse controls.
