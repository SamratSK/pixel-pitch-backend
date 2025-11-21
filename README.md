# Android Malware Scanner Backend (Python/FastAPI)

Lightweight API to accept APK uploads, run stub static/network analysis, and return heuristic results. Dynamic sandboxing is provided as guidance in responses; plug your own sandbox runner where indicated.

## Quick start

```bash
pip install -r backend/requirements.txt
uvicorn backend.app:app --reload --port 8000
```

### Optional env vars

- `VT_API_KEY` (+ `VT_URL`): enable VirusTotal submission/report.
- `HA_API_KEY` (+ `HA_URL`): enable Hybrid Analysis submission/report.
- `STORE_BACKEND=redis` + `REDIS_URL`: persist scans in Redis instead of memory.
- `REDIS_QUEUE_NAME`: queue key when Redis is used (default `apk_scan_jobs`).
- `YARA_RULES_DIR`: directory or single file to load YARA rules from (optional).
- `API_KEY`: when set, all protected endpoints require header `x-api-key: <API_KEY>`.
- `RATE_LIMIT_MAX`, `RATE_LIMIT_WINDOW`: simple in-memory rate limiter per client key (defaults 60 req / 60s).

## API

- `POST /scan` (multipart): field `file` = APK, optional `source` string. Returns `scan_id`.
- `GET /scan/{scan_id}`: status + results when finished.
- `GET /health`: simple heartbeat.

## What it does now

- Saves APK to `backend/uploads/` (100 MB limit).
- Runs static heuristics (hash, size, embedded strings, urls, native libs), manifest/permission extraction (via androguard), mime/file hints, optional YARA scan when rules provided.
- Scrapes network endpoints from strings.
- Provides dynamic run playbook to catch evasive behavior.
- Optionally submits to VirusTotal and/or Hybrid Analysis when API keys are set; returns submission IDs and any immediate report content.
- Produces lightweight heuristic score + reasons.
- Serves a simple test UI at `/ui` for upload + polling.
- Supports auth/rate limiting and a Hybrid Analysis webhook endpoint at `/webhook/hybrid-analysis/{scan_id}` (secured by API key).

## Extend it

- Swap `tasks._run_scan` to call a real sandbox (e.g., Hatching, Joe Sandbox, internal emulator farm).
- Replace string scraping with proper static parsers (androguard/objection/apkid). 
- Add persistence (Postgres/Redis) to replace the in-memory store. (Redis queue + store now supported via env; DB still open.)
- Gate uploads with auth and rate limiting before deploying externally.
