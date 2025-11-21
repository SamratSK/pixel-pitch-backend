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

## API

- `POST /scan` (multipart): field `file` = APK, optional `source` string. Returns `scan_id`.
- `GET /scan/{scan_id}`: status + results when finished.
- `GET /health`: simple heartbeat.

## What it does now

- Saves APK to `backend/uploads/` (100 MB limit).
- Runs static heuristics (hash, size, embedded strings, urls, native libs).
- Scrapes network endpoints from strings.
- Provides dynamic run playbook to catch evasive behavior.
- Optionally submits to VirusTotal and/or Hatching Triage when API keys are set; returns submission IDs and any immediate report content.
- Produces lightweight heuristic score + reasons.

## Extend it

- Swap `tasks._run_scan` to call a real sandbox (e.g., Hatching, Joe Sandbox, internal emulator farm).
- Replace string scraping with proper static parsers (androguard/objection/apkid). 
- Add persistence (Postgres/Redis) to replace the in-memory store.
- Gate uploads with auth and rate limiting before deploying externally.
