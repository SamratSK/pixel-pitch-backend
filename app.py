import uuid
from pathlib import Path
from typing import Optional

from fastapi import BackgroundTasks, Depends, FastAPI, File, Form, HTTPException, UploadFile, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Support running as a package (backend.app) or standalone from this folder
try:  # package-relative imports when launched with `uvicorn backend.app:app`
    from .config import MAX_UPLOAD_BYTES, UPLOAD_DIR
    from . import metrics
    from .auth_store import auth_store
    from .storage import ScanRecord, ScanStatus, store
    from .tasks import enqueue_scan
    from .security import rate_limit_dependency, require_api_key
except ImportError:  # direct imports when launched with `uvicorn app:app`
    from config import MAX_UPLOAD_BYTES, UPLOAD_DIR
    import metrics
    from auth_store import auth_store
    from storage import ScanRecord, ScanStatus, store
    from tasks import enqueue_scan
    from security import rate_limit_dependency, require_api_key

app = FastAPI(title="Android Malware Scanner", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve lightweight UI at /ui if static assets exist
STATIC_DIR = Path(__file__).resolve().parent / "static"
if STATIC_DIR.exists():
    app.mount("/ui", StaticFiles(directory=STATIC_DIR, html=True), name="ui")


def _save_upload(file: UploadFile, destination: Path) -> int:
    bytes_written = 0
    with destination.open("wb") as output:
        while True:
            chunk = file.file.read(1024 * 1024)
            if not chunk:
                break
            bytes_written += len(chunk)
            if bytes_written > MAX_UPLOAD_BYTES:
                destination.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail="APK too large")
            output.write(chunk)
    return bytes_written


@app.post("/scan", dependencies=[Depends(rate_limit_dependency)])
async def create_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    source: Optional[str] = Form(None),
):
    
    scan_id = uuid.uuid4().hex
    suffix = Path(file.filename).suffix if file.filename else ""
    destination = UPLOAD_DIR / f"{scan_id}{suffix or '.bin'}"
    _save_upload(file, destination)

    record = ScanRecord(id=scan_id, filename=file.filename, source=source)
    store.create(record)

    background_tasks.add_task(enqueue_scan, scan_id, destination, source)

    return {"scan_id": scan_id, "status": record.status}


@app.get("/scan/{scan_id}", dependencies=[Depends(rate_limit_dependency)])
async def get_scan(scan_id: str):
    record = store.get(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")

    payload = {
        "scan_id": record.id,
        "filename": record.filename,
        "source": record.source,
        "status": record.status,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "result": record.result,
        "error": record.error,
    }
    return payload


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/")
async def root():
    return {"service": app.title, "version": app.version}


@app.get("/stats")
async def stats():
    """Lightweight stats for dashboards."""
    return metrics.stats.snapshot()


class Credentials(BaseModel):
    username: str
    password: str


@app.post("/auth/register")
async def register(creds: Credentials):
    try:
        auth_store.register(creds.username, creds.password)
        return {"status": "registered"}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/auth/login")
async def login(creds: Credentials):
    if not auth_store.authenticate(creds.username, creds.password):
        raise HTTPException(status_code=401, detail="invalid credentials")
    token, expires_at = auth_store.issue_token(creds.username)
    return {"token": token, "expires_at": expires_at}


@app.post("/webhook/hybrid-analysis/{scan_id}")
async def hybrid_analysis_webhook(scan_id: str, payload: dict, request: Request):
    """Allow Hybrid Analysis callbacks to attach reports to an existing scan."""
    record = store.get(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    store.update_external(scan_id, "ha_webhook", payload)
    return {"status": "accepted"}
