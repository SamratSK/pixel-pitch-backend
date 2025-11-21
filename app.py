import uuid
from pathlib import Path
from typing import Optional

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

# Support running as a package (backend.app) or standalone from this folder
try:  # package-relative imports when launched with `uvicorn backend.app:app`
    from .config import MAX_UPLOAD_BYTES, UPLOAD_DIR
    from .storage import ScanRecord, ScanStatus, store
    from .tasks import enqueue_scan
except ImportError:  # direct imports when launched with `uvicorn app:app`
    from config import MAX_UPLOAD_BYTES, UPLOAD_DIR
    from storage import ScanRecord, ScanStatus, store
    from tasks import enqueue_scan

app = FastAPI(title="Android Malware Scanner", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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


@app.post("/scan")
async def create_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    source: Optional[str] = Form(None),
):

    if file.filename and not file.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="Only .apk files are accepted")
    
    scan_id = uuid.uuid4().hex
    destination = UPLOAD_DIR / f"{scan_id}.apk"
    _save_upload(file, destination)

    record = ScanRecord(id=scan_id, filename=file.filename, source=source)
    store.create(record)

    background_tasks.add_task(enqueue_scan, scan_id, destination, source)

    return {"scan_id": scan_id, "status": record.status}


@app.get("/scan/{scan_id}")
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
