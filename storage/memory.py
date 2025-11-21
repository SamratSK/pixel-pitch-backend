from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional


class ScanStatus(str, Enum):
    pending = "pending"
    running = "running"
    finished = "finished"
    failed = "failed"


@dataclass
class ScanRecord:
    id: str
    filename: str
    source: Optional[str]
    status: ScanStatus = ScanStatus.pending
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    result: Optional[dict] = None
    error: Optional[str] = None


class ScanStore:
    def __init__(self) -> None:
        self._records: Dict[str, ScanRecord] = {}
        self._lock = threading.Lock()

    def create(self, record: ScanRecord) -> ScanRecord:
        with self._lock:
            self._records[record.id] = record
            return record

    def get(self, scan_id: str) -> Optional[ScanRecord]:
        with self._lock:
            return self._records.get(scan_id)

    def update_status(self, scan_id: str, status: ScanStatus) -> None:
        with self._lock:
            record = self._records.get(scan_id)
            if record:
                record.status = status
                record.updated_at = time.time()

    def set_result(self, scan_id: str, result: dict) -> None:
        with self._lock:
            record = self._records.get(scan_id)
            if record:
                record.status = ScanStatus.finished
                record.result = result
                record.updated_at = time.time()

    def set_error(self, scan_id: str, error: str) -> None:
        with self._lock:
            record = self._records.get(scan_id)
            if record:
                record.status = ScanStatus.failed
                record.error = error
                record.updated_at = time.time()

    def update_external(self, scan_id: str, provider: str, payload: dict) -> None:
        with self._lock:
            record = self._records.get(scan_id)
            if not record:
                return
            record.result = record.result or {}
            external = record.result.get("external", {}) if isinstance(record.result, dict) else {}
            external[provider] = payload
            record.result["external"] = external
            record.updated_at = time.time()


store = ScanStore()
