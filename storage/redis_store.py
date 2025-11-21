from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Optional

import redis

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")


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
    created_at: float = 0.0
    updated_at: float = 0.0
    result: Optional[dict] = None
    error: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @staticmethod
    def from_json(payload: str) -> "ScanRecord":
        data = json.loads(payload)
        data["status"] = ScanStatus(data["status"])
        return ScanRecord(**data)


class ScanStore:
    def __init__(self, url: str = REDIS_URL) -> None:
        self.client = redis.Redis.from_url(url, decode_responses=True)

    def create(self, record: ScanRecord) -> ScanRecord:
        now = time.time()
        record.created_at = now
        record.updated_at = now
        self.client.set(record.id, record.to_json())
        return record

    def get(self, scan_id: str) -> Optional[ScanRecord]:
        payload = self.client.get(scan_id)
        if not payload:
            return None
        return ScanRecord.from_json(payload)

    def update_status(self, scan_id: str, status: ScanStatus) -> None:
        record = self.get(scan_id)
        if record:
            record.status = status
            record.updated_at = time.time()
            self.client.set(scan_id, record.to_json())

    def set_result(self, scan_id: str, result: dict) -> None:
        record = self.get(scan_id)
        if record:
            record.status = ScanStatus.finished
            record.result = result
            record.updated_at = time.time()
            self.client.set(scan_id, record.to_json())

    def set_error(self, scan_id: str, error: str) -> None:
        record = self.get(scan_id)
        if record:
            record.status = ScanStatus.failed
            record.error = error
            record.updated_at = time.time()
            self.client.set(scan_id, record.to_json())

    def update_external(self, scan_id: str, provider: str, payload: dict) -> None:
        record = self.get(scan_id)
        if record:
            record.result = record.result or {}
            external = record.result.get("external", {}) if isinstance(record.result, dict) else {}
            external[provider] = payload
            record.result["external"] = external
            record.updated_at = time.time()
            self.client.set(scan_id, record.to_json())
