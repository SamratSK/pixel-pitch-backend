"""Hatching Triage API helper (minimal).

Set ENV `TRIAGE_API_KEY` and optionally `TRIAGE_URL`.
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional

import httpx

TRIAGE_URL = os.getenv("TRIAGE_URL", "https://tria.ge/api")
TRIAGE_API_KEY = os.getenv("TRIAGE_API_KEY")


class TriageClient:
    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None) -> None:
        self.api_key = api_key or TRIAGE_API_KEY
        self.base_url = base_url or TRIAGE_URL

    def enabled(self) -> bool:
        return bool(self.api_key)

    def _headers(self) -> Dict[str, str]:
        if not self.api_key:
            raise RuntimeError("Triage API key is not configured")
        return {"Authorization": f"Bearer {self.api_key}"}

    def submit_file(self, apk_path: Path) -> Optional[str]:
        if not self.enabled():
            return None
        with httpx.Client(timeout=30.0) as client, apk_path.open("rb") as f:
            resp = client.post(
                f"{self.base_url}/v0/samples",
                headers=self._headers(),
                files={"file": (apk_path.name, f, "application/vnd.android.package-archive")},
                data={"kind": "apk"},
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("id")

    def fetch_report(self, sample_id: str) -> Optional[Dict[str, Any]]:
        if not self.enabled():
            return None
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(f"{self.base_url}/v0/samples/{sample_id}", headers=self._headers())
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.json()


client = TriageClient()
