"""Minimal VirusTotal v3 client for APK submissions and reports.

Set ENV `VT_API_KEY` (required) and optionally `VT_URL`.
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional

import httpx

VT_URL = os.getenv("VT_URL", "https://www.virustotal.com/api/v3")
VT_API_KEY = os.getenv("VT_API_KEY")


class VTClient:
    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None) -> None:
        self.api_key = api_key or VT_API_KEY
        self.base_url = base_url or VT_URL

    def enabled(self) -> bool:
        return bool(self.api_key)

    def _headers(self) -> Dict[str, str]:
        if not self.api_key:
            raise RuntimeError("VT API key is not configured")
        return {"x-apikey": self.api_key}

    def submit_file(self, apk_path: Path) -> Optional[str]:
        """Submit a file; returns analysis id if accepted."""
        if not self.enabled():
            return None
        with httpx.Client(timeout=30.0) as client, apk_path.open("rb") as f:
            resp = client.post(
                f"{self.base_url}/files",
                headers=self._headers(),
                files={"file": (apk_path.name, f, "application/vnd.android.package-archive")},
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("data", {}).get("id")

    def fetch_report(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        if not self.enabled():
            return None
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(f"{self.base_url}/analyses/{analysis_id}", headers=self._headers())
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.json()


client = VTClient()
