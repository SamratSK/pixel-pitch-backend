"""Hybrid Analysis (Falcon Sandbox) API helper.

Set ENV `HA_API_KEY` and optionally `HA_URL`.
Community tier allows limited submissions.
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional

import httpx

HA_URL = os.getenv("HA_URL", "https://www.hybrid-analysis.com/api/v2")
HA_API_KEY = os.getenv("HA_API_KEY")


class HybridAnalysisClient:
    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None) -> None:
        self.api_key = api_key or HA_API_KEY
        self.base_url = base_url or HA_URL

    def enabled(self) -> bool:
        return bool(self.api_key)

    def _headers(self) -> Dict[str, str]:
        if not self.api_key:
            raise RuntimeError("HA API key is not configured")
        return {
            "api-key": self.api_key,
            "User-Agent": "Falcon Sandbox",
            "accept": "application/json",
        }

    def submit_file(self, apk_path: Path) -> Optional[str]:
        if not self.enabled():
            return None
        with httpx.Client(timeout=60.0) as client, apk_path.open("rb") as f:
            resp = client.post(
                f"{self.base_url}/submit/file",
                headers=self._headers(),
                files={"file": (apk_path.name, f, "application/vnd.android.package-archive")},
                data={"environment_id": "300"},  # 300 is Android in HA
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("job_id") or data.get("submission_id") or data.get("id")

    def fetch_report(self, job_id: str) -> Optional[Dict[str, Any]]:
        if not self.enabled():
            return None
        with httpx.Client(timeout=20.0) as client:
            resp = client.get(f"{self.base_url}/report/{job_id}/summary", headers=self._headers())
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.json()


client = HybridAnalysisClient()
