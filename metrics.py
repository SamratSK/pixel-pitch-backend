from __future__ import annotations

import threading
from collections import deque
from typing import Deque, Dict, Optional


class StatsTracker:
    """Lightweight in-memory tracker for scan outcomes and durations."""

    def __init__(self, max_samples: int = 30) -> None:
        self.max_samples = max_samples
        self._lock = threading.Lock()
        self._total_scans = 0
        self._flagged_scans = 0
        self._malicious_scans = 0
        self._durations: Deque[float] = deque(maxlen=max_samples)

    def record(self, flagged: bool, duration_seconds: Optional[float], malicious: Optional[bool] = None) -> None:
        with self._lock:
            self._total_scans += 1
            if flagged:
                self._flagged_scans += 1
            if malicious is None:
                malicious = flagged
            if malicious:
                self._malicious_scans += 1
            if duration_seconds is not None:
                self._durations.append(duration_seconds)

    def snapshot(self) -> Dict:
        with self._lock:
            avg = sum(self._durations) / len(self._durations) if self._durations else None
            return {
                "total_scans": self._total_scans,
                "flagged_scans": self._flagged_scans,
                "malicious_scans": self._malicious_scans,
                "avg_duration_seconds_last_30": avg,
                "sample_size": len(self._durations),
            }


def infer_flagged(result: Optional[Dict]) -> bool:
    """Derive a flagged/malicious signal from stored scan results."""
    if not result:
        return False

    heuristic = result.get("heuristic") or {}
    verdict = heuristic.get("verdict")
    score = heuristic.get("score", 0)
    if verdict and verdict != "unknown":
        return True
    if isinstance(score, (int, float)) and score >= 0.5:  # conservative threshold
        return True

    external = result.get("external") or {}
    vt_report = external.get("vt_report") or {}
    stats = (
        vt_report.get("data", {})
        .get("attributes", {})
        .get("stats", {})
        if isinstance(vt_report, dict)
        else {}
    )
    if stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0:
        return True

    return False


stats = StatsTracker(max_samples=30)
