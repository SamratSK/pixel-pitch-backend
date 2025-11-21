import threading
from pathlib import Path
from typing import Dict, Optional

# Support running as a package (backend.tasks) or standalone from this folder
try:
    from .analyzers import dynamic_summarize, network_analyze, static_analyze
    from .integrations import hybrid_analysis, virustotal
    from .job_queue import Worker
    from .storage import ScanStatus, store
    from . import metrics
except ImportError:
    from analyzers import dynamic_summarize, network_analyze, static_analyze
    from integrations import hybrid_analysis, virustotal
    from job_queue import Worker
    from storage import ScanStatus, store
    import metrics


def _score(static_result: Dict, network_result: Dict) -> Dict:
    score = 0.1  # base uncertainty score
    reasons = []

    if static_result.get("suspicious_strings"):
        score += 0.3
        reasons.append("suspicious tooling/anti-analysis strings present")

    if static_result.get("has_native_code"):
        score += 0.1
        reasons.append("contains native libraries (.so)")

    if network_result.get("domains"):
        score += 0.1
        reasons.append("embedded network endpoints found")

    score = min(score, 0.95)
    verdict = "malicious_suspect" if score >= 0.5 else "unknown"

    return {"score": round(score, 3), "verdict": verdict, "reasons": reasons}


def _external_analysis(apk_path: Path) -> Dict:
    """Optionally submit to VirusTotal / Hybrid Analysis if API keys are configured."""
    report: Dict[str, Optional[Dict]] = {
        "vt_submission_id": None,
        "vt_report": None,
        "ha_submission_id": None,
        "ha_report": None,
    }

    if virustotal.client.enabled():
        try:
            vt_id = virustotal.client.submit_file(apk_path)
            report["vt_submission_id"] = vt_id
            if vt_id:
                report["vt_report"] = virustotal.client.fetch_report(vt_id)
        except Exception as exc:  # pragma: no cover
            report["vt_report"] = {"error": str(exc)}

    if hybrid_analysis.client.enabled():
        try:
            ha_id = hybrid_analysis.client.submit_file(apk_path)
            report["ha_submission_id"] = ha_id
            if ha_id:
                report["ha_report"] = hybrid_analysis.client.fetch_report(ha_id)
        except Exception as exc:  # pragma: no cover
            report["ha_report"] = {"error": str(exc)}

    return report


def _record_metrics(scan_id: str, result: Optional[Dict], status: ScanStatus) -> None:
    record = store.get(scan_id)
    duration = None
    if record and record.updated_at and record.created_at:
        duration = record.updated_at - record.created_at
    flagged = metrics.infer_flagged(result if status == ScanStatus.finished else None)
    metrics.stats.record(flagged=flagged, duration_seconds=duration)


def _run_scan(scan_id: str, apk_path: Path, source: Optional[str]) -> None:
    apk_path = Path(apk_path)
    store.update_status(scan_id, ScanStatus.running)

    try:
        static_result = static_analyze(apk_path)
        network_result = network_analyze(apk_path)
        dynamic_plan = dynamic_summarize(apk_path)
        external = _external_analysis(apk_path)
        heuristic = _score(static_result, network_result)

        result = {
            "source": source,
            "static": static_result,
            "network": network_result,
            "dynamic": dynamic_plan,
            "external": external,
            "heuristic": heuristic,
        }
        store.set_result(scan_id, result)
        _record_metrics(scan_id, result, ScanStatus.finished)
    except Exception as exc:  # pragma: no cover
        store.set_error(scan_id, str(exc))
        _record_metrics(scan_id, None, ScanStatus.failed)


queue_worker = Worker(_run_scan)
queue_worker.start()


def enqueue_scan(scan_id: str, apk_path: Path, source: Optional[str]) -> None:
    # If Redis queue is available, push to worker; else fallback to local thread
    if queue_worker.redis_queue.available():
        queue_worker.enqueue({"scan_id": scan_id, "apk_path": str(apk_path), "source": source})
    else:
        worker = threading.Thread(target=_run_scan, args=(scan_id, apk_path, source), daemon=True)
        worker.start()
