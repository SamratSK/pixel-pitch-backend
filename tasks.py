import threading
from pathlib import Path
from typing import Dict, Optional

# Support running as a package (backend.tasks) or standalone from this folder
try:
    from .analyzers import dynamic_summarize, network_analyze, static_analyze
    from .integrations import hybrid_analysis, virustotal
    from .storage import ScanStatus, store
except ImportError:
    from analyzers import dynamic_summarize, network_analyze, static_analyze
    from integrations import hybrid_analysis, virustotal
    from storage import ScanStatus, store


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


def _run_scan(scan_id: str, apk_path: Path, source: Optional[str]) -> None:
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
    except Exception as exc:  # pragma: no cover
        store.set_error(scan_id, str(exc))


def enqueue_scan(scan_id: str, apk_path: Path, source: Optional[str]) -> None:
    worker = threading.Thread(target=_run_scan, args=(scan_id, apk_path, source), daemon=True)
    worker.start()
