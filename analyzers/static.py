import hashlib
import mimetypes
import re
import zipfile
from pathlib import Path
from typing import Dict, List

from .manifest import analyze as manifest_analyze
from .yara_scan import scan as yara_scan


SUSPICIOUS_STRINGS = [
    "frida",
    "magisk",
    "xposed",
    "qemu",
    "genymotion",
    "emulator",
    "root",
    "su",
    "busybox",
]


def _checksum(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _collect_strings(path: Path, limit_bytes: int = 2_000_000) -> List[str]:
    # Read a capped amount to avoid memory spikes on large APKs
    data = path.read_bytes()[:limit_bytes]
    ascii_strings = re.findall(rb"[ -~]{6,}", data)
    return [s.decode("utf-8", errors="ignore") for s in ascii_strings]


def analyze(apk_path: Path) -> Dict:
    apk_path = Path(apk_path)
    checksum = _checksum(apk_path)
    size_bytes = apk_path.stat().st_size

    file_count = 0
    has_native_code = False
    package_entries: List[str] = []
    mime_guess, _ = mimetypes.guess_type(apk_path.name)
    magic = None

    try:
        with zipfile.ZipFile(apk_path) as zf:
            infos = zf.infolist()
            file_count = len(infos)
            package_entries = [i.filename for i in infos]
            has_native_code = any(name.endswith(".so") for name in package_entries)
            magic = "zip"
    except zipfile.BadZipFile:
        # If parsing fails, fall back to minimal metadata
        file_count = 0
        package_entries = []
        has_native_code = False

    corpus_strings = _collect_strings(apk_path)
    suspicious_hits = sorted({s for s in corpus_strings if any(sig in s.lower() for sig in SUSPICIOUS_STRINGS)})
    url_hits = sorted(set(re.findall(r"https?://[\w\.-/:#?=&%]+", "\n".join(corpus_strings))))
    manifest = manifest_analyze(apk_path) if magic == "zip" or apk_path.suffix.lower() == ".apk" else {"parsed": False}
    yara_result = yara_scan(apk_path)

    return {
        "sha256": checksum,
        "size_bytes": size_bytes,
        "file_count": file_count,
        "has_native_code": has_native_code,
        "mime_guess": mime_guess,
        "file_magic": magic,
        "suspicious_strings": suspicious_hits[:50],  # cap to keep responses tidy
        "url_candidates": url_hits[:50],
        "package_entries_sample": package_entries[:50],
        "manifest": manifest,
        "yara": yara_result,
    }
