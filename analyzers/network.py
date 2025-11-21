import re
from pathlib import Path
from typing import Dict, List, Set
from urllib.parse import urlparse


def _collect_strings(path: Path, limit_bytes: int = 2_000_000) -> List[str]:
    data = path.read_bytes()[:limit_bytes]
    ascii_strings = re.findall(rb"[ -~]{6,}", data)
    return [s.decode("utf-8", errors="ignore") for s in ascii_strings]


def analyze(apk_path: Path) -> Dict:
    apk_path = Path(apk_path)
    corpus_strings = _collect_strings(apk_path)

    urls = sorted(set(re.findall(r"https?://[\w\.-/:#?=&%]+", "\n".join(corpus_strings))))
    domains: Set[str] = set()
    for url in urls:
        parsed = urlparse(url)
        if parsed.hostname:
            domains.add(parsed.hostname)

    return {
        "urls": urls[:100],
        "domains": sorted(domains)[:100],
        "notes": "Static string scrape only; run dynamic sandbox to confirm network IOCs.",
    }
