from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Optional

try:
    import yara  # type: ignore
except Exception:  # pragma: no cover
    yara = None


RULES_ENV = os.getenv("YARA_RULES_DIR")
_cached_rules: Optional["yara.Rules"] = None


def _load_rules() -> Optional["yara.Rules"]:
    global _cached_rules
    if _cached_rules is not None:
        return _cached_rules
    if yara is None or not RULES_ENV:
        return None
    rules_path = Path(RULES_ENV)
    if not rules_path.exists():
        return None
    try:
        if rules_path.is_file():
            _cached_rules = yara.load(filepath=str(rules_path))
        else:
            _cached_rules = yara.compile(filepaths={p.name: str(p) for p in rules_path.glob("*.yar*")})
        return _cached_rules
    except Exception:
        return None


def scan(apk_path: Path) -> Dict:
    rules = _load_rules()
    if not rules:
        return {"enabled": False, "matches": []}
    try:
        matches = rules.match(str(apk_path))
        return {
            "enabled": True,
            "match_names": [m.rule for m in matches][:50],
        }
    except Exception as exc:  # pragma: no cover
        return {"enabled": True, "error": str(exc), "matches": []}
