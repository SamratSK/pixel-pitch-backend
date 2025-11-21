from __future__ import annotations

import zipfile
from typing import Dict, List, Optional

try:
    from androguard.core.bytecodes.axml import AXMLPrinter  # type: ignore
except Exception:  # pragma: no cover
    AXMLPrinter = None

try:
    import xml.etree.ElementTree as ET
except Exception:  # pragma: no cover
    ET = None


def _parse_manifest_xml(raw_bytes: bytes) -> Optional[Dict]:
    if AXMLPrinter is None or ET is None:
        return None
    try:
        axml = AXMLPrinter(raw_bytes)
        xml_str = axml.get_xml().decode("utf-8", errors="ignore")
        root = ET.fromstring(xml_str)

        ns = "{http://schemas.android.com/apk/res/android}"
        manifest_info: Dict = {
            "package": root.attrib.get("package"),
            "version_name": root.attrib.get(f"{ns}versionName"),
            "version_code": root.attrib.get(f"{ns}versionCode"),
            "permissions": [],
            "activities": [],
        }

        for child in root:
            if child.tag.endswith("permission"):
                name = child.attrib.get(f"{ns}name")
                if name:
                    manifest_info.setdefault("permissions", []).append(name)
            if child.tag.endswith("application"):
                for comp in child:
                    if comp.tag.endswith("activity"):
                        name = comp.attrib.get(f"{ns}name")
                        if name:
                            manifest_info.setdefault("activities", []).append(name)
        return manifest_info
    except Exception:
        return None


def analyze(apk_path) -> Dict:
    manifest: Dict = {"parsed": False}
    try:
        with zipfile.ZipFile(apk_path) as zf:
            with zf.open("AndroidManifest.xml") as fh:
                raw = fh.read()
                parsed = _parse_manifest_xml(raw)
                if parsed:
                    parsed["parsed"] = True
                    manifest = parsed
    except Exception:
        manifest = {"parsed": False}
    return manifest
