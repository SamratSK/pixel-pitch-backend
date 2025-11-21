from pathlib import Path
from typing import Dict, List


def playbook(apk_path: Path) -> List[str]:
    # Provide actionable steps for a dynamic run; keeps backend stateless
    return [
        "Run on both emulator and rooted physical device",
        "Hook telemetry: file I/O, sockets, DexClassLoader, System.loadLibrary",
        "Patch emulator/root checks (Build.FINGERPRINT, ro.kernel.qemu, su/busybox)",
        "Accelerate sleep/time bombs; replay with wall-clock offsets",
        "Toggle permissions at runtime; exercise overlays/accessibility",
        "Capture full PCAP with MITM and map flows to app UID",
        "Dump decrypted dex/so once loaded for secondary static pass",
    ]


def summarize(apk_path: Path) -> Dict:
    path = Path(apk_path)
    return {
        "device_setup": playbook(path),
        "notes": "Dynamic execution is delegated to a sandbox; these steps guide evasive-behavior capture.",
    }
