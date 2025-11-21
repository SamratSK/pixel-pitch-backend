from pathlib import Path
import os

# Base directory for app resources
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Hard limit for uploaded APK size (100 MB by default)
MAX_UPLOAD_BYTES = 100 * 1024 * 1024

# External services (set via environment variables)
VT_API_KEY = os.getenv("VT_API_KEY")
VT_URL = os.getenv("VT_URL", "https://www.virustotal.com/api/v3")

# Hybrid Analysis
HA_API_KEY = os.getenv("HA_API_KEY")
HA_URL = os.getenv("HA_URL", "https://www.hybrid-analysis.com/api/v2")

# Storage backend selection: "memory" (default) or "redis"
STORE_BACKEND = os.getenv("STORE_BACKEND", "memory")
