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
# Default to apex domain to avoid redirects that some clients treat as errors.
HA_URL = os.getenv("HA_URL", "https://hybrid-analysis.com/api/v2")

# YARA rules directory (optional)
YARA_RULES_DIR = os.getenv("YARA_RULES_DIR")

# Storage backend selection: "memory" (default) or "redis"
STORE_BACKEND = os.getenv("STORE_BACKEND", "memory")
# Redis connection and queue
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_QUEUE_NAME = os.getenv("REDIS_QUEUE_NAME", "apk_scan_jobs")

# Auth + rate limiting
API_KEY = os.getenv("API_KEY")  # if unset, auth is disabled
RATE_LIMIT_MAX = int(os.getenv("RATE_LIMIT_MAX", "60"))
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))  # seconds
