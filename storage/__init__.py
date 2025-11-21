import os

BACKEND = os.getenv("STORE_BACKEND", "memory").lower()

if BACKEND == "redis":
    try:
        from .redis_store import ScanRecord, ScanStatus, ScanStore  # type: ignore

        store = ScanStore()
    except Exception:  # pragma: no cover
        # Fallback silently to memory if Redis is unreachable/misconfigured
        from .memory import ScanRecord, ScanStatus, ScanStore, store  # type: ignore
else:
    from .memory import ScanRecord, ScanStatus, ScanStore, store

__all__ = ["ScanRecord", "ScanStatus", "ScanStore", "store", "BACKEND"]
