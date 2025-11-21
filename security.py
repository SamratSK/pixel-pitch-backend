import time
from typing import Callable, Dict, Optional

from fastapi import Depends, HTTPException, Request, status

try:
    from .config import API_KEY, RATE_LIMIT_MAX, RATE_LIMIT_WINDOW
except ImportError:  # pragma: no cover
    from config import API_KEY, RATE_LIMIT_MAX, RATE_LIMIT_WINDOW


class RateLimiter:
    def __init__(self, max_requests: int = 60, window_seconds: int = 60) -> None:
        self.max = max_requests
        self.window = window_seconds
        self.buckets: Dict[str, list] = {}

    def check(self, key: str) -> None:
        now = time.time()
        window_start = now - self.window
        bucket = self.buckets.setdefault(key, [])
        # prune old
        while bucket and bucket[0] < window_start:
            bucket.pop(0)
        if len(bucket) >= self.max:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="rate limit exceeded")
        bucket.append(now)


rate_limiter = RateLimiter(max_requests=RATE_LIMIT_MAX, window_seconds=RATE_LIMIT_WINDOW)


def require_api_key(request: Request):
    if not API_KEY:
        return  # auth disabled
    provided = request.headers.get("x-api-key") or request.headers.get("authorization")
    if not provided:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing api key")
    token = provided.replace("Bearer", "").strip()
    if token != API_KEY:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid api key")


def rate_limit_dependency(request: Request):
    # key on client host + api key if present
    ident = f"{request.client.host}:{request.headers.get('x-api-key','') or request.headers.get('authorization','')}"
    rate_limiter.check(ident)

