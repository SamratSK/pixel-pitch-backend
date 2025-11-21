import json
import threading
import time
from typing import Optional

try:
    import redis  # type: ignore
except Exception:  # pragma: no cover
    redis = None

# Support package-relative or direct import
try:
    from .config import REDIS_QUEUE_NAME, REDIS_URL
except ImportError:  # pragma: no cover
    from config import REDIS_QUEUE_NAME, REDIS_URL


class RedisQueue:
    def __init__(self) -> None:
        if redis is None:
            self.client = None
            return
        try:
            self.client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        except Exception:
            self.client = None

    def available(self) -> bool:
        if self.client is None:
            return False
        try:
            # Lightweight health check; if it fails, disable Redis usage so we can fall back.
            self.client.ping()
            return True
        except Exception:
            self.client = None
            return False

    def push(self, payload: dict) -> bool:
        if not self.available():
            return False
        try:
            self.client.rpush(REDIS_QUEUE_NAME, json.dumps(payload))
            return True
        except Exception:
            self.client = None
            return False

    def pop_blocking(self, timeout: int = 5) -> Optional[dict]:
        if not self.available():
            return None
        try:
            res = self.client.blpop(REDIS_QUEUE_NAME, timeout=timeout)
            if not res:
                return None
            _, raw = res
            return json.loads(raw)
        except Exception:
            self.client = None
            return None


# Simple thread-based worker that can use Redis queue when available
class Worker:
    def __init__(self, handler) -> None:
        self.handler = handler
        self.redis_queue = RedisQueue()
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None

    def start(self):
        # Only run a worker if Redis is available; otherwise caller runs inline threads
        if not self.redis_queue.available():
            return
        if self.thread and self.thread.is_alive():
            return
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()

    def enqueue(self, payload: dict):
        if self.redis_queue.push(payload):
            return
        # Fallback: run in a short-lived thread when Redis is unavailable/unreachable
        t = threading.Thread(target=self.handler, kwargs=payload, daemon=True)
        t.start()

    def _loop(self):
        while not self.stop_event.is_set():
            job = self.redis_queue.pop_blocking(timeout=3)
            if not job:
                continue
            try:
                self.handler(**job)
            except Exception:
                # swallow to keep worker running; handler should log internally
                time.sleep(0.1)
                continue
