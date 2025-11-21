from __future__ import annotations

import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Dict, Optional, Tuple


class FileAuthStore:
    """Minimal file-backed user store with in-memory session tokens."""

    def __init__(self, file_path: Path) -> None:
        self.file_path = Path(file_path)
        self._lock = threading.Lock()
        self._users: Dict[str, Dict[str, str]] = self._load()
        self._sessions: Dict[str, Tuple[str, float]] = {}  # token -> (username, expires_at)

    def _load(self) -> Dict[str, Dict[str, str]]:
        if not self.file_path.exists():
            return {}
        try:
            data = json.loads(self.file_path.read_text())
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save(self) -> None:
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        self.file_path.write_text(json.dumps(self._users))

    def _hash_password(self, password: str, salt: Optional[bytes] = None) -> str:
        salt_bytes = salt or os.urandom(16)
        import hashlib

        hashed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, 100_000)
        return f"{salt_bytes.hex()}:{hashed.hex()}"

    def _verify_password(self, stored: str, provided: str) -> bool:
        try:
            salt_hex, hash_hex = stored.split(":")
        except ValueError:
            return False
        import hashlib
        salt_bytes = bytes.fromhex(salt_hex)
        provided_hash = hashlib.pbkdf2_hmac("sha256", provided.encode("utf-8"), salt_bytes, 100_000).hex()
        return secrets.compare_digest(hash_hex, provided_hash)

    def register(self, username: str, password: str) -> None:
        username = username.strip().lower()
        if not username or not password:
            raise ValueError("username and password required")
        with self._lock:
            if username in self._users:
                raise ValueError("user exists")
            self._users[username] = {
                "password": self._hash_password(password),
                "created_at": time.time(),
            }
            self._save()

    def authenticate(self, username: str, password: str) -> bool:
        username = username.strip().lower()
        with self._lock:
            record = self._users.get(username)
            if not record:
                return False
            return self._verify_password(record.get("password", ""), password)

    def issue_token(self, username: str, ttl_seconds: int = 86_400) -> Tuple[str, float]:
        expires_at = time.time() + ttl_seconds
        token = secrets.token_hex(32)
        with self._lock:
            self._sessions[token] = (username, expires_at)
        return token, expires_at

    def validate_token(self, token: str) -> Optional[str]:
        now = time.time()
        with self._lock:
            entry = self._sessions.get(token)
            if not entry:
                return None
            username, expires_at = entry
            if expires_at < now:
                self._sessions.pop(token, None)
                return None
            return username


# Default file location: alongside the backend codebase
DEFAULT_USER_FILE = Path(__file__).resolve().parent / "users.json"
auth_store = FileAuthStore(DEFAULT_USER_FILE)
