from __future__ import annotations

import base64
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class OperatorAuthError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class OperatorSession:
    session_id: str
    csrf_token: str
    expires_at: float


class OperatorAuth:
    """Separate local operator credential; only a verifier is persisted."""

    def __init__(
        self,
        path: Path,
        session_ttl: int = 900,
        *,
        clock=None,
        base_backoff: float = 0.25,
        max_backoff: float = 8.0,
    ) -> None:
        self.path, self.session_ttl = Path(path), session_ttl
        self._sessions: dict[str, OperatorSession] = {}
        self._clock = clock or time.time
        self._base_backoff = base_backoff
        self._max_backoff = max_backoff
        self._failures = 0
        self._next_attempt_at = 0.0
        self._auth_lock = threading.RLock()

    def configured(self) -> bool:
        return self.path.exists()

    def enroll(self, passphrase: str) -> None:
        self._validate(passphrase)
        if self.configured():
            raise OperatorAuthError("operator credential is already configured")
        salt = secrets.token_bytes(16)
        verifier = self._derive(passphrase, salt)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(
                {
                    "algorithm": "scrypt",
                    "n": 2**15,
                    "r": 8,
                    "p": 1,
                    "salt": base64.b64encode(salt).decode(),
                    "verifier": base64.b64encode(verifier).decode(),
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )

    def unlock(self, passphrase: str) -> OperatorSession:
        with self._auth_lock:
            self.reauthenticate(passphrase)
            session = OperatorSession(
                secrets.token_urlsafe(32),
                secrets.token_urlsafe(32),
                self._clock() + self.session_ttl,
            )
            self._sessions[session.session_id] = session
            return session

    def reauthenticate(self, passphrase: str) -> None:
        """Verify fresh operator presence without persisting or returning the passphrase."""
        with self._auth_lock:
            self._reauthenticate_locked(passphrase)

    def _reauthenticate_locked(self, passphrase: str) -> None:
        if not self.configured():
            raise OperatorAuthError("authentication failed")
        # An omitted form field is a protocol error, not a password-guessing
        # attempt. Do not spend KDF CPU or consume the bounded backoff budget.
        if not isinstance(passphrase, str) or not passphrase:
            raise OperatorAuthError("authentication failed")
        now = self._clock()
        if now < self._next_attempt_at:
            raise OperatorAuthError("authentication failed")
        try:
            item = json.loads(self.path.read_text(encoding="utf-8"))
            salt = base64.b64decode(item["salt"])
            expected = base64.b64decode(item["verifier"])
            actual = self._derive(passphrase, salt)
        except (OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
            raise OperatorAuthError("authentication failed") from exc
        if not hmac.compare_digest(actual, expected):
            self._failures += 1
            delay = min(
                self._max_backoff,
                self._base_backoff * (2 ** min(self._failures - 1, 16)),
            )
            self._next_attempt_at = now + delay
            raise OperatorAuthError("authentication failed")
        self._failures = 0
        self._next_attempt_at = 0.0

    def validate(self, session_id: str | None, csrf_token: str | None = None) -> OperatorSession:
        with self._auth_lock:
            session = self._sessions.get(session_id or "")
            if session is None or session.expires_at <= self._clock():
                self._sessions.pop(session_id or "", None)
                raise OperatorAuthError("operator session is missing or expired")
            if csrf_token is not None and not hmac.compare_digest(session.csrf_token, csrf_token):
                raise OperatorAuthError("invalid CSRF token")
            return session

    def logout(self, session_id: str | None) -> None:
        with self._auth_lock:
            self._sessions.pop(session_id or "", None)

    @staticmethod
    def session_hash(session_id: str) -> str:
        import hashlib

        return hashlib.sha256(session_id.encode()).hexdigest()

    @staticmethod
    def _validate(passphrase: str) -> None:
        if not isinstance(passphrase, str) or len(passphrase) < 20:
            raise OperatorAuthError(
                "use a unique high-entropy operator passphrase of at least 20 characters"
            )

    @staticmethod
    def _derive(passphrase: str, salt: bytes) -> bytes:
        return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode())
