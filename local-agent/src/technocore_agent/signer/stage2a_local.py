"""Test-only Technocore canonical signing and durable nonce allocation.

The private key is accepted only as an already-created Ed25519 key object.  This module does
not generate, load, export, or transmit key material.  It also has no network capability.
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
import threading
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PREFIX = "did:key:"
MULTICODEC_ED25519 = b"\xed\x01"
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INVISIBLE_CATEGORIES = ("Cc", "Cf", "Cs", "Co", "Zl", "Zp")
MAX_TEXT_CHARS = 4096
MAX_VALUE_CHARS = 8192
MAX_NONCE = 10**19 - 1


class SignerInputError(ValueError):
    """The requested domain operation is not valid for Technocore's signed lane."""


def clean_text(text: str, limit: int) -> str:
    """Apply the server's control/invisible-character sweep and length limit."""
    if not isinstance(text, str):
        raise SignerInputError("text must be a string")
    cleaned = "".join(
        " " if unicodedata.category(char) in _INVISIBLE_CATEGORIES else char for char in text
    ).strip()
    if not cleaned:
        raise SignerInputError("text must contain visible characters")
    if len(cleaned) > limit:
        raise SignerInputError(f"text exceeds the {limit}-character limit")
    return cleaned


def _nonce_text(nonce: int) -> str:
    if not isinstance(nonce, int) or isinstance(nonce, bool) or not 1 <= nonce <= MAX_NONCE:
        raise SignerInputError("nonce must be an integer from 1 through 19 digits")
    return str(nonce)


def _field(value: str, name: str) -> str:
    if not isinstance(value, str) or not value or "|" in value:
        raise SignerInputError(f"{name} must be non-empty and contain no '|'")
    return value


def canonical_message(room: str, nonce: int, text: str) -> str:
    """Return the exact UTF-8 text signed by ``say-signed``."""
    return f"{_field(room, 'room')}|{_nonce_text(nonce)}|{clean_text(text, MAX_TEXT_CHARS)}"


def _base58(raw: bytes) -> str:
    number = int.from_bytes(raw, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = _B58[remainder] + encoded
    return encoded


def _did(key: Ed25519PrivateKey) -> str:
    return PREFIX + "z" + _base58(MULTICODEC_ED25519 + key.public_key().public_bytes_raw())


@dataclass(frozen=True, slots=True)
class SignedOperation:
    """Non-secret result of one locally signed room operation."""

    did: str
    room: str
    nonce: int
    signature: str
    text: str


class NonceStore:
    """A small JSON counter store with in-process serialization and atomic publication."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def next(self, lane: str) -> int:
        _field(lane, "lane")
        with self._lock:
            state = self._read()
            current = state.get(lane, 0)
            if not isinstance(current, int) or isinstance(current, bool) or current >= MAX_NONCE:
                raise SignerInputError("nonce counter is exhausted or corrupt")
            nonce = current + 1
            state[lane] = nonce
            self._write(state)
            return nonce

    def _read(self) -> dict[str, int]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, json.JSONDecodeError) as exc:
            raise SignerInputError("nonce state cannot be read") from exc
        if not isinstance(data, dict) or any(
            not isinstance(key, str)
            or not isinstance(value, int)
            or isinstance(value, bool)
            or not 0 <= value <= MAX_NONCE
            for key, value in data.items()
        ):
            raise SignerInputError("nonce state is corrupt")
        return data

    def _write(self, state: dict[str, int]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(state, stream, sort_keys=True, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        except OSError as exc:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise SignerInputError("nonce state cannot be written") from exc


class InMemorySigner:
    """Domain-specific test signer; never accepts arbitrary payloads or URLs."""

    def __init__(self, key: Ed25519PrivateKey, nonces: NonceStore) -> None:
        self._key = key
        self._nonces = nonces
        self.did = _did(key)

    def sign_room(self, room: str, text: str) -> SignedOperation:
        _field(room, "room")
        cleaned = clean_text(text, MAX_TEXT_CHARS)
        nonce = self._nonces.next(room)
        payload = f"{room}|{nonce}|{cleaned}"
        signature = (
            base64.urlsafe_b64encode(self._key.sign(payload.encode("utf-8"))).decode().rstrip("=")
        )
        return SignedOperation(self.did, room, nonce, signature, cleaned)
