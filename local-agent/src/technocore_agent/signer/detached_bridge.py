"""Secretless, one-shot stdin/stdout bridge for the reviewed detached signer.

This entrypoint intentionally supports only the disposable fixture key. Production custody is
owned by the canonical agent and is not reachable through this Phase 3A.7 command.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..storage.nonce import NonceStore
from .service import Signer

SCHEMA = "technocore-detached-sign-request/v1"
EXPECTED_COMMIT = "e5bd617b36c69315c238ef39bfca7c3f5a8c4d98"


def _request(raw: bytes) -> dict:
    if len(raw) > 16 * 1024:
        raise ValueError("bridge request is too large")
    item = json.loads(raw)
    if not isinstance(item, dict) or set(item) != {"schema", "room", "text", "requestId", "expectedCanonicalCommit", "noncePath"}:
        raise ValueError("bridge request schema is invalid")
    if item["schema"] != SCHEMA or item["expectedCanonicalCommit"] != EXPECTED_COMMIT:
        raise ValueError("bridge request pin is invalid")
    if not all(isinstance(item[key], str) and item[key] for key in ("room", "text", "requestId", "noncePath")):
        raise ValueError("bridge request fields are invalid")
    return item


def serve_once() -> None:
    try:
        request = _request(sys.stdin.buffer.readline(16 * 1024 + 1))
        if not Path(request["noncePath"]).is_absolute():
            raise ValueError("noncePath must be absolute")
        # bytes(range(32)) is a published, disposable test vector, never operator custody.
        signer = Signer(Ed25519PrivateKey.from_private_bytes(bytes(range(32))), NonceStore(Path(request["noncePath"])))
        operation = signer.sign_room_detached(request["room"], request["text"])
        response = {"did": operation.did, "room": operation.room, "nonce": operation.nonce,
                    "signature": operation.signature, "text": operation.text}
    except (TypeError, ValueError, OSError, KeyError) as exc:
        response = {"error": str(exc)}
    sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    serve_once()
