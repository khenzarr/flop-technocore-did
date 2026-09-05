"""Shared, transport-free detached signing controller.

This module deliberately knows nothing about DPAPI, Windows, IPC, or submission.  The
caller supplies the custody provider and nonce store through ``Signer`` construction;
the production and fixture entrypoints therefore exercise exactly the same control flow.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ..storage.nonce import NonceStore
from .service import SignedOperation, Signer

SCHEMA = "technocore-detached-sign-request/v2"
PURPOSE = "DETACHED_ROOM_SIGNING"


class CustodyProvider(Protocol):
    def load_or_create(self): ...


@dataclass(frozen=True, slots=True)
class DetachedRequest:
    schema: str
    request_id: str
    room: str
    text: str
    expected_canonical_commit: str
    purpose: str

    @classmethod
    def from_mapping(cls, item: object) -> DetachedRequest:
        required = {"schema", "requestId", "room", "text", "expectedCanonicalCommit", "purpose"}
        if not isinstance(item, dict) or set(item) != required:
            raise ValueError("bridge request schema is invalid")
        if item["schema"] != SCHEMA or item["purpose"] != PURPOSE:
            raise ValueError("bridge request purpose or schema is invalid")
        if any(not isinstance(item[key], str) or not item[key] for key in required - {"schema", "purpose"}):
            raise ValueError("bridge request fields are invalid")
        commit = item["expectedCanonicalCommit"]
        if len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit):
            raise ValueError("bridge request commit is invalid")
        return cls(item["schema"], item["requestId"], item["room"], item["text"], commit, item["purpose"])


def run_detached_signing(
    request: DetachedRequest,
    custody_provider: CustodyProvider,
    nonce_store: NonceStore,
    *,
    actual_canonical_commit: str,
    operator_context: str = PURPOSE,
) -> SignedOperation:
    """Validate and perform one detached signature, with no submission surface."""
    if operator_context != PURPOSE:
        raise PermissionError("detached operation purpose is invalid")
    if actual_canonical_commit != request.expected_canonical_commit:
        raise ValueError("canonical repository HEAD does not match expected commit")
    if len(actual_canonical_commit) != 40 or any(c not in "0123456789abcdef" for c in actual_canonical_commit):
        raise ValueError("canonical repository HEAD is invalid")
    signer = Signer(custody_provider.load_or_create(), nonce_store)
    return signer.sign_room_detached(request.room, request.text)


def serialize_signed_operation(operation: SignedOperation, canonical_commit: str, custody_mode: str) -> dict[str, object]:
    """Return the machine response; logging layers must use ``sanitized_error`` instead."""
    return {
        "did": operation.did,
        "room": operation.room,
        "nonce": operation.nonce,
        "signature": operation.signature,
        "text": operation.text,
        "canonicalCommit": canonical_commit,
        "custodyMode": custody_mode,
    }


def sanitized_error(exc: Exception) -> dict[str, str]:
    return {"error": str(exc)}
