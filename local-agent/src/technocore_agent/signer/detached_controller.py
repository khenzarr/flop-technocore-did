"""Shared, transport-free detached signing controller.

This module deliberately knows nothing about DPAPI, Windows, IPC, or submission.  The
caller supplies the custody provider and nonce store through ``Signer`` construction;
the production and fixture entrypoints therefore exercise exactly the same control flow.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
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
    profile: str = "default"
    expected_signer_did: str | None = None

    @classmethod
    def from_mapping(cls, item: object) -> DetachedRequest:
        required = {"schema", "requestId", "room", "text", "expectedCanonicalCommit", "purpose"}
        profile_fields = {"profile", "expectedSignerDid"}
        allowed = (required, required | {"profile"}, required | profile_fields)
        if not isinstance(item, dict) or set(item) not in allowed:
            raise ValueError("bridge request schema is invalid")
        if item["schema"] != SCHEMA or item["purpose"] != PURPOSE:
            raise ValueError("bridge request purpose or schema is invalid")
        if any(not isinstance(item[key], str) or not item[key] for key in required - {"schema", "purpose"}):
            raise ValueError("bridge request fields are invalid")
        profile = item.get("profile", "default")
        expected_did = item.get("expectedSignerDid")
        if not isinstance(profile, str) or not profile:
            raise ValueError("bridge profile is invalid")
        if profile != "default" and (not isinstance(expected_did, str) or not expected_did):
            raise ValueError("named bridge profile requires expected signer DID")
        if expected_did is not None and (not isinstance(expected_did, str) or not expected_did):
            raise ValueError("bridge expected signer DID is invalid")
        commit = item["expectedCanonicalCommit"]
        if len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit):
            raise ValueError("bridge request commit is invalid")
        return cls(item["schema"], item["requestId"], item["room"], item["text"], commit,
                   item["purpose"], profile, expected_did)


def _profile_root(profile: str) -> Path:
    if profile == "default":
        from ..service.local_init import default_local_state
        return default_local_state().resolve()
    from ..service.profile_init import derive_profile_root
    return derive_profile_root(profile)


def _public_did(profile: str, profile_root: Path | None = None) -> str:
    marker = (profile_root if profile_root is not None else _profile_root(profile)) / "local-install.json"
    if not marker.is_file() or marker.is_symlink():
        raise ValueError("selected signer profile is not enrolled")
    try:
        item = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("selected signer profile marker is invalid") from exc
    did = item.get("public_did") if isinstance(item, dict) else None
    if not isinstance(did, str) or not did.startswith("did:key:"):
        raise ValueError("selected signer profile marker has no valid public DID")
    return did


def run_detached_signing(
    request: DetachedRequest,
    custody_provider: CustodyProvider,
    nonce_store: NonceStore,
    *,
    actual_canonical_commit: str,
    operator_context: str = PURPOSE,
    profile: str = "default",
    expected_signer_did: str | None = None,
    profile_root: Path | None = None,
) -> SignedOperation:
    """Validate and perform one detached signature, with no submission surface."""
    if operator_context != PURPOSE:
        raise PermissionError("detached operation purpose is invalid")
    if profile != request.profile or expected_signer_did != request.expected_signer_did:
        raise ValueError("signer selection does not match the reviewed request")
    if actual_canonical_commit != request.expected_canonical_commit:
        raise ValueError("canonical repository HEAD does not match expected commit")
    if len(actual_canonical_commit) != 40 or any(c not in "0123456789abcdef" for c in actual_canonical_commit):
        raise ValueError("canonical repository HEAD is invalid")
    selected_did = None
    if profile != "default" or expected_signer_did is not None:
        selected_did = _public_did(profile, profile_root)
        if expected_signer_did is not None and selected_did != expected_signer_did:
            raise ValueError("expected signer DID does not match selected custody profile")
    signer = Signer(custody_provider.load_or_create(), nonce_store)
    if selected_did is not None and signer.did != selected_did:
        raise ValueError("selected custody profile public DID does not match its key")
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
