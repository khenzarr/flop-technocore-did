"""Two-stage, transport-free W2 nonce reservation and exact detached signing.

This is an additive custody entrypoint. Reserve reads the selected public DID and
fsyncs the shared room nonce store without loading a key. Sign independently
validates the exact approval, requires an operator terminal in real custody,
and consumes the reserved signature budget before calling the existing signer.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..service.local_init import default_local_state
from ..service.profile_init import derive_profile_root, validate_profile
from ..service.runtime import TrustedPaths
from ..storage.nonce import NonceStore
from .canonical import canonical_message, clean_text
from .detached_controller import _public_did
from .real_detached_sign_bridge import (
    FIXTURE_KEY,
    TerminalApproval,
    _actual_commit,
    _clean_relevant_tree,
    _provider,
)
from .service import Signer, canonical_did

RESERVE_SCHEMA = "technocore-w2-reserve-request/v1"
SIGN_SCHEMA = "technocore-w2-sign-reserved-request/v1"
CANCEL_SCHEMA = "technocore-w2-cancel-reserved-request/v1"
NONCE = re.compile(r"(?:0|[1-9][0-9]{0,18})\Z")
ROOM = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}\Z")
SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
DID = re.compile(r"did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}\Z")
OP = re.compile(r"w2op1-[0-9a-f]{64}\Z")
DRAFT = re.compile(r"w2draft1-[0-9a-f]{64}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
ASSERTION_KEYS = frozenset({"assertionType", "coverage", "evidenceArtifactSha256",
                            "inputSha256", "limitations", "schema", "venueOrigin",
                            "verdict", "verifier", "workloadId"})
LIMITATIONS = ["NO_ECONOMIC_OR_REWARD_CLAIM", "NOT_INDEPENDENT_CONTRIBUTION_PROOF",
               "ROOM_REDACTED", "SELF_PUBLISHED", "SUPPLIED_WINDOW_ONLY"]
APPROVAL_KEYS = frozenset({
    "action", "approvalExpiresAt", "approvalIssuedAt", "evidenceArtifactSha256",
    "nonce", "operationId", "schema", "signaturePreimageSha256", "signedText",
    "signedTextSha256", "signerDid", "targetRoom", "targetVenueOrigin",
})


class W2ApprovalExpiredError(ValueError):
    pass


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    output = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate W2 JSON member")
        output[key] = value
    return output


def _read(path: Path) -> dict:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("W2 request path is invalid")
    raw = path.read_bytes()
    if len(raw) > 16 * 1024:
        raise ValueError("W2 request is too large")
    item = json.loads(raw, object_pairs_hook=_unique_pairs)
    if not isinstance(item, dict):
        raise ValueError("W2 request is not an object")
    return item


def _venue(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        return (parsed.scheme == "https" and bool(parsed.netloc) and
                not parsed.username and not parsed.password and not parsed.path and
                not parsed.query and not parsed.fragment and
                value == f"https://{parsed.netloc.lower()}")
    except (TypeError, ValueError):
        return False


def _assertion(value: object) -> None:
    if not isinstance(value, dict) or set(value) != ASSERTION_KEYS:
        raise ValueError("W2 assertion schema is not closed")
    if value["schema"] != "blackbox/validation-result-assertion/v1" or value["assertionType"] != "W1_VALIDATION_RESULT":
        raise ValueError("W2 assertion type is invalid")
    if not (isinstance(value["workloadId"], str) and HEX.fullmatch(value["workloadId"])
            and isinstance(value["inputSha256"], str) and HEX.fullmatch(value["inputSha256"])
            and isinstance(value["evidenceArtifactSha256"], str) and SHA.fullmatch(value["evidenceArtifactSha256"])):
        raise ValueError("W2 assertion commitment is invalid")
    if value["verdict"] not in {"VALID", "INVALID", "INDETERMINATE"} or value["limitations"] != LIMITATIONS:
        raise ValueError("W2 assertion verdict or limitations are invalid")
    if not isinstance(value["venueOrigin"], str) or not _venue(value["venueOrigin"]):
        raise ValueError("W2 assertion venue is invalid")
    coverage = value["coverage"]
    if not isinstance(coverage, dict) or set(coverage) != {"generation", "historyCompleteness", "scope", "windowStatus"}:
        raise ValueError("W2 assertion coverage is invalid")
    if coverage["historyCompleteness"] != "NOT_PROVEN" or coverage["scope"] != "SUPPLIED_WINDOW_ONLY":
        raise ValueError("W2 assertion coverage is invalid")
    if coverage["windowStatus"] not in {"BOUNDED", "GAPPED", "UNRELIABLE_ORDER", "UNKNOWN_GENERATION", "EMPTY"}:
        raise ValueError("W2 assertion window status is invalid")
    generation = coverage["generation"]
    if not isinstance(generation, dict):
        raise ValueError("W2 assertion generation is invalid")
    known = (set(generation) == {"source", "status", "value"} and
             generation.get("source") == "SUPPLIED_HEADER" and generation.get("status") == "KNOWN" and
             isinstance(generation.get("value"), str) and NONCE.fullmatch(generation["value"]))
    unknown = (set(generation) == {"source", "status"} and
               generation.get("source") == "NONE" and generation.get("status") == "UNKNOWN")
    if not (known or unknown):
        raise ValueError("W2 assertion generation is invalid")
    verifier = value["verifier"]
    if not isinstance(verifier, dict) or set(verifier) != {"checkProfile", "id", "implementationDigest"}:
        raise ValueError("W2 assertion verifier is invalid")
    if (verifier["checkProfile"] != "tc-export-signed-rows/v1" or
            verifier["id"] != "technocore-transcript-validation/v1" or
            not isinstance(verifier["implementationDigest"], str) or
            not SHA.fullmatch(verifier["implementationDigest"])):
        raise ValueError("W2 assertion verifier is invalid")


def _profile(request: dict, custody: str, state: Path) -> tuple[Path, str]:
    profile = request.get("profile")
    expected = request.get("expectedSignerDid")
    if not isinstance(profile, str) or not isinstance(expected, str) or not DID.fullmatch(expected):
        raise ValueError("W2 signer selection is invalid")
    if profile != "default":
        validate_profile(profile)
    root = default_local_state() if profile == "default" else derive_profile_root(profile)
    if custody == "fixture":
        return state, canonical_did(Ed25519PrivateKey.from_private_bytes(FIXTURE_KEY))
    return root, _public_did(profile, root)


def validate_reserve_request(item: dict) -> dict:
    expected = {"schema", "purpose", "expectedCanonicalCommit", "requestId", "profile",
                "expectedSignerDid", "targetRoom", "targetVenueOrigin", "signedTextSha256"}
    if set(item) != expected or item.get("schema") != RESERVE_SCHEMA or item.get("purpose") != "W2_RESERVE_ROOM_NONCE":
        raise ValueError("W2 reserve schema is invalid")
    if not DRAFT.fullmatch(item["requestId"]) or not ROOM.fullmatch(item["targetRoom"]) or not SHA.fullmatch(item["signedTextSha256"]):
        raise ValueError("W2 reserve binding is invalid")
    if not _venue(item["targetVenueOrigin"]):
        raise ValueError("W2 reserve venue is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", item["expectedCanonicalCommit"]):
        raise ValueError("W2 signer pin is invalid")
    return item


def validate_sign_request(item: dict, *, check_time: bool = True) -> tuple[dict, str]:
    expected = {"schema", "purpose", "expectedCanonicalCommit", "requestId", "profile",
                "expectedSignerDid", "approvalCandidate", "approvalHash"}
    if set(item) != expected or item.get("schema") != SIGN_SCHEMA or item.get("purpose") != "W2_SIGN_EXACT_RESERVATION":
        raise ValueError("W2 sign schema is invalid")
    if not DRAFT.fullmatch(item["requestId"]) or not re.fullmatch(r"[0-9a-f]{40}", item["expectedCanonicalCommit"]):
        raise ValueError("W2 sign request id or pin is invalid")
    candidate = item["approvalCandidate"]
    if not isinstance(candidate, dict) or set(candidate) != APPROVAL_KEYS:
        raise ValueError("W2 sign approval schema is not closed")
    if candidate["schema"] != "blackbox/w2-sign-approval/v1" or candidate["action"] != "CREATE_DETACHED_SIGNATURE_ONLY":
        raise ValueError("W2 sign approval purpose is invalid")
    if not all(isinstance(value, str) and value.isascii() and value.isprintable() for value in candidate.values()):
        raise ValueError("W2 sign approval fields are invalid")
    if not (SHA.fullmatch(candidate["evidenceArtifactSha256"]) and SHA.fullmatch(candidate["signedTextSha256"])
            and SHA.fullmatch(candidate["signaturePreimageSha256"]) and OP.fullmatch(candidate["operationId"])
            and ROOM.fullmatch(candidate["targetRoom"]) and DID.fullmatch(candidate["signerDid"])
            and NONCE.fullmatch(candidate["nonce"]) and candidate["nonce"] != "0"):
        raise ValueError("W2 sign approval binding is invalid")
    text = candidate["signedText"]
    if not text.startswith("blackbox-w2 ") or clean_text(text) != text or len(text) > 4096:
        raise ValueError("W2 signed text is invalid")
    assertion = json.loads(text[len("blackbox-w2 "):], object_pairs_hook=_unique_pairs)
    _assertion(assertion)
    if text != "blackbox-w2 " + _canonical(assertion).decode("ascii"):
        raise ValueError("W2 assertion is not canonical")
    if assertion.get("venueOrigin") != candidate["targetVenueOrigin"]:
        raise ValueError("W2 signed venue differs from approval")
    if assertion.get("evidenceArtifactSha256") != candidate["evidenceArtifactSha256"]:
        raise ValueError("W2 signed W1 commitment differs from approval")
    if candidate["signerDid"] != item["expectedSignerDid"]:
        raise ValueError("W2 signer selection differs from approval")
    if _sha(text.encode()) != candidate["signedTextSha256"]:
        raise ValueError("W2 signed text hash mismatch")
    preimage = canonical_message(candidate["targetRoom"], int(candidate["nonce"]), text)
    if _sha(preimage.encode()) != candidate["signaturePreimageSha256"]:
        raise ValueError("W2 signature preimage hash mismatch")
    core = {"assertionSchema": "blackbox/validation-result-assertion/v1",
            "evidenceArtifactSha256": candidate["evidenceArtifactSha256"],
            "nonce": candidate["nonce"], "room": candidate["targetRoom"],
            "signedTextSha256": candidate["signedTextSha256"],
            "signerDid": candidate["signerDid"], "venueOrigin": candidate["targetVenueOrigin"]}
    operation = "w2op1-" + hashlib.sha256(b"BLACKBOX::W2::OPERATION::v1\0" + _canonical(core)).hexdigest()
    if candidate["operationId"] != operation:
        raise ValueError("W2 operation id mismatch")
    draft = {"evidenceArtifactSha256": candidate["evidenceArtifactSha256"],
             "room": candidate["targetRoom"], "signerDid": candidate["signerDid"],
             "signedTextSha256": candidate["signedTextSha256"],
             "venueOrigin": candidate["targetVenueOrigin"]}
    expected_request_id = "w2draft1-" + hashlib.sha256(
        b"BLACKBOX::W2::DRAFT::v1\0" + _canonical(draft)).hexdigest()
    if item["requestId"] != expected_request_id:
        raise ValueError("W2 draft reservation id mismatch")
    approved_hash = _sha(b"BLACKBOX::W2::SIGN_APPROVAL::v1\0" + _canonical(candidate))
    if item["approvalHash"] != approved_hash:
        raise ValueError("W2 sign approval hash mismatch")
    issued = datetime.fromisoformat(candidate["approvalIssuedAt"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(candidate["approvalExpiresAt"].replace("Z", "+00:00"))
    now = datetime.now(UTC)
    if issued.tzinfo is None or expires.tzinfo is None or expires - issued != timedelta(minutes=15):
        raise ValueError("W2 sign approval time bounds are invalid")
    if check_time and not issued <= now <= expires:
        raise W2ApprovalExpiredError("W2 sign approval is expired or not yet valid")
    return candidate, approved_hash


def validate_cancel_request(item: dict) -> tuple[dict, str]:
    if item.get("schema") != CANCEL_SCHEMA or item.get("purpose") != "W2_CANCEL_EXACT_RESERVATION":
        raise ValueError("W2 cancellation purpose is invalid")
    if item.get("cancelReason") not in {"CANCELLED", "EXPIRED"}:
        raise ValueError("W2 cancellation reason is invalid")
    sign_shape = {key: value for key, value in item.items() if key != "cancelReason"}
    sign_shape.update(schema=SIGN_SCHEMA, purpose="W2_SIGN_EXACT_RESERVATION")
    return validate_sign_request(sign_shape, check_time=False)


def _cancel_bound(store: NonceStore, item: dict, candidate: dict,
                  approval_hash: str, reason: str) -> dict:
    return store.cancel_w2(
        item["requestId"], lane=candidate["targetRoom"], signer_did=candidate["signerDid"],
        venue_origin=candidate["targetVenueOrigin"], text_sha256=candidate["signedTextSha256"],
        nonce=candidate["nonce"], operation_id=candidate["operationId"],
        approval_hash=approval_hash, reason=reason,
    )


def cancel_once(item: dict, *, custody: str, state: Path, actual_commit: str) -> dict:
    """No key, signer, transport, or fresh nonce is reachable on this path."""
    candidate, approval_hash = validate_cancel_request(item)
    if actual_commit != item["expectedCanonicalCommit"]:
        raise ValueError("W2 signer pin mismatch")
    root, selected_did = _profile(item, custody, state)
    if selected_did != candidate["signerDid"]:
        raise ValueError("W2 signer DID does not match selected profile")
    reservation = _cancel_bound(NonceStore(TrustedPaths.under(root).nonces), item,
                                candidate, approval_hash, item["cancelReason"])
    return {"schema": "technocore-w2-cancellation/v1", "requestId": item["requestId"],
            "operationId": candidate["operationId"], "signerDid": selected_did,
            "nonce": reservation["nonce"], "state": reservation["state"],
            "auditEvent": reservation["audit_event"], "canonicalCommit": actual_commit,
            "custodyMode": custody}


def reserve_once(item: dict, *, custody: str, state: Path, actual_commit: str) -> dict:
    validate_reserve_request(item)
    if actual_commit != item["expectedCanonicalCommit"]:
        raise ValueError("W2 signer pin mismatch")
    root, selected_did = _profile(item, custody, state)
    if selected_did != item["expectedSignerDid"]:
        raise ValueError("W2 signer DID does not match selected profile")
    reservation = NonceStore(TrustedPaths.under(root).nonces).reserve_w2(
        item["requestId"], item["targetRoom"], selected_did,
        item["targetVenueOrigin"], item["signedTextSha256"])
    return {"schema": "technocore-w2-reservation/v1", "requestId": item["requestId"],
            "room": item["targetRoom"], "signerDid": selected_did,
            "venueOrigin": item["targetVenueOrigin"], "nonce": reservation["nonce"],
            "state": reservation["state"], "createdAt": reservation["created_at"],
            "canonicalCommit": actual_commit, "custodyMode": custody}


def sign_once(item: dict, *, custody: str, state: Path, actual_commit: str,
              approval: TerminalApproval | None = None) -> dict:
    if actual_commit != item["expectedCanonicalCommit"]:
        raise ValueError("W2 signer pin mismatch")
    try:
        candidate, approved_hash = validate_sign_request(item)
    except W2ApprovalExpiredError:
        candidate, approved_hash = validate_sign_request(item, check_time=False)
        root, selected_did = _profile(item, custody, state)
        if selected_did == item.get("expectedSignerDid"):
            _cancel_bound(NonceStore(TrustedPaths.under(root).nonces), item,
                          candidate, approved_hash, "EXPIRED")
        raise
    root, selected_did = _profile(item, custody, state)
    if selected_did != candidate["signerDid"]:
        raise ValueError("W2 signer DID does not match selected profile")
    channel = approval or TerminalApproval()
    if custody == "real" and not isinstance(channel, TerminalApproval):
        raise PermissionError("W2 real custody needs the terminal channel")
    if not channel.attached():
        raise PermissionError("W2 interactive terminal required")
    phrase = f"SIGN W2 ONCE {approved_hash[-8:].upper()}"
    channel.prompt("\nW2 EXACT DETACHED SIGNATURE — NO POST\n" + _canonical(candidate).decode("ascii")
                   + f"\nAPPROVAL HASH: {approved_hash}\nType exactly: {phrase}\nW2 approval: ")
    if channel.read().rstrip("\r\n") != phrase:
        raise PermissionError("W2 exact approval refused")
    store = NonceStore(TrustedPaths.under(root).nonces)
    store.approve_w2(item["requestId"], lane=candidate["targetRoom"],
                     signer_did=candidate["signerDid"], venue_origin=candidate["targetVenueOrigin"],
                     text_sha256=candidate["signedTextSha256"], nonce=candidate["nonce"],
                     operation_id=candidate["operationId"], approval_hash=approved_hash)
    provider = _provider(custody, root)
    signer = Signer(provider.load_existing() if custody == "real" else provider.load_or_create(), store)
    operation = signer.sign_reserved_w2(
        request_id=item["requestId"], room=candidate["targetRoom"],
        text=candidate["signedText"], nonce=candidate["nonce"],
        expected_did=candidate["signerDid"], venue_origin=candidate["targetVenueOrigin"],
        operation_id=candidate["operationId"], approval_hash=approved_hash,
    )
    return {"schema": "technocore-w2-signed-operation/v1", "requestId": item["requestId"],
            "did": operation.did, "room": operation.room, "nonce": str(operation.nonce),
            "text": operation.text, "signature": operation.signature,
            "operationId": candidate["operationId"], "approvalHash": approved_hash,
            "canonicalCommit": actual_commit, "custodyMode": custody}


def main() -> None:
    parser = argparse.ArgumentParser(description="W2 reserved nonce custody bridge")
    parser.add_argument("--request-file", type=Path, required=True)
    parser.add_argument("--custody", choices=("fixture", "real"), required=True)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    try:
        item = _read(args.request_file)
        actual = _actual_commit()
        _clean_relevant_tree()
        if item.get("schema") == RESERVE_SCHEMA:
            response = reserve_once(item, custody=args.custody, state=args.state, actual_commit=actual)
        elif item.get("schema") == SIGN_SCHEMA:
            response = sign_once(item, custody=args.custody, state=args.state, actual_commit=actual)
        elif item.get("schema") == CANCEL_SCHEMA:
            response = cancel_once(item, custody=args.custody, state=args.state, actual_commit=actual)
        else:
            raise ValueError("W2 request schema is unsupported")
    except Exception:
        response = {"error": "W2_CUSTODY_REFUSED"}
    sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
