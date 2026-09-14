from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_agent.service.runtime import DPAPIKeyProvider, TrustedPaths
from technocore_agent.signer.service import canonical_did
from technocore_agent.signer.w2_reserved_bridge import (
    W2ApprovalExpiredError,
    _canonical,
    _sha,
    cancel_once,
    reserve_once,
    sign_once,
    validate_cancel_request,
    validate_sign_request,
)
from technocore_agent.storage.nonce import NonceStore

PIN = "a" * 40
DID = canonical_did(Ed25519PrivateKey.from_private_bytes(bytes(range(32))))
ROOM = "w2-fixture"
VENUE = "https://technocore.chat"
ASSERTION = {"schema": "blackbox/validation-result-assertion/v1",
             "assertionType": "W1_VALIDATION_RESULT",
             "coverage": {"generation": {"source": "SUPPLIED_HEADER", "status": "KNOWN", "value": "1"},
                          "historyCompleteness": "NOT_PROVEN", "scope": "SUPPLIED_WINDOW_ONLY",
                          "windowStatus": "BOUNDED"},
             "evidenceArtifactSha256": "sha256:" + "b" * 64,
             "inputSha256": "c" * 64,
             "limitations": ["NO_ECONOMIC_OR_REWARD_CLAIM", "NOT_INDEPENDENT_CONTRIBUTION_PROOF",
                             "ROOM_REDACTED", "SELF_PUBLISHED", "SUPPLIED_WINDOW_ONLY"],
             "venueOrigin": VENUE, "verdict": "VALID",
             "verifier": {"checkProfile": "tc-export-signed-rows/v1",
                          "id": "technocore-transcript-validation/v1",
                          "implementationDigest": "sha256:" + "d" * 64},
             "workloadId": "e" * 64}
TEXT = "blackbox-w2 " + _canonical(ASSERTION).decode()
REQUEST_ID = "w2draft1-" + hashlib.sha256(b"BLACKBOX::W2::DRAFT::v1\0" + _canonical({
    "evidenceArtifactSha256": ASSERTION["evidenceArtifactSha256"], "room": ROOM,
    "signerDid": DID, "signedTextSha256": _sha(TEXT.encode()), "venueOrigin": VENUE,
})).hexdigest()


def reserve_request():
    return {"schema": "technocore-w2-reserve-request/v1", "purpose": "W2_RESERVE_ROOM_NONCE",
            "expectedCanonicalCommit": PIN, "requestId": REQUEST_ID, "profile": "default",
            "expectedSignerDid": DID, "targetRoom": ROOM, "targetVenueOrigin": VENUE,
            "signedTextSha256": _sha(TEXT.encode())}


def sign_request(nonce="1"):
    now = datetime.now(UTC).replace(microsecond=0)
    core = {"assertionSchema": ASSERTION["schema"], "evidenceArtifactSha256": ASSERTION["evidenceArtifactSha256"],
            "nonce": nonce, "room": ROOM, "signedTextSha256": _sha(TEXT.encode()),
            "signerDid": DID, "venueOrigin": VENUE}
    operation = "w2op1-" + hashlib.sha256(b"BLACKBOX::W2::OPERATION::v1\0" + _canonical(core)).hexdigest()
    candidate = {"action": "CREATE_DETACHED_SIGNATURE_ONLY", "approvalExpiresAt": (now + timedelta(minutes=15)).isoformat().replace("+00:00", "Z"),
                 "approvalIssuedAt": now.isoformat().replace("+00:00", "Z"),
                 "evidenceArtifactSha256": ASSERTION["evidenceArtifactSha256"], "nonce": nonce,
                 "operationId": operation, "schema": "blackbox/w2-sign-approval/v1",
                 "signaturePreimageSha256": _sha(f"{ROOM}|{nonce}|{TEXT}".encode()),
                 "signedText": TEXT, "signedTextSha256": _sha(TEXT.encode()),
                 "signerDid": DID, "targetRoom": ROOM, "targetVenueOrigin": VENUE}
    approval_hash = _sha(b"BLACKBOX::W2::SIGN_APPROVAL::v1\0" + _canonical(candidate))
    return {"schema": "technocore-w2-sign-reserved-request/v1", "purpose": "W2_SIGN_EXACT_RESERVATION",
            "expectedCanonicalCommit": PIN, "requestId": REQUEST_ID, "profile": "default",
            "expectedSignerDid": DID, "approvalCandidate": candidate, "approvalHash": approval_hash}


def cancel_request(nonce="1"):
    return {**sign_request(nonce), "schema": "technocore-w2-cancel-reserved-request/v1",
            "purpose": "W2_CANCEL_EXACT_RESERVATION", "cancelReason": "CANCELLED"}


class FixtureApproval:
    def __init__(self, answer="correct"):
        self.answer = answer
        self.prompted = ""

    def attached(self):
        return True

    def prompt(self, text):
        self.prompted = text

    def read(self):
        if self.answer == "correct":
            return self.prompted.split("Type exactly: ")[1].splitlines()[0] + "\n"
        return "WRONG\n"


def test_fixture_bridge_reserves_then_signs_exact_nonce(tmp_path):
    reserve = reserve_once(reserve_request(), custody="fixture", state=tmp_path, actual_commit=PIN)
    assert reserve["nonce"] == "1" and reserve["state"] == "RESERVED"
    assert reserve["signerDid"] == DID
    store = NonceStore(TrustedPaths.under(tmp_path).nonces)
    assert store.get_w2(REQUEST_ID)["state"] == "RESERVED"
    approval = FixtureApproval()
    signed = sign_once(sign_request(), custody="fixture", state=tmp_path, actual_commit=PIN, approval=approval)
    assert signed["nonce"] == reserve["nonce"] and signed["did"] == DID
    assert store.get_w2(REQUEST_ID)["state"] == "SIGNED"
    assert "APPROVAL HASH" in approval.prompted and "SIGN W2 ONCE" in approval.prompted
    with pytest.raises(ValueError):
        sign_once(sign_request(), custody="fixture", state=tmp_path, actual_commit=PIN, approval=FixtureApproval())
    raw = (tmp_path / "nonces.json").read_text()
    assert "private" not in raw.lower() and "pairing" not in raw.lower()


def test_wrong_terminal_phrase_does_not_sign_but_nonce_stays_burned(tmp_path):
    reserve_once(reserve_request(), custody="fixture", state=tmp_path, actual_commit=PIN)
    with pytest.raises(PermissionError):
        sign_once(sign_request(), custody="fixture", state=tmp_path, actual_commit=PIN, approval=FixtureApproval("wrong"))
    store = NonceStore(TrustedPaths.under(tmp_path).nonces)
    assert store.get_w2(REQUEST_ID)["state"] == "RESERVED"
    second = {**reserve_request(), "requestId": "w2draft1-" + "2" * 64}
    assert reserve_once(second, custody="fixture", state=tmp_path, actual_commit=PIN)["nonce"] == "2"


@pytest.mark.parametrize("field,change", [
    ("nonce", "007"), ("targetRoom", "other-room"),
    ("targetVenueOrigin", "https://example.com"),
    ("signerDid", "did:key:z6Mk" + "1" * 44),
    ("signedText", TEXT + "x"),
    ("operationId", "w2op1-" + "c" * 64),
])
def test_sign_approval_tampering_refused_before_custody(field, change):
    request = sign_request()
    request["approvalCandidate"][field] = change
    with pytest.raises(ValueError):
        validate_sign_request(request)


def test_approval_hash_change_refused_before_custody():
    request = sign_request()
    request["approvalHash"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="approval hash"):
        validate_sign_request(request)


def test_expired_approval_refused_before_custody():
    request = sign_request()
    old = datetime.now(UTC) - timedelta(hours=2)
    request["approvalCandidate"]["approvalIssuedAt"] = old.isoformat().replace("+00:00", "Z")
    request["approvalCandidate"]["approvalExpiresAt"] = (old + timedelta(minutes=15)).isoformat().replace("+00:00", "Z")
    request["approvalHash"] = _sha(b"BLACKBOX::W2::SIGN_APPROVAL::v1\0" + _canonical(request["approvalCandidate"]))
    with pytest.raises(ValueError, match="expired"):
        validate_sign_request(request)


def test_expired_approval_marks_reservation_burned(tmp_path):
    reserve_once(reserve_request(), custody="fixture", state=tmp_path, actual_commit=PIN)
    request = sign_request()
    old = datetime.now(UTC) - timedelta(hours=2)
    request["approvalCandidate"]["approvalIssuedAt"] = old.isoformat().replace("+00:00", "Z")
    request["approvalCandidate"]["approvalExpiresAt"] = (old + timedelta(minutes=15)).isoformat().replace("+00:00", "Z")
    request["approvalHash"] = _sha(b"BLACKBOX::W2::SIGN_APPROVAL::v1\0" + _canonical(request["approvalCandidate"]))
    with pytest.raises(W2ApprovalExpiredError):
        sign_once(request, custody="fixture", state=tmp_path, actual_commit=PIN, approval=FixtureApproval())
    assert NonceStore(TrustedPaths.under(tmp_path).nonces).get_w2(REQUEST_ID)["state"] == "BURNED"


def test_request_has_no_private_or_pairing_material():
    for request in (reserve_request(), sign_request()):
        data = json.dumps(request)
        assert "privateKey" not in data and "pairingToken" not in data and "seed" not in data


def test_w2_real_provider_refuses_missing_identity_without_creating_one(tmp_path):
    protected_path = tmp_path / "identity.dpapi"
    with pytest.raises(FileNotFoundError):
        DPAPIKeyProvider(protected_path).load_existing()
    assert not protected_path.exists()


def test_cancel_bridge_burns_exact_reservation_without_sign_or_post(tmp_path, monkeypatch):
    reserve_once(reserve_request(), custody="fixture", state=tmp_path, actual_commit=PIN)
    def forbidden(*_args, **_kwargs):
        raise AssertionError("cancellation must not sign, allocate, or use transport")
    monkeypatch.setattr("technocore_agent.signer.service.Signer.sign_reserved_w2", forbidden)
    monkeypatch.setattr("technocore_agent.storage.nonce.NonceStore.reserve_w2", forbidden)
    first = cancel_once(cancel_request(), custody="fixture", state=tmp_path, actual_commit=PIN)
    assert first["state"] == "BURNED" and first["auditEvent"] == "CANCELED_BEFORE_SIGNING"
    assert cancel_once(cancel_request(), custody="fixture", state=tmp_path, actual_commit=PIN) == first
    store = NonceStore(TrustedPaths.under(tmp_path).nonces)
    assert store.get_w2(REQUEST_ID)["state"] == "BURNED"
    assert "private" not in json.dumps(first).lower() and "pairing" not in json.dumps(first).lower()


@pytest.mark.parametrize("field,change", [
    ("operationId", "w2op1-" + "9" * 64), ("nonce", "2"),
    ("signerDid", "did:key:z6Mk" + "1" * 44),
])
def test_cancel_bridge_rejects_wrong_operation_or_signer(field, change, tmp_path):
    reserve_once(reserve_request(), custody="fixture", state=tmp_path, actual_commit=PIN)
    request = cancel_request()
    request["approvalCandidate"][field] = change
    with pytest.raises(ValueError):
        validate_cancel_request(request)
    assert NonceStore(TrustedPaths.under(tmp_path).nonces).get_w2(REQUEST_ID)["state"] == "RESERVED"


def test_cancel_bridge_rejects_already_signed(tmp_path):
    reserve_once(reserve_request(), custody="fixture", state=tmp_path, actual_commit=PIN)
    sign_once(sign_request(), custody="fixture", state=tmp_path, actual_commit=PIN, approval=FixtureApproval())
    with pytest.raises(ValueError, match="crossed signing boundary"):
        cancel_once(cancel_request(), custody="fixture", state=tmp_path, actual_commit=PIN)
