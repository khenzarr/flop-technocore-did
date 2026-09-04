from __future__ import annotations

import base64
import hashlib
import io
import json
import subprocess
import sys
from typing import cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_agent.control import ApprovalStore, DraftStore
from technocore_agent.evidence.ledger import Ledger, LedgerError
from technocore_agent.ipc.subprocess_broker import serve_once
from technocore_agent.policy.transport import RecordingTransport, SubmissionResult
from technocore_agent.signer import Signer
from technocore_agent.signer.canonical import canonical_message
from technocore_agent.storage import dpapi
from technocore_agent.storage.nonce import NonceError, NonceStore, OperationStore


def _key():
    return Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


def _service(tmp_path, mode="accepted", ledger=None):
    outcomes = []
    transport = RecordingTransport(outcomes, mode)
    approvals = ApprovalStore(tmp_path / "approvals.json")
    service = Signer(
        _key(),
        NonceStore(tmp_path / "nonces.json"),
        OperationStore(tmp_path / "operations.json"),
        transport,
        ledger,
        approvals,
    )
    return service, outcomes


def _approval(tmp_path, request_id="request", room="room", text="hello"):
    drafts, approvals = (
        DraftStore(tmp_path / "drafts.json"),
        ApprovalStore(tmp_path / "approvals.json"),
    )
    draft = drafts.create(request_id, "sign_room", room, text, "test")
    approval = approvals.for_draft(draft.draft_id)
    if draft.status == "PENDING":
        approval = approval or approvals.create(draft, "test-session-hash")
        draft = drafts.transition(draft.draft_id, "APPROVED")
    assert approval is not None
    if approval.status == "APPROVED":
        approval = approvals.consume(approval.approval_id, draft)
    return approval


def _execute(service, approval, room="room", text="hello"):
    return service.execute_room(approval.draft_id, room, text, approval)


class _UnreachableTransport:
    def __init__(self):
        self.calls = 0

    def submit(self, _operation):
        self.calls += 1
        raise AssertionError("detached signing must not submit")


def test_detached_room_signing_returns_verified_operation_and_consumes_nonce(tmp_path):
    transport = _UnreachableTransport()
    service = Signer(_key(), NonceStore(tmp_path / "nonces.json"), transport=transport)
    first = service.sign_room_detached("room", "  hello\u200b  ")
    second = service.sign_room_detached("room", "next")

    assert first.room == second.room == "room"
    assert first.text == "hello"
    assert (first.nonce, second.nonce) == (1, 2)
    public = _key().public_key()
    public.verify(
        base64.urlsafe_b64decode(first.signature + "=="),
        canonical_message(first.room, first.nonce, first.text).encode(),
    )
    assert transport.calls == 0
    assert json.loads((tmp_path / "nonces.json").read_text())["counters"]["room"] == 2


def test_detached_concurrent_signers_reserve_distinct_nonces(tmp_path):
    path = tmp_path / "nonces.json"
    code = (
        "from pathlib import Path; from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; "
        "from technocore_agent.signer import Signer; from technocore_agent.storage.nonce import NonceStore; "
        "import sys; print(Signer(Ed25519PrivateKey.from_private_bytes(bytes(range(32))), NonceStore(Path(sys.argv[1]))).sign_room_detached('room', 'text').nonce)"
    )
    processes = [
        subprocess.Popen([sys.executable, "-c", code, str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(8)
    ]
    results = []
    for process in processes:
        stdout, stderr = process.communicate(timeout=20)
        assert process.returncode == 0, stderr
        results.append(int(stdout.strip()))
    assert sorted(results) == list(range(1, 9))


def test_detached_validation_and_signing_failures_consume_no_or_one_nonce(tmp_path):
    service = Signer(_key(), NonceStore(tmp_path / "nonces.json"))
    with pytest.raises(ValueError):
        service.sign_room_detached("bad|room", "hello")
    assert not (tmp_path / "nonces.json").exists()

    class BrokenKey:
        def public_key(self):
            return _key().public_key()

        def sign(self, _message):
            raise RuntimeError("fixture signing failure")

    broken = Signer(cast(Ed25519PrivateKey, BrokenKey()), NonceStore(tmp_path / "broken.json"))
    with pytest.raises(RuntimeError, match="fixture signing failure"):
        broken.sign_room_detached("room", "hello")
    assert NonceStore(tmp_path / "broken.json").reserve("room", "next") == 2


def test_nonce_request_reservation_is_one_atomic_document(tmp_path):
    path = tmp_path / "nonces.json"
    store = NonceStore(path)
    assert store.reserve("room", "request-a") == 1
    state = json.loads(path.read_text(encoding="utf-8"))
    assert state == {
        "version": 1,
        "counters": {"room": 1},
        "requests": {"request-a": {"lane": "room", "nonce": 1}},
    }
    assert NonceStore(path).reserve("room", "request-a") == 1
    assert NonceStore(path).reserve("room", "request-b") == 2
    with pytest.raises(NonceError):
        NonceStore(path).reserve("other", "request-a")


@pytest.mark.parametrize("bad", [b"{", b"[]", b'{"version":1,"counters":{},"requests":[]}'])
def test_nonce_load_failure_releases_os_lock(tmp_path, bad):
    path = tmp_path / "nonces.json"
    path.write_bytes(bad)
    with pytest.raises(NonceError):
        NonceStore(path).reserve("room", "request")
    path.unlink()
    assert NonceStore(path).reserve("room", "request") == 1


def test_nonce_injected_failure_releases_os_lock(tmp_path):
    path = tmp_path / "nonces.json"

    def fault(point):
        if point == "during_temp_write":
            raise OSError("injected")

    with pytest.raises(NonceError):
        NonceStore(path, fault=fault).reserve("room", "request")
    assert NonceStore(path).reserve("room", "request") == 1


@pytest.mark.parametrize(
    ("mode", "state"),
    [
        ("pre_send_failure", "FAILED_FINAL"),
        ("definite_rejection", "FAILED_FINAL"),
        ("accepted", "ACCEPTED"),
        ("accepted_response_lost", "UNKNOWN"),
        ("timeout_unknown", "UNKNOWN"),
    ],
)
def test_submission_outcomes_are_durable_and_idempotent(tmp_path, mode, state):
    service, outcomes = _service(tmp_path, mode)
    approval = _approval(tmp_path)
    first = _execute(service, approval)
    assert first["state"] == state
    submission_count = outcomes.count("submitted")
    restarted, restarted_outcomes = _service(tmp_path, mode)
    second = _execute(restarted, approval)
    assert second["state"] == state
    assert second["nonce"] == first["nonce"] == 1
    assert restarted_outcomes.count("submitted") == 0
    assert outcomes.count("submitted") == submission_count


def test_exact_server_receipt_is_committed_with_acceptance_and_evidence(tmp_path):
    receipt: dict[str, object] = {
        "room": "room",
        "seq": 91,
        "ts": "2026-08-28T12:52:29.000000+00:00",
        "from": "did:key:z6MkReceiptTest",
        "nonce": 1,
        "text": "hello",
    }

    class ReceiptTransport:
        def submit(self, _operation):
            return SubmissionResult("accepted", receipt)

    approvals = ApprovalStore(tmp_path / "approvals.json")
    ledger = Ledger(tmp_path / "evidence.jsonl")
    service = Signer(
        _key(),
        NonceStore(tmp_path / "nonces.json"),
        OperationStore(tmp_path / "operations.json"),
        ReceiptTransport(),
        ledger,
        approvals,
    )
    approval = _approval(tmp_path)
    result = _execute(service, approval)
    assert result["state"] == "ACCEPTED" and result["receipt"] == receipt
    stored = OperationStore(tmp_path / "operations.json").get(approval.draft_id)
    assert stored is not None and stored["receipt"] == receipt
    evidence = ledger.read()[-1]
    assert evidence["server_sequence"] == 91
    assert evidence["server_timestamp"] == receipt["ts"]


def test_request_id_conflict_matrix(tmp_path):
    service, _ = _service(tmp_path)
    approval = _approval(tmp_path)
    _execute(service, approval)
    for room, text in (("room", "different"), ("different", "hello")):
        with pytest.raises(ValueError, match="approval does not bind"):
            _execute(service, approval, room, text)
    store = OperationStore(tmp_path / "operations.json")
    with pytest.raises(NonceError):
        store.create(
            approval.draft_id, "room", hashlib.sha256(b"hello").hexdigest(), operation="other"
        )


def test_signed_restart_is_never_automatically_submitted(tmp_path):
    approval = _approval(tmp_path)
    store = OperationStore(tmp_path / "operations.json")
    digest = hashlib.sha256(b"hello").hexdigest()
    store.create(approval.draft_id, "room", digest, 1)
    store.update(approval.draft_id, signature="non-secret-signature")
    store.transition(approval.draft_id, "SIGNED")
    service, outcomes = _service(tmp_path)
    record = _execute(service, approval)
    assert record["state"] == "SIGNED"
    assert outcomes == []


@pytest.mark.parametrize(
    ("mode", "state"),
    [
        ("reconcile_accepted", "RECONCILED"),
        ("reconcile_rejected", "FAILED_FINAL"),
        ("reconcile_unknown", "UNKNOWN"),
    ],
)
def test_unknown_reconciliation_persists_and_keeps_original_hash(tmp_path, mode, state):
    ledger = Ledger(tmp_path / "evidence.jsonl")
    service, _ = _service(tmp_path, "timeout_unknown", ledger)
    approval = _approval(tmp_path)
    original = _execute(service, approval)
    expected_hash = original["text_hash"]
    restarted, outcomes = _service(tmp_path, mode, ledger)
    assert _execute(restarted, approval)["state"] == "UNKNOWN"
    assert outcomes == []
    resolved = restarted.reconcile_room(approval.draft_id)
    assert resolved["state"] == state
    stored = OperationStore(tmp_path / "operations.json").get(approval.draft_id)
    assert stored is not None and stored["state"] == state
    if state != "UNKNOWN":
        assert ledger.read()[-1]["text_hash"] == expected_hash


class _FailingLedger:
    def append(self, **kwargs):
        raise LedgerError("injected evidence failure")


def test_evidence_failure_does_not_redefine_accepted_truth(tmp_path):
    service, outcomes = _service(tmp_path, ledger=_FailingLedger())
    approval = _approval(tmp_path)
    with pytest.raises(LedgerError):
        _execute(service, approval)
    assert outcomes.count("submitted") == 1
    stored = OperationStore(tmp_path / "operations.json").get(approval.draft_id)
    assert stored is not None and stored["state"] == "ACCEPTED"
    restarted, restarted_outcomes = _service(tmp_path, ledger=_FailingLedger())
    assert _execute(restarted, approval)["state"] == "ACCEPTED"
    assert restarted_outcomes == []


def test_process_level_nonce_coordination(tmp_path):
    path = tmp_path / "process-nonces.json"
    code = (
        "from pathlib import Path; from technocore_agent.storage.nonce import NonceStore; "
        "import sys; print(NonceStore(Path(sys.argv[1])).reserve('room', sys.argv[2]))"
    )
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", code, str(path), f"request-{index}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for index in range(12)
    ]
    results = []
    for process in processes:
        stdout, stderr = process.communicate(timeout=20)
        assert process.returncode == 0, stderr
        results.append(int(stdout.strip()))
    assert sorted(results) == list(range(1, 13))
    state = json.loads(path.read_text(encoding="utf-8"))
    assert state["counters"]["room"] == 12
    assert len(state["requests"]) == 12


def test_secretless_subprocess_broker_schema_and_safe_response():
    valid = {
        "operation": "sign_room",
        "room": "room",
        "text": "text",
        "request_id": "request",
    }
    source, destination = io.BytesIO(json.dumps(valid).encode() + b"\n"), io.BytesIO()
    serve_once(source, destination, lambda request: {"state": "ACCEPTED", "nonce": 1})
    assert json.loads(destination.getvalue()) == {"nonce": 1, "state": "ACCEPTED"}
    for invalid in (
        b"not-json\n",
        json.dumps({**valid, "operation": "unknown"}).encode() + b"\n",
        json.dumps({**valid, "unknown": True}).encode() + b"\n",
        json.dumps({**valid, "approved": True}).encode() + b"\n",
        json.dumps({**valid, "private_key": "forbidden"}).encode() + b"\n",
    ):
        output = io.BytesIO()
        serve_once(io.BytesIO(invalid), output, lambda request: {"state": "ACCEPTED"})
        assert "error" in json.loads(output.getvalue())


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows DPAPI proof")
def test_dpapi_invalid_inputs_fail_closed():
    for value in (b"", "not-bytes", None):
        invalid = cast(bytes, value)
        with pytest.raises(dpapi.DPAPIError):
            dpapi.protect(invalid)
        with pytest.raises(dpapi.DPAPIError):
            dpapi.unprotect(invalid)
