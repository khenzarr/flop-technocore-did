from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_agent.signer.service import Signer
from technocore_agent.storage.nonce import NonceError, NonceStore

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
ROOM = "w2-fixture"
VENUE = "https://technocore.chat"
TEXT = 'blackbox-w2 {"assertionType":"W1_VALIDATION_RESULT"}'
TEXT_HASH = "sha256:" + hashlib.sha256(TEXT.encode()).hexdigest()
OPERATION_ID = "w2op1-" + "a" * 64
APPROVAL_HASH = "sha256:" + "b" * 64


def request_id(number: int) -> str:
    return f"w2draft1-{number:064x}"


def reserve(store: NonceStore, number: int, **changed) -> dict:
    values = {"request_id": request_id(number), "lane": ROOM,
              "signer_did": Signer(KEY, store).did, "venue_origin": VENUE,
              "text_sha256": TEXT_HASH}
    values.update(changed)
    return store.reserve_w2(**values)


def sign_reserved(store: NonceStore, reservation: dict, **changed):
    values = {"request_id": reservation["request_id"], "room": ROOM, "text": TEXT,
              "nonce": reservation["nonce"], "expected_did": reservation["signer_did"],
              "venue_origin": VENUE, "operation_id": OPERATION_ID,
              "approval_hash": APPROVAL_HASH}
    values.update(changed)
    return Signer(KEY, store).sign_reserved_w2(**values)


def bound(reservation: dict, **changed) -> dict:
    values = {"request_id": reservation["request_id"], "lane": ROOM,
              "signer_did": reservation["signer_did"], "venue_origin": VENUE,
              "text_sha256": TEXT_HASH, "nonce": reservation["nonce"],
              "operation_id": OPERATION_ID, "approval_hash": APPROVAL_HASH}
    values.update(changed)
    return values


def test_reserve_without_signing_is_durable_and_restart_safe(tmp_path):
    path = tmp_path / "nonce.json"
    store = NonceStore(path)
    first = reserve(store, 1)
    assert first["nonce"] == "1" and first["state"] == "RESERVED"
    assert first == NonceStore(path).get_w2(request_id(1))
    assert reserve(NonceStore(path), 1) == first
    assert reserve(NonceStore(path), 2)["nonce"] == "2"
    data = json.loads(path.read_text())
    assert data["counters"][ROOM] == 2
    assert "private" not in json.dumps(data).lower()
    assert "pairing" not in json.dumps(data).lower()
    with pytest.raises(NonceError):
        reserve(NonceStore(path), 1, venue_origin="https://example.com")


def test_concurrent_w2_reservations_are_unique(tmp_path):
    path = tmp_path / "nonce.json"
    with ThreadPoolExecutor(max_workers=12) as pool:
        values = list(pool.map(lambda number: reserve(NonceStore(path), number)["nonce"], range(1, 25)))
    assert sorted(map(int, values)) == list(range(1, 25))


def test_terminal_generation_retry_preserves_history_and_active_idempotency(tmp_path):
    path = tmp_path / "nonce.json"
    store = NonceStore(path)
    first = reserve(store, 1)
    assert first["nonce"] == "1" and first["generation"] == 1
    burned = store.cancel_w2(**bound(first))
    second = reserve(NonceStore(path), 1)
    assert second["request_id"] == first["request_id"]
    assert second["nonce"] == "2" and second["generation"] == 2
    assert reserve(NonceStore(path), 1) == second
    assert NonceStore(path).get_w2_history(first["request_id"]) == [burned]
    data = json.loads(path.read_text())
    assert data["counters"][ROOM] == 2


def test_active_generation_signs_and_stale_burned_generation_is_refused(tmp_path):
    store = NonceStore(tmp_path / "nonce.json")
    first = reserve(store, 1)
    store.cancel_w2(**bound(first))
    second = reserve(store, 1)
    store.approve_w2(**bound(second))
    with pytest.raises(NonceError):
        sign_reserved(store, first)
    signed = sign_reserved(store, second)
    assert str(signed.nonce) == "2"
    assert store.get_w2_history(first["request_id"])[0]["state"] == "BURNED"


def test_expired_generation_advances_and_parallel_duplicates_allocate_once(tmp_path):
    path = tmp_path / "nonce.json"
    first = reserve(NonceStore(path), 1)
    NonceStore(path).cancel_w2(**bound(first), reason="EXPIRED")
    with ThreadPoolExecutor(max_workers=12) as pool:
        values = list(pool.map(lambda _value: reserve(NonceStore(path), 1), range(24)))
    assert {item["nonce"] for item in values} == {"2"}
    assert {item["generation"] for item in values} == {2}
    data = json.loads(path.read_text())
    assert data["counters"][ROOM] == 2
    assert data["w2_reservation_history"][first["request_id"]][0]["burn_reason"] == "EXPIRED"


def test_reserved_w2_uses_exact_nonce_and_will_not_sign_again(tmp_path):
    path = tmp_path / "nonce.json"
    reserved = reserve(NonceStore(path), 1)
    NonceStore(path).approve_w2(**bound(reserved))
    signed = sign_reserved(NonceStore(path), reserved)
    assert str(signed.nonce) == reserved["nonce"]
    assert signed.did == reserved["signer_did"]
    KEY.public_key().verify(__import__("base64").urlsafe_b64decode(signed.signature + "=="),
                            f"{ROOM}|{reserved['nonce']}|{TEXT}".encode())
    assert NonceStore(path).get_w2(request_id(1))["state"] == "SIGNED"
    with pytest.raises(NonceError):
        sign_reserved(NonceStore(path), reserved)
    assert reserve(NonceStore(path), 2)["nonce"] == "2"


@pytest.mark.parametrize("changed", [
    {"room": "other-room"}, {"nonce": "007"}, {"nonce": "2"},
    {"venue_origin": "https://example.com"}, {"text": TEXT + "x"},
    {"expected_did": "did:key:z6Mk" + "1" * 44},
])
def test_mismatch_never_signs_or_consumes_another_nonce(tmp_path, changed):
    store = NonceStore(tmp_path / "nonce.json")
    reserved = reserve(store, 1)
    store.approve_w2(**bound(reserved))
    with pytest.raises((NonceError, ValueError)):
        sign_reserved(store, reserved, **changed)
    assert store.get_w2(request_id(1))["state"] == "APPROVED"
    assert reserve(store, 2)["nonce"] == "2"


def test_cancel_and_expiry_burn_without_reuse(tmp_path):
    store = NonceStore(tmp_path / "nonce.json")
    first = reserve(store, 1)
    assert store.burn_w2(first["request_id"], "CANCELLED")["state"] == "BURNED"
    with pytest.raises(NonceError):
        sign_reserved(store, first)
    second = reserve(store, 2)
    assert store.burn_w2(second["request_id"], "EXPIRED")["state"] == "BURNED"
    assert reserve(store, 3)["nonce"] == "3"


def test_above_2_pow_53_is_exact_and_sign_failure_burns(tmp_path):
    path = tmp_path / "nonce.json"
    store = NonceStore(path)
    store._write_reservation_state({"version": 1, "counters": {ROOM: 9007199254740992}, "requests": {}})
    reserved = reserve(store, 1)
    assert reserved["nonce"] == "9007199254740993"

    class BrokenKey:
        def public_key(self):
            return KEY.public_key()

        def sign(self, _message):
            raise RuntimeError("fixture signing failure")

    with pytest.raises(RuntimeError):
        store.approve_w2(**bound(reserved))
        Signer(BrokenKey(), store).sign_reserved_w2(
            request_id=reserved["request_id"], room=ROOM, text=TEXT,
            nonce=reserved["nonce"], expected_did=reserved["signer_did"],
            venue_origin=VENUE, operation_id=OPERATION_ID,
            approval_hash=APPROVAL_HASH)
    assert store.get_w2(request_id(1))["state"] == "SIGNING_OUTCOME_UNCERTAIN"
    assert reserve(store, 2)["nonce"] == "9007199254740994"


@pytest.mark.parametrize("approved", [False, True])
def test_exact_cancel_is_durable_idempotent_and_never_reuses_nonce(tmp_path, approved):
    path = tmp_path / "nonce.json"
    store = NonceStore(path)
    first = reserve(store, 1)
    if approved:
        store.approve_w2(**bound(first))
    before = path.read_bytes()
    canceled = store.cancel_w2(**bound(first))
    assert canceled["state"] == "BURNED"
    assert canceled["audit_event"] == "CANCELED_BEFORE_SIGNING"
    after = path.read_bytes()
    assert before != after
    assert NonceStore(path).cancel_w2(**bound(first)) == canceled
    assert path.read_bytes() == after
    assert NonceStore(path).get_w2(first["request_id"]) == canceled
    with pytest.raises(NonceError):
        sign_reserved(store, first)
    assert reserve(NonceStore(path), 2)["nonce"] == "2"


@pytest.mark.parametrize("changed", [
    {"request_id": request_id(9)}, {"operation_id": "w2op1-" + "9" * 64},
    {"signer_did": "did:key:z6Mk" + "1" * 44}, {"nonce": "2"},
    {"approval_hash": "sha256:" + "9" * 64}, {"venue_origin": "https://example.com"},
])
def test_cancel_wrong_binding_rejected_without_mutation(tmp_path, changed):
    store = NonceStore(tmp_path / "nonce.json")
    first = reserve(store, 1)
    store.approve_w2(**bound(first))
    before = store.path.read_bytes()
    with pytest.raises(NonceError):
        store.cancel_w2(**bound(first, **changed))
    assert store.path.read_bytes() == before


def test_cancel_after_signing_or_submitting_is_refused(tmp_path):
    store = NonceStore(tmp_path / "nonce.json")
    first = reserve(store, 1)
    store.approve_w2(**bound(first))
    sign_reserved(store, first)
    with pytest.raises(NonceError, match="crossed signing boundary"):
        store.cancel_w2(**bound(first))
    # The trusted signer does not submit. A submitted W2 is necessarily already SIGNED.
    assert store.get_w2(first["request_id"])["state"] == "SIGNED"


def test_corrupt_w2_reservation_blocks_new_allocation(tmp_path):
    path = tmp_path / "nonce.json"
    first = reserve(NonceStore(path), 1)
    data = json.loads(path.read_text())
    data["w2_reservations"][first["request_id"]]["nonce"] = "007"
    path.write_text(json.dumps(data))
    with pytest.raises(NonceError, match="corrupt"):
        reserve(NonceStore(path), 2)
