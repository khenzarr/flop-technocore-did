from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..evidence.contribution import create_contribution_proof
from ..storage.nonce import NonceStore
from .canonical import canonical_message

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def canonical_did(key: Ed25519PrivateKey) -> str:
    """Return the upstream Technocore Ed25519 ``did:key`` representation."""
    raw = b"\xed\x01" + key.public_key().public_bytes_raw()
    number = int.from_bytes(raw, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = _B58[remainder] + encoded
    return "did:key:z" + ("1" * (len(raw) - len(raw.lstrip(b"\0"))) + encoded)


if TYPE_CHECKING:
    from ..control.approval import Approval


@dataclass(frozen=True, slots=True)
class SignedOperation:
    did: str
    room: str
    nonce: int
    signature: str
    text: str


class Signer:
    def __init__(
        self,
        key: Ed25519PrivateKey,
        nonces: NonceStore,
        operations=None,
        transport=None,
        ledger=None,
        approvals=None,
    ) -> None:
        self._key, self._nonces = key, nonces
        self._operations, self._transport, self._ledger = operations, transport, ledger
        self._approvals = approvals
        self.did = canonical_did(key)

    def sign_room(self, room: str, text: str) -> SignedOperation:
        cleaned = canonical_message(room, 1, text).rsplit("|", 1)[1]
        nonce = self._nonces.reserve(room)
        return self._sign_with_nonce(room, cleaned, nonce)

    def sign_room_detached(self, room: str, text: str) -> SignedOperation:
        """Sign a room operation and return it without contacting Technocore.

        Reservation is durable and consumed even when the returned operation is never
        submitted.  This method intentionally has no operation-store or transport path.
        """
        cleaned = canonical_message(room, 1, text).rsplit("|", 1)[1]
        nonce = self._nonces.reserve(room)
        return self._sign_with_nonce(room, cleaned, nonce)

    def create_contribution_proof(self, artifact_url: str, commit: str) -> dict[str, str]:
        return create_contribution_proof(self._key, self.did, artifact_url, commit)

    def execute_room(self, request_id: str, room: str, text: str, approval: Approval) -> dict:
        if self._approvals is None:
            raise ValueError("trusted approval store is not configured")
        self._approvals.validate_consumed(approval)
        if approval.draft_id != request_id or approval.draft_fingerprint != self._fingerprint(
            room, text
        ):
            raise ValueError("approval does not bind to this exact operation")
        if self._operations is None or self._transport is None:
            raise ValueError("durable operation service is not configured")
        cleaned = canonical_message(room, 1, text).rsplit("|", 1)[1]
        text_hash = hashlib.sha256(cleaned.encode()).hexdigest()
        record = self._operations.create(request_id, room, text_hash, operation="sign_room")
        if record["state"] in {
            "UNKNOWN",
            "SUBMISSION_STARTED",
            "ACCEPTED",
            "RECONCILED",
            "FAILED_FINAL",
        }:
            return record
        if record["state"] == "SIGNED":
            # A crash after signing but before durable submission-start cannot be
            # distinguished from a crash before sending. Never resubmit implicitly.
            return record
        nonce = record["nonce"]
        if nonce is None:
            nonce = self._nonces.reserve(room, request_id)
            record = self._operations.bind_nonce(request_id, nonce)
        signed = self._sign_with_nonce(room, cleaned, nonce)
        record = self._operations.update(request_id, signature=signed.signature)
        self._operations.transition(request_id, "SIGNED")
        self._operations.transition(request_id, "SUBMISSION_STARTED")
        outcome = self._transport.submit(signed)
        outcome_status = outcome.status if hasattr(outcome, "status") else outcome
        receipt = outcome.receipt if hasattr(outcome, "receipt") else None
        state = {"accepted": "ACCEPTED", "rejected": "FAILED_FINAL", "unknown": "UNKNOWN"}.get(
            outcome_status
        )
        if state is None:
            state = "FAILED_FINAL"
        record = self._operations.transition(request_id, state, receipt=receipt)
        self._append_evidence(record, room, cleaned)
        return record

    def reconcile_room(self, request_id: str) -> dict:
        if self._operations is None or self._transport is None:
            raise ValueError("durable operation service is not configured")
        record = self._operations.get(request_id)
        if record is None or record["state"] != "UNKNOWN":
            return record
        outcome = self._transport.reconcile(record)
        outcome_status = outcome.status if hasattr(outcome, "status") else outcome
        receipt = outcome.receipt if hasattr(outcome, "receipt") else None
        if outcome_status == "accepted":
            record = self._operations.transition(request_id, "RECONCILED", receipt=receipt)
        elif outcome_status == "rejected":
            record = self._operations.transition(request_id, "FAILED_FINAL")
        if record is not None and record["state"] in {"RECONCILED", "FAILED_FINAL"}:
            self._append_evidence(record, record["lane"], "")
        return record

    def operation_record(self, request_id: str) -> dict | None:
        if self._operations is None:
            return None
        return self._operations.get(request_id)

    def _sign_with_nonce(self, room: str, text: str, nonce: int) -> SignedOperation:
        message = canonical_message(room, nonce, text)
        signature = base64.urlsafe_b64encode(self._key.sign(message.encode())).decode().rstrip("=")
        return SignedOperation(self.did, room, nonce, signature, text)

    def _append_evidence(self, record: dict, room: str, text: str) -> None:
        if self._ledger is not None and record["state"] in {
            "ACCEPTED",
            "RECONCILED",
            "FAILED_FINAL",
        }:
            stored_receipt = record.get("receipt")
            receipt: dict = stored_receipt if isinstance(stored_receipt, dict) else {}
            self._ledger.append(
                public_did=self.did,
                room=room,
                nonce=record["nonce"],
                text=text,
                result_class=record["state"].lower(),
                request_id=record["request_id"],
                reconciliation_status=record["state"].lower(),
                text_hash=record["text_hash"],
                server_sequence=receipt.get("seq"),
                server_timestamp=receipt.get("ts"),
            )

    @staticmethod
    def _fingerprint(room: str, text: str) -> str:
        from ..control.drafts import draft_fingerprint

        return draft_fingerprint("sign_room", room, text)
