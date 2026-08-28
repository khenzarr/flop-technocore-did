from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..control.approval import ApprovalStore
from ..control.drafts import DraftStore
from ..control.operator import OperatorAuth
from ..control.service import ControlPlane
from ..evidence.ledger import Ledger
from ..policy.transport import RecordingTransport
from ..signer.service import Signer
from ..storage import dpapi
from ..storage.nonce import NonceStore, OperationStore
from .proof import (
    PROOF_SCHEMA,
    ProofModeError,
    dpapi_round_trip,
    local_process_metadata,
    proof_enabled,
    sanitize_diagnostics,
)
from .windows_diagnostics import current_process_token_evidence


@dataclass(frozen=True, slots=True)
class TrustedPaths:
    root: Path
    drafts: Path
    approvals: Path
    operations: Path
    nonces: Path
    evidence: Path
    operator: Path
    protected_key: Path

    @classmethod
    def under(cls, root: Path) -> TrustedPaths:
        root = Path(root).resolve()
        return cls(
            root,
            root / "drafts.json",
            root / "approvals.json",
            root / "operations.json",
            root / "nonces.json",
            root / "evidence.jsonl",
            root / "operator.json",
            root / "identity.dpapi",
        )


class DPAPIKeyProvider:
    """Ed25519 key lifecycle bound to the Windows identity running the service."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def load_or_create(self) -> Ed25519PrivateKey:
        if self.path.exists():
            raw = dpapi.load(self.path)
        else:
            key = Ed25519PrivateKey.generate()
            raw = key.private_bytes_raw()
            dpapi.save(self.path, raw)
        try:
            return Ed25519PrivateKey.from_private_bytes(raw)
        finally:
            # Python cannot guarantee zeroization; minimize the plaintext lifetime.
            del raw


# Compatibility name retained for the frozen offline proof and its tests.
DPAPITestKeyProvider = DPAPIKeyProvider


class TrustedRuntime:
    """The sole runtime owner of trusted stores, authentication, key, and signer."""

    def __init__(self, paths: TrustedPaths, key_provider, *, transport=None) -> None:
        self.paths = paths
        paths.root.mkdir(parents=True, exist_ok=True)
        self.drafts = DraftStore(paths.drafts)
        self._approvals = ApprovalStore(paths.approvals)
        self._operations = OperationStore(paths.operations)
        self._nonces = NonceStore(paths.nonces)
        self._ledger = Ledger(paths.evidence)
        self.auth = OperatorAuth(paths.operator)
        self._transport = transport or RecordingTransport([])
        key = key_provider.load_or_create()
        self._signer = Signer(
            key,
            self._nonces,
            self._operations,
            self._transport,
            self._ledger,
            self._approvals,
        )
        bind_did = getattr(self._transport, "bind_did", None)
        if bind_did is not None:
            bind_did(self._signer.did)
        self._dpapi_proof: dict[str, object] | None = None
        if proof_enabled(paths.root):
            # The trusted service performs this once; IPC only exposes the cached result.
            self._dpapi_proof = dpapi_round_trip(paths.root / "stage2d-proof-dpapi.blob")
        self.control = ControlPlane(
            self.drafts,
            self._approvals,
            self.auth,
            self._signer,
            mode="live" if type(self._transport).__name__ == "TechnocoreTransport" else "offline",
        )

    def proof_status(self, expected_service_sid: str | None = None) -> dict:
        """Return only non-secret evidence, and only for an installer marker."""
        if not proof_enabled(self.paths.root):
            raise ProofModeError("Stage2D proof mode is not enabled by trusted configuration")
        operations = self._operations._read()
        evidence = self._ledger.read()
        drafts = self.drafts.list()
        if expected_service_sid is None:
            raise ProofModeError("expected service SID is required for token validation")
        identity = current_process_token_evidence(expected_service_sid)
        result = {
            "schema": PROOF_SCHEMA,
            "mode": "TEST/OFFLINE",
            "transport": type(self._transport).__name__,
            **local_process_metadata(),
            "public_did": self.public_did,
            "trusted_state_path": str(self.paths.root),
            **identity,
            "draft_count": len(drafts),
            "operation_count": len(operations),
            "submission_count": getattr(self._transport, "submission_count", 0),
            "evidence_count": len(evidence),
            "drafts": [
                {"draft_id": d.draft_id, "request_id": d.external_request_id, "status": d.status}
                for d in drafts
            ],
            "operations": [
                {"request_id": k, "state": v.get("state"), "nonce": v.get("nonce")}
                for k, v in operations.items()
            ],
            "dpapi": self._dpapi_proof,
        }
        return sanitize_diagnostics(result)

    def run_dpapi_proof(self) -> dict:
        raise ProofModeError("caller-triggered DPAPI proof is not allowed")

    @property
    def public_did(self) -> str:
        return self._signer.did

    def handle_agent_request(self, item: dict[str, str]) -> dict:
        operation, request_id = item["operation"], item["request_id"]
        if operation == "submit_draft":
            draft = self.drafts.create(
                request_id,
                "sign_room",
                item["room"],
                item["text"],
                "untrusted-agent-ipc",
            )
            return {
                "draft_id": draft.draft_id,
                "request_id": draft.external_request_id,
                "status": draft.status,
            }
        if operation == "get_own_draft_status":
            matches = [
                draft for draft in self.drafts.list() if draft.external_request_id == request_id
            ]
            if not matches:
                return {"request_id": request_id, "status": "NOT_FOUND"}
            draft = matches[0]
            return {
                "draft_id": draft.draft_id,
                "request_id": draft.external_request_id,
                "status": draft.status,
            }
        raise ValueError("operation is not allowed")
