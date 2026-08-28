"""Read-only, fail-closed Stage 2D proof support.

This module deliberately has no approval, signing, or state-selection API.  The
marker is provisioned by the trusted installer; a request cannot enable proof
mode.
"""

from __future__ import annotations

import json
import os
import platform
import socketserver
import sys
from pathlib import Path
from typing import Any, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..signer.service import canonical_did
from ..storage import dpapi

PROOF_SCHEMA = "stage2d-proof-status-v1"
PROOF_MARKER = "stage2d-proof-enabled.json"
_PUBLIC_FIELDS = frozenset(
    {
        "schema",
        "mode",
        "transport",
        "pid",
        "architecture",
        "executable_path",
        "service_account",
        "service_sid",
        "integrity_level",
        "public_did",
        "draft_count",
        "operation_count",
        "submission_count",
        "evidence_count",
        "drafts",
        "operations",
        "dpapi",
        "trusted_state_path",
        "account_name",
        "account_sid",
        "expected_service_sid",
        "service_sid_present",
        "test_offline",
    }
)


class ProofModeError(RuntimeError):
    pass


def proof_enabled(root: Path) -> bool:
    """Only trusted on-disk configuration can enable this contract."""
    marker = Path(root) / PROOF_MARKER
    try:
        return marker.is_file() and marker.read_text(encoding="utf-8").strip() == PROOF_SCHEMA
    except OSError:
        return False


def dpapi_round_trip(path: Path) -> dict[str, object]:
    """Perform a disposable proof and never include key/blob bytes."""
    path = Path(path)
    key = Ed25519PrivateKey.generate()
    did_a = canonical_did(key)
    raw = key.private_bytes_raw()
    try:
        dpapi.save(path, raw)
        reloaded = Ed25519PrivateKey.from_private_bytes(dpapi.load(path))
        did_b = canonical_did(reloaded)
    finally:
        del raw, key
    return {
        "did_a": did_a,
        "did_b": did_b,
        "equal": did_a == did_b,
        "protected_test_blob_path": str(path),
        "status": "PASS" if did_a == did_b else "FAIL",
    }


def initialize_proof_result(root: Path) -> dict[str, object]:
    """Create the disposable proof once during trusted service startup."""
    return dpapi_round_trip(Path(root) / "stage2d-proof-dpapi.blob")


def sanitize_diagnostics(value: dict) -> dict:
    """Defence-in-depth allowlist for responses crossing the proof IPC."""
    result = {key: value[key] for key in _PUBLIC_FIELDS if key in value}
    if "dpapi" in result and isinstance(result["dpapi"], dict):
        result["dpapi"] = {
            key: result["dpapi"][key]
            for key in ("did_a", "did_b", "equal", "protected_test_blob_path", "status")
            if key in result["dpapi"]
        }
    return result


def local_process_metadata() -> dict[str, object]:
    return {
        "pid": os.getpid(),
        "architecture": platform.machine(),
        "executable_path": str(Path(os.path.abspath(sys.executable))),
        "test_offline": True,
    }


def validate_service_identity_evidence(value: dict[str, object]) -> dict[str, object]:
    """Validate the safe identity contract without trusting account names."""
    required = {
        "account_name",
        "account_sid",
        "expected_service_sid",
        "service_sid_present",
        "pid",
        "architecture",
        "executable_path",
        "trusted_state_path",
        "test_offline",
        "transport",
    }
    missing = sorted(required.difference(value))
    if missing:
        raise ProofModeError(f"service identity evidence is incomplete: {', '.join(missing)}")
    if not isinstance(value["service_sid_present"], bool):
        raise ProofModeError("service SID membership must be a boolean")
    if value["transport"] != "RecordingTransport" or value["test_offline"] is not True:
        raise ProofModeError("service proof must use TEST/OFFLINE RecordingTransport")
    return sanitize_diagnostics(value)


def decode_proof_request(raw: bytes) -> dict[str, str]:
    if not isinstance(raw, bytes) or len(raw) > 4096:
        raise ProofModeError("proof request is invalid")
    try:
        item = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProofModeError("proof request is invalid") from exc
    if not isinstance(item, dict):
        raise ProofModeError("proof request schema is invalid")
    operation = item.get("operation")
    if operation == "dpapi_proof":
        raise ProofModeError("caller-triggered DPAPI proof is not allowed")
    if operation == "proof_status" and set(item) == {"operation", "expected_service_sid"}:
        expected_sid = item.get("expected_service_sid")
        if isinstance(expected_sid, str) and expected_sid.startswith("S-1-5-80-"):
            return {"operation": operation, "expected_service_sid": expected_sid}
    if operation not in {"proof_status", "dpapi_proof"}:
        raise ProofModeError("proof operation is not allowed")
    raise ProofModeError("proof request schema is invalid")


class _ProofHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        server = cast(Any, self.server)
        self.request.settimeout(10.0)
        try:
            request = decode_proof_request(self.rfile.readline(4097))
            response = (
                server.runtime.proof_status(request["expected_service_sid"])
                if request["operation"] == "proof_status"
                else (_ for _ in ()).throw(ProofModeError("operation is not allowed"))
            )
        except (OSError, TypeError, ValueError, ProofModeError) as exc:
            response = {"error": str(exc)}
        self.wfile.write((json.dumps(response, sort_keys=True) + "\n").encode())


class ProofIPCServer(socketserver.ThreadingTCPServer):
    """Separate loopback proof channel; never accepts agent requests."""

    allow_reuse_address = False
    daemon_threads = True
    timeout = 15

    def __init__(self, runtime, port: int = 0) -> None:
        self.runtime = runtime
        super().__init__(("127.0.0.1", port), _ProofHandler)
