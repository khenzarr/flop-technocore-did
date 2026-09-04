"""One-shot detached room-signing entrypoint.

The request is a non-secret temporary file because the child's stdin belongs to the trusted
operator console.  ``fixture`` is the only custody mode used by Phase 3A.8.  ``real`` is
intentionally gated by an explicit external authorization and must never be selected by normal
tests or demos.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..service.runtime import DPAPIKeyProvider, TrustedPaths, create_local_signer

SCHEMA = "technocore-detached-sign-request/v2"
PURPOSE = "DETACHED_ROOM_SIGNING"
FIXTURE_KEY = bytes(range(32))


def _actual_commit() -> str:
    root = Path(__file__).resolve().parents[4]
    result = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=True,
                            capture_output=True, text=True)
    commit = result.stdout.strip()
    if len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit):
        raise ValueError("canonical repository HEAD is invalid")
    return commit


def _clean_relevant_tree() -> None:
    root = Path(__file__).resolve().parents[4]
    result = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain", "--",
         "local-agent/src/technocore_agent/signer", "local-agent/src/technocore_agent/storage/nonce.py",
         "local-agent/src/technocore_agent/service/runtime.py"],
        check=True, capture_output=True, text=True,
    )
    if result.stdout.strip():
        raise ValueError("canonical relevant worktree is dirty")


def _read_request(path: Path) -> dict[str, str]:
    if not path.is_absolute():
        raise ValueError("request path must be absolute")
    raw = path.read_bytes()
    if len(raw) > 16 * 1024:
        raise ValueError("bridge request is too large")
    item = json.loads(raw)
    required = {"schema", "requestId", "room", "text", "expectedCanonicalCommit", "purpose"}
    if not isinstance(item, dict) or set(item) != required:
        raise ValueError("bridge request schema is invalid")
    if item["schema"] != SCHEMA or item["purpose"] != PURPOSE:
        raise ValueError("bridge request purpose or schema is invalid")
    if any(not isinstance(item[key], str) or not item[key] for key in required - {"schema", "purpose"}):
        raise ValueError("bridge request fields are invalid")
    expected = item["expectedCanonicalCommit"]
    if len(expected) != 40 or any(c not in "0123456789abcdef" for c in expected):
        raise ValueError("bridge request commit is invalid")
    return item


def _signer(mode: str, state: Path):
    if mode == "fixture":
        # Published disposable test vector; it is never a protected operator identity.
        return create_local_signer(TrustedPaths.under(state),
                                   type("FixtureProvider", (), {
                                       "load_or_create": lambda self: Ed25519PrivateKey.from_private_bytes(FIXTURE_KEY)
                                   })())
    if mode == "real":
        # This branch is structurally present for the separately authorized future operator
        # command.  serve_once refuses before reaching it during this phase.
        paths = TrustedPaths.under(state)
        return create_local_signer(paths, DPAPIKeyProvider(paths.protected_key))
    raise ValueError("custody mode is invalid")


def serve_once(request_path: Path, *, custody: str, state: Path) -> None:
    try:
        request = _read_request(request_path)
        actual = _actual_commit()
        if actual != request["expectedCanonicalCommit"]:
            raise ValueError("canonical repository HEAD does not match expected commit")
        _clean_relevant_tree()
        if custody == "real":
            raise PermissionError("FRESH_REAL_OPERATOR_APPROVAL_REQUIRED")
        signer = _signer(custody, state)
        operation = signer.sign_room_detached(request["room"], request["text"])
        response = {"did": operation.did, "room": operation.room, "nonce": operation.nonce,
                    "signature": operation.signature, "text": operation.text,
                    "canonicalCommit": actual, "custodyMode": custody}
    except Exception as exc:  # one sanitized machine-readable failure response
        response = {"error": str(exc)}
    sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description="One-shot detached room signer")
    parser.add_argument("--request-file", type=Path, required=True)
    parser.add_argument("--custody", choices=("fixture", "real"), required=True)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    serve_once(args.request_file, custody=args.custody, state=args.state)


if __name__ == "__main__":
    main()
