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

from ..service.runtime import DPAPIKeyProvider, TrustedPaths
from ..storage.nonce import NonceStore
from .service import Signer
from .detached_controller import (
    PURPOSE,
    SCHEMA,
    DetachedRequest,
    run_detached_signing,
    sanitized_error,
    serialize_signed_operation,
)

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
    DetachedRequest.from_mapping(item)
    return item


def _provider(mode: str, state: Path):
    if mode == "fixture":
        # Published disposable test vector; it is never a protected operator identity.
        return type("FixtureProvider", (), {
            "load_or_create": lambda self: Ed25519PrivateKey.from_private_bytes(FIXTURE_KEY)
        })()
    if mode == "real":
        # This branch is structurally present for the separately authorized future operator
        # command.  serve_once refuses before reaching it during this phase.
        paths = TrustedPaths.under(state)
        return DPAPIKeyProvider(paths.protected_key)
    raise ValueError("custody mode is invalid")


def _signer(mode: str, state: Path):
    """Compatibility inspection helper; production flow uses ``_provider``."""
    provider = _provider(mode, state)
    return Signer(provider.load_or_create(), NonceStore(TrustedPaths.under(state).nonces))


def serve_once(request_path: Path, *, custody: str, state: Path) -> None:
    try:
        request = _read_request(request_path)
        actual = _actual_commit()
        _clean_relevant_tree()
        if custody == "real":
            raise PermissionError("FRESH_REAL_OPERATOR_APPROVAL_REQUIRED")
        if custody != "fixture":
            raise ValueError("custody mode is invalid")
        operation = run_detached_signing(
            DetachedRequest.from_mapping(request), _provider(custody, state),
            NonceStore(TrustedPaths.under(state).nonces), actual_canonical_commit=actual,
        )
        response = serialize_signed_operation(operation, actual, custody)
    except Exception as exc:  # one sanitized machine-readable failure response
        response = sanitized_error(exc)
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
