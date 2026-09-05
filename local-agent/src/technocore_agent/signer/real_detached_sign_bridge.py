"""One-shot detached room-signing entrypoint.

The request is a non-secret temporary file because the child's stdin belongs to the operator's
terminal; the file is transport, never authorization.  ``real`` custody is reachable only after
this child's own interactive, request-bound operator confirmation, which cannot be supplied by
argv, environment, or the request file.  ``fixture`` custody runs the identical control flow with
a test approval channel and a disposable key, so validation never touches protected custody.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..service.runtime import DPAPIKeyProvider, TrustedPaths
from ..storage.nonce import NonceStore
from .detached_controller import (
    PURPOSE,  # noqa: F401
    SCHEMA,  # noqa: F401
    DetachedRequest,
    run_detached_signing,
    sanitized_error,
    serialize_signed_operation,
)
from .service import Signer

FIXTURE_KEY = bytes(range(32))
APPROVAL_PREFIX = "SIGN DETACHED"


def _confirmation_suffix(request: dict[str, str]) -> str:
    """Return a short value bound to this exact frozen request."""
    material = json.dumps({key: request[key] for key in sorted(request)},
                          sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(material).hexdigest()[-8:].upper()


class TerminalApproval:
    """The production human channel: the operator's own terminal, never a proxy.

    stdout is the captured machine-readable response channel, so the confirmation is displayed
    on stderr and read from stdin.  A later custody credential prompt uses the same terminal
    directly and is never relayed through the calling process.
    """

    def attached(self) -> bool:
        return sys.stdin.isatty()

    def prompt(self, text: str) -> None:
        sys.stderr.write(text)
        sys.stderr.flush()

    def read(self) -> str:
        return sys.stdin.readline()


class FixtureApproval:
    """Test double for the human channel; refused for real custody by ``serve_once``.

    It answers only from the displayed instruction, exactly as a human operator would, so the
    production gate logic — not the double — decides the outcome.
    """

    def __init__(self, response: str = "correct") -> None:
        self._response = response
        self._prompt = ""

    def attached(self) -> bool:
        return True

    def prompt(self, text: str) -> None:
        self._prompt = text

    def read(self) -> str:
        if self._response == "blank":
            return "\n"
        if self._response == "wrong":
            return f"{APPROVAL_PREFIX} WRONG\n"
        instruction = next(line for line in self._prompt.splitlines()
                           if line.startswith("Type exactly: "))
        return instruction.removeprefix("Type exactly: ") + "\n"


def _require_canonical_operator(request: dict[str, str], channel: TerminalApproval) -> None:
    """Second, independent human checkpoint at the canonical custody boundary."""
    if not channel.attached():
        raise PermissionError("INTERACTIVE_TTY_REQUIRED: canonical custody requires a human terminal")
    suffix = _confirmation_suffix(request)
    channel.prompt(
        "\nCANONICAL PROTECTED CUSTODY\n"
        "DETACHED ROOM SIGNATURE\n"
        "NO NETWORK SUBMISSION\n\n"
        f"ROOM:\n{request['room']}\n\n"
        f"REQUEST / FRAME FINGERPRINT:\n{suffix}\n\n"
        "LOCAL NONCE:\nWILL BE CONSUMED\n\n"
        "MAX SIGNATURES:\n1\n\n"
        f"Type exactly: {APPROVAL_PREFIX} {suffix}\n"
        "Canonical approval: "
    )
    if channel.read().strip() != f"{APPROVAL_PREFIX} {suffix}":
        raise PermissionError("WRONG_CANONICAL_APPROVAL: no custody was attempted")


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
        # Reachable only after the interactive canonical confirmation above.  Storage, key
        # representation, and any credential prompt remain the unmodified DPAPI provider.
        paths = TrustedPaths.under(state)
        return DPAPIKeyProvider(paths.protected_key)
    raise ValueError("custody mode is invalid")


def _signer(mode: str, state: Path):
    """Compatibility inspection helper; production flow uses ``_provider``."""
    provider = _provider(mode, state)
    return Signer(provider.load_or_create(), NonceStore(TrustedPaths.under(state).nonces))


def serve_once(request_path: Path, *, custody: str, state: Path, approval=None) -> None:
    try:
        if custody not in ("fixture", "real"):
            raise ValueError("custody mode is invalid")
        channel = approval if approval is not None else TerminalApproval()
        if custody == "real" and not isinstance(channel, TerminalApproval):
            raise PermissionError("real custody requires the operator terminal approval channel")
        request = _read_request(request_path)
        actual = _actual_commit()
        _clean_relevant_tree()
        # Attest the exact reviewed child before the operator is asked, so approval can only
        # ever bind to reviewed code, and refuse before any custody provider is constructed.
        if actual != request["expectedCanonicalCommit"]:
            raise ValueError("canonical repository HEAD does not match expected commit")
        _require_canonical_operator(request, channel)
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
    # Fixture-only channel for automated validation of this same flow.  ``serve_once`` refuses it
    # for real custody, so it can never become an approval bypass.
    parser.add_argument("--approval-source", choices=("terminal", "fixture"), default="terminal")
    parser.add_argument("--approval-response", choices=("correct", "wrong", "blank"), default="correct")
    args = parser.parse_args()
    approval = FixtureApproval(args.approval_response) if args.approval_source == "fixture" else TerminalApproval()
    serve_once(args.request_file, custody=args.custody, state=args.state, approval=approval)


if __name__ == "__main__":
    main()
