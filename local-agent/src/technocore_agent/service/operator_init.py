"""Narrow, human-driven first-use operator credential provisioning."""

from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path

from ..control.operator import OperatorAuth, OperatorAuthError

STAGE2D_STATE_ROOT = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / (
    "TechnocoreAgent-Stage2D-Test"
)


def _require_admin() -> None:
    if os.name != "nt":
        raise PermissionError("operator initialization requires Windows administrator context")
    import ctypes

    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise PermissionError("operator initialization requires an elevated administrator")


def initialize_operator(state_root: Path, *, passphrase_provider=getpass.getpass) -> None:
    """Initialize only an absent verifier after validating the trusted marker."""
    _require_admin()
    state_root = Path(state_root).resolve()
    expected_root = STAGE2D_STATE_ROOT.resolve()
    if state_root != expected_root:
        raise OperatorAuthError("only the canonical Stage2D StateRoot is accepted")
    if state_root.is_symlink():
        raise OperatorAuthError("trusted Stage2D StateRoot must not be a reparse point")
    marker = state_root / "stage2d-install.json"
    if not marker.is_file():
        raise OperatorAuthError("trusted Stage2D state marker is missing")
    try:
        item = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise OperatorAuthError("trusted Stage2D state marker is invalid") from exc
    required = {
        "schema": "stage2d-install-marker-v1",
        "service_name": "TechnocoreAgentStage2DTest",
        "install_root": str(
            Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
            / "TechnocoreAgent-Stage2D-Test"
        ),
        "state_root": str(expected_root),
        "package_version": "0.1.0",
    }
    if any(item.get(key) != value for key, value in required.items()):
        raise OperatorAuthError("trusted StateRoot marker mismatch")
    if not isinstance(item.get("installation_id"), str) or not item["installation_id"].strip():
        raise OperatorAuthError("trusted Stage2D installation identity is missing")
    auth = OperatorAuth(state_root / "operator.json")
    if auth.configured():
        raise OperatorAuthError("operator credential is already configured")
    first = passphrase_provider("Operator passphrase: ")
    second = passphrase_provider("Confirm operator passphrase: ")
    if first != second:
        raise OperatorAuthError("operator passphrases do not match")
    auth.enroll(first)


def main() -> None:
    parser = argparse.ArgumentParser(description="TEST-ONLY trusted operator bootstrap")
    parser.add_argument("--state-root", required=True)
    args = parser.parse_args()
    initialize_operator(Path(args.state_root))
    print("operator credential initialized")
