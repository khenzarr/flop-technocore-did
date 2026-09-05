"""Human-only enrollment of additional named, DPAPI-protected local identities.

This module is a *caller* of the reviewed custody primitive in :mod:`local_init`.
It contains no key generation, no storage format, no private-key representation,
no signing, no nonce and no transport logic of its own: the protected key is
created exclusively by ``initialize_local_identity``, unchanged.

Boundaries enforced here, before any custody call:

* the operator supplies a **logical profile name only** — never a filesystem
  path, drive, UNC share or environment expansion;
* every additional identity resolves inside the single reviewed namespace
  ``%LOCALAPPDATA%\\TechnocoreAgent\\identities``, proven by a containment check
  after resolution, and can therefore never collide with the default identity
  root used by ``technocore-agent-init``;
* an already-enrolled profile is reported, never overwritten, regenerated or
  rotated;
* real enrollment requires a directly interactive human terminal plus a manual
  confirmation phrase bound to the derived root. The profile name is deliberately
  the only accepted argument: there is no approval flag and no environment
  override that can stand in for the human;
* the operator credential is read only by the existing protected prompt inside
  this process, so it never appears in argv, the environment, a file, a log or
  any machine-readable output.

The default identity path and its single-root guard in ``local_init.main`` are
untouched.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ..control.operator import OperatorAuthError

# Private helpers are imported rather than re-implemented so the reparse-point
# predicate and the private-ACL applier stay byte-identical to the reviewed
# default enrollment path.
from .local_init import (
    LOCAL_MARKER_SCHEMA,
    _apply_private_acl,
    _is_reparse,
    default_local_state,
    initialize_local_identity,
)
from .runtime import DPAPIKeyProvider

IDENTITIES_DIRNAME = "identities"
LOCAL_MARKER_NAME = "local-install.json"
CONFIRMATION_PREFIX = "CREATE IDENTITY"
CONFIRMATION_TAG = "technocore-named-identity-v1"

# Narrow allowlist: 3-64 characters, lowercase ASCII, no separators of any kind.
PROFILE_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{1,62}[a-z0-9]")
PROFILE_RULE = (
    "3-64 characters of lowercase ASCII letters, digits, '-' or '_', "
    "starting and ending with a letter or digit"
)
_DEVICE_NAMES = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)
RESERVED_PROFILES = (
    frozenset({"default", "primary", "identity", "identities", "technocoreagent"}) | _DEVICE_NAMES
)


class ProfileEnrollmentError(OperatorAuthError):
    """Refusal raised before any protected key material is created or read."""


@dataclass(frozen=True, slots=True)
class NamedIdentity:
    """Public, non-secret result of a named-profile enrollment."""

    profile: str
    root: Path
    public_did: str
    public_key_fingerprint: str
    status: str


class InteractionChannel(Protocol):
    """Direct human terminal used for the pre-custody review gate."""

    def attached(self) -> bool: ...

    def notify(self, text: str) -> None: ...

    def read(self) -> str: ...


class HumanTerminal:
    """Refuses anything that is not a directly interactive console."""

    def attached(self) -> bool:
        return bool(sys.stdin.isatty() and sys.stdout.isatty())

    def notify(self, text: str) -> None:
        sys.stdout.write(text)
        sys.stdout.flush()

    def read(self) -> str:
        return sys.stdin.readline()


def validate_profile(profile: str) -> str:
    """Return ``profile`` unchanged, or refuse it. Unsafe input is never normalized."""
    if not isinstance(profile, str) or not profile:
        raise ProfileEnrollmentError(f"PROFILE_INVALID: profile is required and must be {PROFILE_RULE}")
    if profile != profile.strip():
        raise ProfileEnrollmentError(
            "PROFILE_INVALID: profile must not contain leading or trailing whitespace"
        )
    if PROFILE_PATTERN.fullmatch(profile) is None:
        raise ProfileEnrollmentError(f"PROFILE_INVALID: profile must be {PROFILE_RULE}")
    if profile in RESERVED_PROFILES:
        raise ProfileEnrollmentError(f"PROFILE_RESERVED: '{profile}' is a reserved profile name")
    return profile


def confirmation_code(profile: str, root: Path) -> str:
    """Return a short, non-secret code bound to this exact profile and derived root."""
    material = f"{CONFIRMATION_TAG}|{profile}|{root}".encode()
    return hashlib.sha256(material).hexdigest()[:8].upper()


def _refuse_unsafe_directory(path: Path, label: str) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if not path.is_dir() or _is_reparse(path):
        raise ProfileEnrollmentError(f"UNSAFE_IDENTITY_PATH: {label} must be a regular directory")


def derive_profile_root(profile: str) -> Path:
    """Derive the state root for ``profile`` internally and prove it stays contained."""
    name = validate_profile(profile)
    default_root = default_local_state().resolve()
    namespace = default_root / IDENTITIES_DIRNAME
    _refuse_unsafe_directory(namespace, "the additional-identity namespace")
    resolved_namespace = namespace.resolve()
    if resolved_namespace.name != IDENTITIES_DIRNAME or resolved_namespace.parent != default_root:
        raise ProfileEnrollmentError(
            "IDENTITY_NAMESPACE_ESCAPE: the additional-identity namespace must resolve to "
            f"{default_root / IDENTITIES_DIRNAME}"
        )
    root = (resolved_namespace / name).resolve()
    if (
        root == resolved_namespace
        or root.parent != resolved_namespace
        or not root.is_relative_to(resolved_namespace)
    ):
        raise ProfileEnrollmentError(
            f"PROFILE_ROOT_ESCAPE: '{name}' does not resolve inside {resolved_namespace}"
        )
    if root == default_root:
        raise ProfileEnrollmentError(
            "DEFAULT_ROOT_COLLISION: an additional identity may never use the default state root"
        )
    _refuse_unsafe_directory(root, "the additional-identity state root")
    return root


def _require_initialized_default_identity() -> None:
    """The default identity must exist first.

    ``initialize_local_identity`` refuses a state root that contains unrecognized
    entries before its own marker exists, so creating the ``identities`` namespace
    inside an uninitialized default root would break ``technocore-agent-init``.
    """
    default_root = default_local_state().resolve()
    if not (default_root / LOCAL_MARKER_NAME).is_file():
        raise ProfileEnrollmentError(
            "DEFAULT_IDENTITY_NOT_INITIALIZED: run technocore-agent-init first; additional "
            f"identities live beneath the initialized default state root {default_root}"
        )


def _already_enrolled(profile: str, root: Path) -> NamedIdentity | None:
    """Return the existing public identity of ``profile``, or ``None``. Never writes."""
    marker = root / LOCAL_MARKER_NAME
    if not marker.exists() and not marker.is_symlink():
        return None
    if not marker.is_file() or _is_reparse(marker):
        raise ProfileEnrollmentError(
            "UNSAFE_IDENTITY_PATH: the existing local installation marker is not a regular file"
        )
    try:
        item = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ProfileEnrollmentError("EXISTING_MARKER_INVALID: refusing to touch this profile") from exc
    did = item.get("public_did") if isinstance(item, dict) else None
    schema = item.get("schema") if isinstance(item, dict) else None
    if schema != LOCAL_MARKER_SCHEMA or not isinstance(did, str) or not did.startswith("did:key:"):
        raise ProfileEnrollmentError("EXISTING_MARKER_INVALID: refusing to touch this profile")
    return NamedIdentity(profile, root, did, public_key_fingerprint(did), "ALREADY_ENROLLED")


def public_key_fingerprint(did: str) -> str:
    """Return the public, non-secret fingerprint of a public DID."""
    return hashlib.sha256(did.encode()).hexdigest()


def _render_review(profile: str, root: Path, code: str) -> str:
    return (
        "\nTECHNOCORE AGENT — ADDITIONAL PROTECTED IDENTITY\n\n"
        f"PROFILE:\n{profile}\n\n"
        f"STATE ROOT:\n{root}\n\n"
        "ACTION:\nCREATE ONE NEW PROTECTED DID\n\n"
        "SIGNING:\nNONE\n\n"
        "NONCE:\nNONE\n\n"
        "NETWORK:\nNONE\n\n"
        "TECHNOCORE:\nNONE\n\n"
        f"Type exactly: {CONFIRMATION_PREFIX} {code}\n"
        "Confirmation: "
    )


def enroll_named_identity(
    profile: str,
    *,
    terminal: InteractionChannel | None = None,
    passphrase_provider=getpass.getpass,
    acl_applier=_apply_private_acl,
    key_provider_factory=DPAPIKeyProvider,
) -> NamedIdentity:
    """Enrol exactly one additional protected identity for a reviewed profile name."""
    name = validate_profile(profile)
    root = derive_profile_root(name)
    _require_initialized_default_identity()
    existing = _already_enrolled(name, root)
    if existing is not None:
        return existing
    channel = terminal if terminal is not None else HumanTerminal()
    if not channel.attached():
        raise ProfileEnrollmentError(
            "INTERACTIVE_TTY_REQUIRED: creating a protected identity requires a directly "
            "interactive human terminal; no identity was created"
        )
    code = confirmation_code(name, root)
    channel.notify(_render_review(name, root, code))
    if channel.read().strip() != f"{CONFIRMATION_PREFIX} {code}":
        raise ProfileEnrollmentError(
            "WRONG_ENROLLMENT_CONFIRMATION: no identity was created"
        )
    did = initialize_local_identity(
        root,
        passphrase_provider=passphrase_provider,
        acl_applier=acl_applier,
        key_provider_factory=key_provider_factory,
    )
    return NamedIdentity(name, root, did, public_key_fingerprint(did), "ENROLLED")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="technocore-agent-profile-init",
        description=(
            "Enrol an additional Windows-local Technocore DID under a reviewed profile name. "
            "The state root is derived internally and cannot be supplied."
        ),
    )
    parser.add_argument("--profile", required=True, help=f"reviewed profile name ({PROFILE_RULE})")
    args = parser.parse_args()
    try:
        identity = enroll_named_identity(args.profile)
    except OperatorAuthError as exc:
        raise SystemExit(f"REFUSED {exc}") from None
    print(f"PROFILE {identity.profile}")
    print(f"PUBLIC DID {identity.public_did}")
    print(f"PUBLIC KEY FINGERPRINT {identity.public_key_fingerprint}")
    print(f"CUSTODY ROOT {identity.root}")
    print("PRIVATE_KEY Windows DPAPI protected; not exported")
    if identity.status == "ALREADY_ENROLLED":
        print("ENROLLED=ALREADY_ENROLLED")
        return
    print("ENROLLED=YES")


if __name__ == "__main__":
    main()
