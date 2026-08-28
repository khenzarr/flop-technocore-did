"""Portable encrypted backup and restore for the Windows-local DID."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import stat
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..control.operator import OperatorAuth, OperatorAuthError
from ..signer.service import canonical_did
from ..storage import dpapi, recovery

LOCAL_MARKER_SCHEMA = "technocore-local-install-v1"


class IdentityRecoveryError(ValueError):
    pass


def _is_reparse(path: Path) -> bool:
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _default_local_state() -> Path:
    value = os.environ.get("LOCALAPPDATA")
    if not value:
        raise IdentityRecoveryError("LOCALAPPDATA is unavailable")
    return Path(value).resolve() / "TechnocoreAgent"


def _regular_file(path: Path, label: str) -> Path:
    source = Path(path)
    if source.is_symlink() or not source.is_file() or _is_reparse(source):
        raise IdentityRecoveryError(f"{label} must be a regular non-reparse file")
    return source.resolve(strict=True)


def _new_backup_path(path: Path) -> Path:
    requested = Path(path)
    if requested.exists() or requested.is_symlink():
        raise IdentityRecoveryError("backup output already exists")
    if (
        requested.parent.is_symlink()
        or not requested.parent.is_dir()
        or _is_reparse(requested.parent)
    ):
        raise IdentityRecoveryError("backup parent must be a regular non-reparse directory")
    return requested.parent.resolve(strict=True) / requested.name


def _new_secret(provider, prompt: str, confirm_prompt: str) -> bytes:
    first = provider(prompt)
    second = provider(confirm_prompt)
    if first != second:
        raise IdentityRecoveryError("backup passphrases do not match")
    if not isinstance(first, str) or len(first) < 20:
        raise IdentityRecoveryError("use a unique backup passphrase of at least 20 characters")
    return first.encode("utf-8")


def _read_secret(provider, prompt: str) -> bytes:
    value = provider(prompt)
    if not isinstance(value, str) or not value:
        raise IdentityRecoveryError("backup passphrase is required")
    return value.encode("utf-8")


def _atomic_create(path: Path, data: bytes) -> None:
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    published = False
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, stat.S_IRUSR | stat.S_IWUSR)
        # A hard link publishes the fully flushed bytes atomically and fails if
        # another process created the requested output name first.
        os.link(name, path)
        published = True
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as exc:
        if published:
            try:
                path.unlink()
            except OSError:
                pass
        raise IdentityRecoveryError("backup file could not be created") from exc
    finally:
        try:
            os.unlink(name)
        except OSError:
            pass


def backup_identity(
    state_root: Path,
    output_path: Path,
    *,
    passphrase_provider=getpass.getpass,
    key_loader=dpapi.load,
) -> str:
    requested_root = Path(state_root)
    if requested_root.is_symlink():
        raise IdentityRecoveryError("local state must not be a reparse point")
    root = requested_root.resolve()
    key_path = _regular_file(root / "identity.dpapi", "protected identity")
    output = _new_backup_path(output_path)
    password = _new_secret(
        passphrase_provider,
        "New backup passphrase (20+ characters): ",
        "Confirm backup passphrase: ",
    )
    raw: bytes | None = None
    try:
        raw = key_loader(key_path)
        if not isinstance(raw, bytes) or len(raw) != 32:
            raise IdentityRecoveryError("protected identity is invalid")
        did = canonical_did(Ed25519PrivateKey.from_private_bytes(raw))
        bundle = recovery.create(raw, lambda: password)
        verified = recovery.restore(bundle, lambda: password)
        if verified != raw:
            raise IdentityRecoveryError("backup verification failed")
        _atomic_create(output, bundle)
        return did
    finally:
        raw = None
        password = b""


def restore_identity(
    state_root: Path,
    backup_path: Path,
    *,
    recovery_passphrase_provider=getpass.getpass,
    operator_passphrase_provider=getpass.getpass,
    acl_applier=None,
    key_saver=dpapi.save,
) -> str:
    requested_root = Path(state_root)
    if requested_root.is_symlink():
        raise IdentityRecoveryError("local state must not be a reparse point")
    root = requested_root.resolve()
    backup = _regular_file(backup_path, "backup")
    if acl_applier is None:
        from .local_init import _apply_private_acl

        acl_applier = _apply_private_acl
    root.mkdir(parents=True, exist_ok=True)
    if not root.is_dir() or _is_reparse(root):
        raise IdentityRecoveryError("local state must be a regular non-reparse directory")
    targets = [root / "operator.json", root / "identity.dpapi", root / "local-install.json"]
    if any(path.exists() or path.is_symlink() for path in targets) or any(root.iterdir()):
        raise IdentityRecoveryError("restore requires an empty local state directory")

    password = _read_secret(recovery_passphrase_provider, "Backup passphrase: ")
    raw: bytes | None = None
    try:
        raw = recovery.restore(backup.read_bytes(), lambda: password)
    except (OSError, recovery.RecoveryError) as exc:
        password = b""
        raise IdentityRecoveryError("backup is invalid or the passphrase is incorrect") from exc
    created: list[Path] = []
    try:
        if raw is None or len(raw) != 32:
            raise IdentityRecoveryError("backup identity is invalid")
        did = canonical_did(Ed25519PrivateKey.from_private_bytes(raw))
        acl_applier(root)
        auth = OperatorAuth(targets[0])
        first = operator_passphrase_provider("New operator passphrase (20+ characters): ")
        second = operator_passphrase_provider("Confirm operator passphrase: ")
        if first != second:
            raise OperatorAuthError("operator passphrases do not match")
        auth.enroll(first)
        created.append(targets[0])
        key_saver(targets[1], raw)
        created.append(targets[1])
        targets[2].write_text(
            json.dumps(
                {"schema": LOCAL_MARKER_SCHEMA, "public_did": did},
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        created.append(targets[2])
        acl_applier(root)
        return did
    except Exception:
        for path in reversed(created):
            try:
                path.unlink()
            except OSError:
                pass
        raise
    finally:
        raw = None
        password = b""


def main() -> None:
    parser = argparse.ArgumentParser(description="Backup or restore the Windows-local DID")
    subparsers = parser.add_subparsers(dest="operation", required=True)
    backup = subparsers.add_parser("backup", help="create an encrypted portable backup")
    backup.add_argument("output", type=Path)
    restore = subparsers.add_parser("restore", help="restore into a new local installation")
    restore.add_argument("backup", type=Path)
    args = parser.parse_args()
    state = _default_local_state()
    if args.operation == "backup":
        did = backup_identity(state, args.output)
        print(f"BACKUP_CREATED {args.output.resolve()}")
        print(f"PUBLIC_DID {did}")
        print("KEEP_BACKUP_AND_PASSPHRASE_SEPARATE")
    else:
        did = restore_identity(state, args.backup)
        print(f"RESTORE_COMPLETE {state}")
        print(f"PUBLIC_DID {did}")


if __name__ == "__main__":
    main()
