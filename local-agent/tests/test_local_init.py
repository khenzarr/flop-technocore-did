from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_agent.service.identity_recovery import (
    IdentityRecoveryError,
    backup_identity,
    restore_identity,
)
from technocore_agent.service.local_init import initialize_local_identity
from technocore_agent.signer.service import canonical_did
from technocore_agent.storage import recovery


class KeyProvider:
    key = Ed25519PrivateKey.generate()

    def __init__(self, path):
        self.path = path

    def load_or_create(self):
        return self.key


def test_local_initialization_enrolls_operator_and_returns_stable_public_did(tmp_path):
    acl_calls = []
    passwords = iter(("a unique local operator passphrase", "a unique local operator passphrase"))
    did = initialize_local_identity(
        tmp_path / "state",
        passphrase_provider=lambda _prompt: next(passwords),
        acl_applier=lambda path: acl_calls.append(path),
        key_provider_factory=KeyProvider,
    )
    assert did.startswith("did:key:z6Mk")
    assert (tmp_path / "state" / "operator.json").is_file()
    assert (tmp_path / "state" / "local-install.json").is_file()
    assert acl_calls == [tmp_path / "state", tmp_path / "state"]


def test_local_initialization_is_idempotent_after_operator_enrollment(tmp_path):
    root = tmp_path / "state"
    first_passwords = iter(("a unique local operator passphrase",) * 2)
    first = initialize_local_identity(
        root,
        passphrase_provider=lambda _prompt: next(first_passwords),
        acl_applier=lambda _path: None,
        key_provider_factory=KeyProvider,
    )
    second = initialize_local_identity(
        root,
        passphrase_provider=lambda _prompt: (_ for _ in ()).throw(AssertionError()),
        acl_applier=lambda _path: None,
        key_provider_factory=KeyProvider,
    )
    assert second == first


def test_local_initialization_rejects_unrecognized_preexisting_content(tmp_path):
    root = tmp_path / "state"
    root.mkdir()
    (root / "unexpected.txt").write_text("not trusted", encoding="utf-8")
    try:
        initialize_local_identity(
            root,
            passphrase_provider=lambda _prompt: "a unique local operator passphrase",
            acl_applier=lambda _path: None,
            key_provider_factory=KeyProvider,
        )
    except ValueError as exc:
        assert "unrecognized" in str(exc)
    else:
        raise AssertionError("unrecognized preexisting state was accepted")


def test_portable_backup_is_encrypted_and_verifies_same_did(tmp_path):
    root = tmp_path / "state"
    root.mkdir()
    (root / "identity.dpapi").write_bytes(b"protected-placeholder")
    output = tmp_path / "did-backup.json"
    raw = bytes(range(32))
    passwords = iter(("a separate portable backup passphrase",) * 2)
    did = backup_identity(
        root,
        output,
        passphrase_provider=lambda _prompt: next(passwords),
        key_loader=lambda _path: raw,
    )
    assert raw not in output.read_bytes()
    assert did == canonical_did(Ed25519PrivateKey.from_private_bytes(raw))
    assert recovery.restore(
        output.read_bytes(), lambda: b"a separate portable backup passphrase"
    ) == raw


def test_portable_backup_never_overwrites_existing_output(tmp_path):
    root = tmp_path / "state"
    root.mkdir()
    (root / "identity.dpapi").write_bytes(b"protected-placeholder")
    output = tmp_path / "existing.json"
    output.write_text("keep", encoding="utf-8")
    try:
        backup_identity(root, output, key_loader=lambda _path: bytes(range(32)))
    except IdentityRecoveryError as exc:
        assert "exists" in str(exc)
    else:
        raise AssertionError("existing backup was accepted")
    assert output.read_text(encoding="utf-8") == "keep"


def test_restore_creates_same_did_without_exposing_plaintext(tmp_path):
    raw = bytes(range(32))
    backup = tmp_path / "backup.json"
    recovery.write(backup, raw, lambda: b"a separate portable backup passphrase")
    operator_passwords = iter(("a new restored operator passphrase",) * 2)

    def save(path, value):
        assert value == raw
        path.write_bytes(b"test-protected-value")

    root = tmp_path / "restored"
    did = restore_identity(
        root,
        backup,
        recovery_passphrase_provider=lambda _prompt: "a separate portable backup passphrase",
        operator_passphrase_provider=lambda _prompt: next(operator_passwords),
        acl_applier=lambda _path: None,
        key_saver=save,
    )
    assert did == canonical_did(Ed25519PrivateKey.from_private_bytes(raw))
    assert (root / "identity.dpapi").read_bytes() == b"test-protected-value"
    assert raw not in b"".join(path.read_bytes() for path in root.iterdir())


def test_restore_wrong_passphrase_leaves_no_identity_state(tmp_path):
    backup = tmp_path / "backup.json"
    recovery.write(
        backup, bytes(range(32)), lambda: b"a separate portable backup passphrase"
    )
    root = tmp_path / "restored"
    try:
        restore_identity(
            root,
            backup,
            recovery_passphrase_provider=lambda _prompt: "wrong",
            acl_applier=lambda _path: None,
        )
    except IdentityRecoveryError:
        pass
    else:
        raise AssertionError("wrong recovery passphrase was accepted")
    assert root.is_dir() and list(root.iterdir()) == []
