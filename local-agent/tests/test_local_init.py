from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_agent.service.local_init import initialize_local_identity


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
