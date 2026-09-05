"""Fixture-only validation of the human-only named-profile enrollment entrypoint.

No test in this module creates a real protected identity: the DPAPI provider, the
credential prompt, the ACL applier and the human terminal are all injected, and the
default state root is redirected into ``tmp_path`` through ``LOCALAPPDATA``.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_agent.service import profile_init
from technocore_agent.service.local_init import initialize_local_identity
from technocore_agent.service.profile_init import (
    CONFIRMATION_PREFIX,
    ProfileEnrollmentError,
    confirmation_code,
    derive_profile_root,
    enroll_named_identity,
    validate_profile,
)

FIXTURE_PASSPHRASE = "fixture only local operator passphrase"
PROFILE_A = "phase3b-fixture-a"
PROFILE_B = "phase3b-fixture-b"

REJECTED_PROFILES = [
    "",
    ".",
    "..",
    "../x",
    "..\\x",
    "/x",
    "\\x",
    "C:\\x",
    "c:/x",
    "\\\\server\\share",
    "//server/share",
    "file://x",
    "%LOCALAPPDATA%",
    "%TEMP%\\x",
    "$env:TEMP",
    " leading",
    "trailing ",
    "with space",
    "\tprofile",
    "profile\n",
    "UPPER",
    "-leading-hyphen",
    "trailing-hyphen-",
    "a",
    "ab",
    "a" * 65,
    "dot.profile",
    "colon:profile",
    "star*profile",
    "quote\"profile",
    "nul\x00byte",
    "caf\u00e9",
    "\u0130stanbul",
    "prof\u2044ile",
]

RESERVED_NAMES = ["default", "primary", "identity", "identities", "technocoreagent", "con", "nul", "com1", "lpt9"]


class FixtureKeyProvider:
    """Deterministic per-path stand-in for :class:`DPAPIKeyProvider`.

    Writes an opaque blob so storage separation between profiles is observable
    without ever touching real DPAPI or exporting a private key.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def load_or_create(self) -> Ed25519PrivateKey:
        seed = hashlib.sha256(str(self.path).encode()).digest()
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_bytes(b"FIXTURE-PROTECTED-BLOB" + seed)
        return Ed25519PrivateKey.from_private_bytes(seed)


class FixtureTerminal:
    """Injected stand-in for the direct human terminal."""

    def __init__(self, *, attached: bool = True, response: str | None = None) -> None:
        self._attached = attached
        self._response = response
        self.prompts: list[str] = []

    def attached(self) -> bool:
        return self._attached

    def notify(self, text: str) -> None:
        self.prompts.append(text)

    def read(self) -> str:
        if self._response is not None:
            return self._response
        instruction = next(
            line for line in "".join(self.prompts).splitlines() if line.startswith("Type exactly: ")
        )
        return instruction.removeprefix("Type exactly: ") + "\n"


def _fixture_passphrases():
    return lambda _prompt: FIXTURE_PASSPHRASE


def _enroll(profile: str, *, terminal: FixtureTerminal | None = None):
    return enroll_named_identity(
        profile,
        terminal=terminal if terminal is not None else FixtureTerminal(),
        passphrase_provider=_fixture_passphrases(),
        acl_applier=lambda _path: None,
        key_provider_factory=FixtureKeyProvider,
    )


@pytest.fixture
def local_appdata(tmp_path, monkeypatch):
    """Redirect the default state root into ``tmp_path`` and enrol a fixture DID A."""
    base = tmp_path / "LocalAppData"
    base.mkdir()
    monkeypatch.setenv("LOCALAPPDATA", str(base))
    default_root = base / "TechnocoreAgent"
    initialize_local_identity(
        default_root,
        passphrase_provider=_fixture_passphrases(),
        acl_applier=lambda _path: None,
        key_provider_factory=FixtureKeyProvider,
    )
    return base


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


# --- profile name validation -------------------------------------------------


@pytest.mark.parametrize("profile", REJECTED_PROFILES)
def test_unsafe_profile_names_are_refused_not_normalized(profile):
    with pytest.raises(ProfileEnrollmentError) as excinfo:
        validate_profile(profile)
    assert "PROFILE_INVALID" in str(excinfo.value)


@pytest.mark.parametrize("profile", RESERVED_NAMES)
def test_reserved_profile_names_are_refused(profile):
    with pytest.raises(ProfileEnrollmentError) as excinfo:
        validate_profile(profile)
    assert "PROFILE_RESERVED" in str(excinfo.value)


@pytest.mark.parametrize("profile", ["abc", "phase3b-counterparty-b", "a_b-9", "a" * 64])
def test_reviewed_profile_names_are_accepted_unchanged(profile):
    assert validate_profile(profile) == profile


@pytest.mark.parametrize("profile", REJECTED_PROFILES + RESERVED_NAMES)
def test_unsafe_profile_names_never_reach_root_derivation(profile, local_appdata):
    with pytest.raises(ProfileEnrollmentError):
        derive_profile_root(profile)
    assert not (local_appdata / "TechnocoreAgent" / "identities").exists()


# --- namespace derivation and containment ------------------------------------


def test_profile_root_is_derived_inside_the_reviewed_namespace(local_appdata):
    root = derive_profile_root(PROFILE_A)
    namespace = (local_appdata / "TechnocoreAgent" / "identities").resolve()
    assert root == namespace / PROFILE_A
    assert root.parent == namespace
    assert root.is_relative_to(namespace)
    assert root != (local_appdata / "TechnocoreAgent").resolve()


def test_derivation_creates_nothing(local_appdata):
    before = _snapshot(local_appdata)
    derive_profile_root(PROFILE_A)
    assert not (local_appdata / "TechnocoreAgent" / "identities").exists()
    assert _snapshot(local_appdata) == before


def test_namespace_symlinked_outside_the_default_root_is_refused(local_appdata, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    namespace = local_appdata / "TechnocoreAgent" / "identities"
    try:
        namespace.symlink_to(elsewhere, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not permitted in this environment")
    with pytest.raises(ProfileEnrollmentError) as excinfo:
        derive_profile_root(PROFILE_A)
    assert "UNSAFE_IDENTITY_PATH" in str(excinfo.value) or "IDENTITY_NAMESPACE_ESCAPE" in str(
        excinfo.value
    )


def test_namespace_that_is_a_regular_file_is_refused(local_appdata):
    (local_appdata / "TechnocoreAgent" / "identities").write_text("x", encoding="utf-8")
    with pytest.raises(ProfileEnrollmentError) as excinfo:
        derive_profile_root(PROFILE_A)
    assert "UNSAFE_IDENTITY_PATH" in str(excinfo.value)


def test_profile_root_symlinked_outside_the_namespace_is_refused(local_appdata, tmp_path):
    elsewhere = tmp_path / "escape-target"
    elsewhere.mkdir()
    namespace = local_appdata / "TechnocoreAgent" / "identities"
    namespace.mkdir()
    try:
        (namespace / PROFILE_A).symlink_to(elsewhere, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not permitted in this environment")
    with pytest.raises(ProfileEnrollmentError) as excinfo:
        derive_profile_root(PROFILE_A)
    assert "PROFILE_ROOT_ESCAPE" in str(excinfo.value) or "UNSAFE_IDENTITY_PATH" in str(excinfo.value)


def test_default_root_collision_is_impossible(local_appdata):
    default_root = (local_appdata / "TechnocoreAgent").resolve()
    for profile in ("identities", "default", "..", "%LOCALAPPDATA%"):
        with pytest.raises(ProfileEnrollmentError):
            derive_profile_root(profile)
    root = derive_profile_root(PROFILE_A)
    assert root != default_root
    assert default_root not in [root, *root.parents[:1]]


def test_enrollment_requires_the_default_identity_first(tmp_path, monkeypatch):
    base = tmp_path / "EmptyLocalAppData"
    base.mkdir()
    monkeypatch.setenv("LOCALAPPDATA", str(base))
    with pytest.raises(ProfileEnrollmentError) as excinfo:
        _enroll(PROFILE_A)
    assert "DEFAULT_IDENTITY_NOT_INITIALIZED" in str(excinfo.value)
    assert not (base / "TechnocoreAgent" / "identities").exists()


# --- fixture end-to-end enrollment -------------------------------------------


def test_fixture_enrollment_end_to_end_creates_one_isolated_identity(local_appdata):
    default_root = local_appdata / "TechnocoreAgent"
    default_before = _snapshot(default_root)

    identity = _enroll(PROFILE_A)

    assert identity.status == "ENROLLED"
    assert identity.profile == PROFILE_A
    assert identity.root == (default_root / "identities" / PROFILE_A).resolve()
    assert identity.public_did.startswith("did:key:z6Mk")
    assert identity.public_key_fingerprint == hashlib.sha256(identity.public_did.encode()).hexdigest()
    assert (identity.root / "identity.dpapi").is_file()
    assert (identity.root / "local-install.json").is_file()
    assert not (identity.root / "nonces.json").exists()

    default_after = _snapshot(default_root)
    for name, payload in default_before.items():
        assert default_after[name] == payload
    assert set(default_after) - set(default_before) == {
        str(Path("identities") / PROFILE_A / "identity.dpapi"),
        str(Path("identities") / PROFILE_A / "operator.json"),
        str(Path("identities") / PROFILE_A / "local-install.json"),
    }


def test_two_profiles_yield_distinct_roots_dids_and_blobs(local_appdata):
    first = _enroll(PROFILE_A)
    second = _enroll(PROFILE_B)

    assert first.root != second.root
    assert first.public_did != second.public_did
    assert first.public_key_fingerprint != second.public_key_fingerprint
    assert (first.root / "identity.dpapi").read_bytes() != (second.root / "identity.dpapi").read_bytes()

    files_a = {str(p.resolve()) for p in first.root.rglob("*") if p.is_file()}
    files_b = {str(p.resolve()) for p in second.root.rglob("*") if p.is_file()}
    assert files_a and files_b
    assert files_a.isdisjoint(files_b)


def test_default_identity_did_differs_from_fixture_profiles(local_appdata):
    default_did = (local_appdata / "TechnocoreAgent" / "local-install.json").read_text(encoding="utf-8")
    identity = _enroll(PROFILE_A)
    assert identity.public_did not in default_did


def test_review_screen_shows_the_no_side_effect_contract(local_appdata):
    terminal = FixtureTerminal()
    identity = _enroll(PROFILE_A, terminal=terminal)
    screen = "".join(terminal.prompts)
    assert "TECHNOCORE AGENT — ADDITIONAL PROTECTED IDENTITY" in screen
    assert f"PROFILE:\n{PROFILE_A}" in screen
    assert f"STATE ROOT:\n{identity.root}" in screen
    assert "ACTION:\nCREATE ONE NEW PROTECTED DID" in screen
    for section in ("SIGNING", "NONCE", "NETWORK", "TECHNOCORE"):
        assert f"{section}:\nNONE" in screen
    assert f"{CONFIRMATION_PREFIX} {confirmation_code(PROFILE_A, identity.root)}" in screen


def test_confirmation_code_is_bound_to_profile_and_root(local_appdata):
    root_a = derive_profile_root(PROFILE_A)
    root_b = derive_profile_root(PROFILE_B)
    assert confirmation_code(PROFILE_A, root_a) != confirmation_code(PROFILE_B, root_b)
    assert confirmation_code(PROFILE_A, root_a) != confirmation_code(PROFILE_A, root_b)
    assert confirmation_code(PROFILE_A, root_a) == confirmation_code(PROFILE_A, root_a)


# --- existing profile semantics ----------------------------------------------


def test_existing_profile_is_reported_never_regenerated(local_appdata):
    first = _enroll(PROFILE_A)
    blob = (first.root / "identity.dpapi").read_bytes()
    marker = (first.root / "local-install.json").read_bytes()
    operator = (first.root / "operator.json").read_bytes()

    terminal = FixtureTerminal(attached=False)
    again = enroll_named_identity(
        PROFILE_A,
        terminal=terminal,
        passphrase_provider=lambda _prompt: pytest.fail("credential prompted for existing profile"),
        acl_applier=lambda _path: pytest.fail("ACL re-applied for existing profile"),
        key_provider_factory=lambda _path: pytest.fail("key provider used for existing profile"),
    )

    assert again.status == "ALREADY_ENROLLED"
    assert again.public_did == first.public_did
    assert again.public_key_fingerprint == first.public_key_fingerprint
    assert terminal.prompts == []
    assert (first.root / "identity.dpapi").read_bytes() == blob
    assert (first.root / "local-install.json").read_bytes() == marker
    assert (first.root / "operator.json").read_bytes() == operator


def test_corrupt_existing_marker_is_refused_without_touching_custody(local_appdata):
    first = _enroll(PROFILE_A)
    blob = (first.root / "identity.dpapi").read_bytes()
    (first.root / "local-install.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(ProfileEnrollmentError) as excinfo:
        _enroll(PROFILE_A)
    assert "EXISTING_MARKER_INVALID" in str(excinfo.value)
    assert (first.root / "identity.dpapi").read_bytes() == blob


# --- human-only gate ---------------------------------------------------------


def test_non_tty_refuses_before_any_custody(local_appdata):
    with pytest.raises(ProfileEnrollmentError) as excinfo:
        _enroll(PROFILE_A, terminal=FixtureTerminal(attached=False))
    assert "INTERACTIVE_TTY_REQUIRED" in str(excinfo.value)
    assert not (local_appdata / "TechnocoreAgent" / "identities" / PROFILE_A).exists()


def test_test_runner_default_terminal_refuses_real_enrollment(local_appdata):
    with pytest.raises(ProfileEnrollmentError) as excinfo:
        enroll_named_identity(
            PROFILE_A,
            passphrase_provider=lambda _prompt: pytest.fail("credential prompted under automation"),
            acl_applier=lambda _path: None,
            key_provider_factory=FixtureKeyProvider,
        )
    assert "INTERACTIVE_TTY_REQUIRED" in str(excinfo.value)
    assert not (local_appdata / "TechnocoreAgent" / "identities" / PROFILE_A).exists()


@pytest.mark.parametrize(
    "response",
    ["", "\n", "   \n", "yes\n", "y\n", "CREATE IDENTITY\n", "CREATE IDENTITY 00000000\n", "create identity abc\n"],
)
def test_blank_or_wrong_confirmation_refuses_before_any_custody(local_appdata, response):
    with pytest.raises(ProfileEnrollmentError) as excinfo:
        enroll_named_identity(
            PROFILE_A,
            terminal=FixtureTerminal(response=response),
            passphrase_provider=lambda _prompt: pytest.fail("credential prompted after wrong phrase"),
            acl_applier=lambda _path: None,
            key_provider_factory=FixtureKeyProvider,
        )
    assert "WRONG_ENROLLMENT_CONFIRMATION" in str(excinfo.value)
    assert not (local_appdata / "TechnocoreAgent" / "identities" / PROFILE_A).exists()


def test_credential_cancellation_leaves_no_enrolled_identity(local_appdata):
    def cancel(_prompt):
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        enroll_named_identity(
            PROFILE_A,
            terminal=FixtureTerminal(),
            passphrase_provider=cancel,
            acl_applier=lambda _path: None,
            key_provider_factory=FixtureKeyProvider,
        )
    root = local_appdata / "TechnocoreAgent" / "identities" / PROFILE_A
    assert not (root / "local-install.json").exists()


def test_mismatched_fixture_credentials_are_refused(local_appdata):
    answers = iter(["first fixture passphrase", "second fixture passphrase"])
    with pytest.raises(Exception) as excinfo:  # noqa: B017 - OperatorAuthError subclass
        enroll_named_identity(
            PROFILE_A,
            terminal=FixtureTerminal(),
            passphrase_provider=lambda _prompt: next(answers),
            acl_applier=lambda _path: None,
            key_provider_factory=FixtureKeyProvider,
        )
    assert "passphrase" in str(excinfo.value)
    root = local_appdata / "TechnocoreAgent" / "identities" / PROFILE_A
    assert not (root / "local-install.json").exists()


# --- CLI surface -------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--profile"],
        ["--profile", PROFILE_A, "--state", "C:\\anything"],
        ["--profile", PROFILE_A, "--root", "C:\\anything"],
        ["--state", "C:\\anything"],
        ["--profile", PROFILE_A, "--passphrase", "leak"],
        ["--profile", PROFILE_A, "--yes"],
        ["--profile", PROFILE_A, "--force"],
        ["--profile", PROFILE_A, "--non-interactive"],
        ["--profile", PROFILE_A, "--sign"],
        ["--profile", PROFILE_A, "--nonce", "1"],
        ["--profile", PROFILE_A, "--submit"],
        ["--profile", PROFILE_A, PROFILE_B],
    ],
)
def test_cli_refuses_unsupported_arguments(monkeypatch, local_appdata, argv):
    monkeypatch.setattr("sys.argv", ["technocore-agent-profile-init", *argv])
    with pytest.raises(SystemExit) as excinfo:
        profile_init.main()
    assert excinfo.value.code == 2
    assert not (local_appdata / "TechnocoreAgent" / "identities").exists()


def test_cli_exposes_only_the_profile_option():
    source = Path(profile_init.__file__).read_text(encoding="utf-8")
    assert source.count("add_argument(") == 1
    assert 'parser.add_argument("--profile"' in source
    for forbidden in ("--state", "--root", "--yes", "--force", "--non-interactive", "--passphrase"):
        assert forbidden not in source


def test_cli_refusal_is_reported_without_traceback(monkeypatch, local_appdata):
    monkeypatch.setattr("sys.argv", ["technocore-agent-profile-init", "--profile", "default"])
    with pytest.raises(SystemExit) as excinfo:
        profile_init.main()
    assert str(excinfo.value).startswith("REFUSED PROFILE_RESERVED")


@pytest.mark.parametrize(
    "variable", ["ENROLL", "PASSPHRASE", "TECHNOCORE_PASSPHRASE", "PROFILE", "CI", "FORCE"]
)
def test_environment_cannot_approve_or_supply_a_credential(local_appdata, monkeypatch, variable):
    monkeypatch.setenv(variable, "true")
    with pytest.raises(ProfileEnrollmentError) as excinfo:
        _enroll(PROFILE_A, terminal=FixtureTerminal(attached=False))
    assert "INTERACTIVE_TTY_REQUIRED" in str(excinfo.value)


# --- credential and secret boundaries ----------------------------------------


def test_no_output_or_artifact_reveals_the_credential(local_appdata, capsys, monkeypatch):
    identity = _enroll(PROFILE_A)
    monkeypatch.setattr("sys.argv", ["technocore-agent-profile-init", "--profile", PROFILE_A])
    profile_init.main()
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert FIXTURE_PASSPHRASE not in combined
    assert "PRIVATE" not in combined.replace("PRIVATE_KEY Windows DPAPI protected; not exported", "")
    assert identity.public_did in captured.out
    assert "ENROLLED=ALREADY_ENROLLED" in captured.out
    for path in (local_appdata / "TechnocoreAgent").rglob("*"):
        if path.is_file():
            assert FIXTURE_PASSPHRASE.encode() not in path.read_bytes()


def test_repr_of_result_carries_no_secret(local_appdata):
    identity = _enroll(PROFILE_A)
    assert FIXTURE_PASSPHRASE not in repr(identity)
    assert not hasattr(identity, "private_key")
    assert set(identity.__slots__) == {
        "profile",
        "root",
        "public_did",
        "public_key_fingerprint",
        "status",
    }


# --- no signing / nonce / transport ------------------------------------------


def test_module_source_has_no_signing_nonce_or_transport_route():
    source = Path(profile_init.__file__).read_text(encoding="utf-8")
    for forbidden in (
        "sign_room",
        "sign_room_detached",
        "execute_room",
        "NonceStore",
        "TechnocoreTransport",
        "nonces.json",
        "requests",
        "urllib",
        "http",
        "socket",
        "subprocess",
    ):
        assert forbidden not in source


def test_fixture_enrollment_leaves_no_nonce_ledger(local_appdata):
    identity = _enroll(PROFILE_A)
    assert not (identity.root / "nonces.json").exists()
    assert sorted(p.name for p in identity.root.iterdir()) == [
        "identity.dpapi",
        "local-install.json",
        "operator.json",
    ]
