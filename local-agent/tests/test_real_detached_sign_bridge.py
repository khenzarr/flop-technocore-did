from __future__ import annotations

import base64
import io
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_agent.signer import real_detached_sign_bridge as bridge
from technocore_agent.signer.canonical import canonical_message
from technocore_agent.signer.real_detached_sign_bridge import (
    PURPOSE,
    SCHEMA,
    FixtureApproval,
    TerminalApproval,
    _confirmation_suffix,
    _read_request,
    _require_canonical_operator,
    _signer,
    serve_once,
)

COMMIT = "a" * 40


def request_item(**overrides: str) -> dict[str, str]:
    item: dict[str, str] = {
        "schema": SCHEMA, "requestId": "r1", "room": "fixture-room", "text": "fixture text",
        "expectedCanonicalCommit": COMMIT, "purpose": PURPOSE,
    }
    item.update(overrides)
    return item


def write_request(tmp_path: Path, **overrides: str) -> Path:
    path = tmp_path / "request.json"
    path.write_text(json.dumps(request_item(**overrides)), encoding="utf-8")
    return path


@pytest.fixture()
def custody_sentinel(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record every custody-provider construction so refusals can be proven to precede it."""
    calls: list[str] = []
    real_provider = bridge._provider

    def tracking(mode: str, state: Path):
        calls.append(mode)
        return real_provider(mode, state)

    monkeypatch.setattr(bridge, "_provider", tracking)
    monkeypatch.setattr(bridge, "_actual_commit", lambda: COMMIT)
    monkeypatch.setattr(bridge, "_clean_relevant_tree", lambda: None)
    return calls


def run(tmp_path: Path, *, custody: str = "fixture", approval=None, **overrides: str) -> dict:
    path = write_request(tmp_path, **overrides)
    out = io.StringIO()
    stdout = bridge.sys.stdout
    bridge.sys.stdout = out
    try:
        serve_once(path, custody=custody, state=tmp_path,
                   approval=FixtureApproval() if approval is None else approval)
    finally:
        bridge.sys.stdout = stdout
    return json.loads(out.getvalue())


def test_request_schema_excludes_custody_material(tmp_path: Path) -> None:
    item = _read_request(write_request(tmp_path))
    assert item["purpose"] == PURPOSE
    assert not {"approved", "approval", "passphrase", "privateKey", "seed"} & set(item)


def test_full_enabled_route_with_fixture_custody_signs_and_verifies(
    tmp_path: Path, custody_sentinel: list[str]
) -> None:
    response = run(tmp_path)
    assert custody_sentinel == ["fixture"]
    assert response["custodyMode"] == "fixture"
    assert response["nonce"] == 1
    key = Ed25519PrivateKey.from_private_bytes(bridge.FIXTURE_KEY)
    message = canonical_message(response["room"], response["nonce"], response["text"])
    key.public_key().verify(
        base64.urlsafe_b64decode(response["signature"] + "=="), message.encode()
    )


def test_confirmation_phrase_is_request_bound_and_not_reusable(tmp_path: Path) -> None:
    first = _confirmation_suffix(request_item())
    assert first != _confirmation_suffix(request_item(text="other text"))
    assert first != _confirmation_suffix(request_item(room="other-room"))
    assert first != _confirmation_suffix(request_item(requestId="r2"))


def test_direct_child_non_tty_refuses_before_custody(
    tmp_path: Path, custody_sentinel: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bridge.sys, "stdin", io.StringIO(f"{bridge.APPROVAL_PREFIX} X\n"))
    with pytest.raises(PermissionError, match="INTERACTIVE_TTY_REQUIRED"):
        _require_canonical_operator(request_item(), TerminalApproval())
    assert run(tmp_path, approval=TerminalApproval())["error"].startswith("INTERACTIVE_TTY_REQUIRED")
    assert custody_sentinel == []


def test_direct_child_wrong_blank_and_piped_approval_refuse_before_custody(
    tmp_path: Path, custody_sentinel: list[str]
) -> None:
    for response in ("wrong", "blank"):
        assert "WRONG_CANONICAL_APPROVAL" in run(tmp_path, approval=FixtureApproval(response))["error"]
    assert custody_sentinel == []


def test_real_custody_rejects_non_terminal_approval_channel(
    tmp_path: Path, custody_sentinel: list[str]
) -> None:
    error = run(tmp_path, custody="real", approval=FixtureApproval())["error"]
    assert "operator terminal approval channel" in error
    assert custody_sentinel == []


def test_wrong_commit_dirty_tree_malformed_and_purpose_refuse_before_custody(
    tmp_path: Path, custody_sentinel: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert "does not match expected commit" in run(tmp_path, expectedCanonicalCommit="b" * 40)["error"]
    assert "purpose or schema is invalid" in run(tmp_path, purpose="OTHER")["error"]
    assert "schema is invalid" in run(tmp_path, extra="x")["error"]
    assert "custody mode is invalid" in run(tmp_path, custody="other")["error"]
    monkeypatch.setattr(bridge, "_clean_relevant_tree",
                        lambda: (_ for _ in ()).throw(ValueError("canonical relevant worktree is dirty")))
    assert "worktree is dirty" in run(tmp_path)["error"]
    assert custody_sentinel == []


def test_response_channel_carries_no_prompt_and_errors_stay_sanitized(
    tmp_path: Path, custody_sentinel: list[str]
) -> None:
    channel = FixtureApproval()
    response = run(tmp_path, approval=channel)
    assert "CANONICAL PROTECTED CUSTODY" in channel._prompt
    assert "WILL BE CONSUMED" in channel._prompt
    assert response["signature"] not in channel._prompt


def test_fixture_signer_has_no_transport(tmp_path: Path) -> None:
    signer = _signer("fixture", tmp_path)
    assert signer._transport is None
    assert signer._operations is None
    assert signer._approvals is None
