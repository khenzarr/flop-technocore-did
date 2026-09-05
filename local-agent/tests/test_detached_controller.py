from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_agent.signer.detached_controller import (
    PURPOSE,
    SCHEMA,
    DetachedRequest,
    run_detached_signing,
)
from technocore_agent.storage.nonce import NonceStore


class FixtureCustody:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def load_or_create(self) -> Ed25519PrivateKey:
        self.calls.append("load_or_create")
        return Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


def request(commit: str = "a" * 40) -> DetachedRequest:
    return DetachedRequest.from_mapping({
        "schema": SCHEMA,
        "requestId": "fixture-request",
        "room": "fixture-room",
        "text": "fixture text",
        "expectedCanonicalCommit": commit,
        "purpose": PURPOSE,
    })


def test_fixture_production_controller_signs_and_consumes_local_nonce(tmp_path: Path) -> None:
    calls: list[str] = []
    nonce = NonceStore(tmp_path / "nonces.json")
    operation = run_detached_signing(request(), FixtureCustody(calls), nonce,
                                     actual_canonical_commit="a" * 40)
    assert operation.nonce == 1
    assert calls == ["load_or_create"]
    assert nonce.reserve("fixture-room") == 2


def test_controller_rejects_commit_and_purpose_before_custody(tmp_path: Path) -> None:
    calls: list[str] = []
    provider = FixtureCustody(calls)
    with pytest.raises(ValueError, match="does not match"):
        run_detached_signing(request(), provider, NonceStore(tmp_path / "n.json"),
                             actual_canonical_commit="b" * 40)
    with pytest.raises(PermissionError):
        run_detached_signing(request(), provider, NonceStore(tmp_path / "n2.json"),
                             actual_canonical_commit="a" * 40, operator_context="wrong")
    assert calls == []


def test_controller_has_no_transport_or_submission_path(tmp_path: Path) -> None:
    operation = run_detached_signing(request(), FixtureCustody([]), NonceStore(tmp_path / "n.json"),
                                     actual_canonical_commit="a" * 40)
    assert operation.signature
