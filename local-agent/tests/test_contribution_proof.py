from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_agent.evidence.contribution import (
    ContributionProofError,
    contribution_payload,
    create_contribution_proof,
    main,
    verify_contribution_proof,
    write_new_proof,
)
from technocore_agent.signer.service import canonical_did


def _key():
    return Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


def test_proof_is_zun_compatible_deterministic_and_self_verifying():
    key = _key()
    did = canonical_did(key)
    repository = "https://github.com/khenzarr/flop-technocore-did"
    commit = "9aa6803e52d8c91de07e9b76bb481e75c77b7b55"
    proof = create_contribution_proof(key, did, repository, commit)
    assert proof == create_contribution_proof(key, did, repository, commit.upper())
    assert json.loads(contribution_payload(repository, commit)) == {
        "artifact_url": repository,
        "commit": commit,
        "schema": "technocore-contribution-v1",
    }
    verify_contribution_proof(proof)


@pytest.mark.parametrize("field", ["did", "artifact_url", "commit", "signature"])
def test_proof_mutations_are_rejected(field):
    key = _key()
    proof = create_contribution_proof(
        key,
        canonical_did(key),
        "https://github.com/khenzarr/flop-technocore-did",
        "9aa6803e52d8c91de07e9b76bb481e75c77b7b55",
    )
    proof[field] = proof[field][:-1] + ("0" if proof[field][-1] != "0" else "1")
    with pytest.raises(ContributionProofError):
        verify_contribution_proof(proof)


def test_proof_file_is_exclusive_and_contains_no_private_material(tmp_path):
    key = _key()
    proof = create_contribution_proof(
        key,
        canonical_did(key),
        "https://github.com/khenzarr/flop-technocore-did",
        "9aa6803e52d8c91de07e9b76bb481e75c77b7b55",
    )
    path = tmp_path / "contribution-proof.json"
    assert write_new_proof(path, proof) == path.resolve()
    raw = path.read_text(encoding="utf-8")
    assert bytes(range(32)).hex() not in raw
    verify_contribution_proof(json.loads(raw))
    with pytest.raises(ContributionProofError, match="overwrite"):
        write_new_proof(path, proof)
    assert main([str(path)]) == 0


@pytest.mark.parametrize(
    "url,commit",
    [
        ("http://github.com/example/repo", "0" * 40),
        ("https://user@github.com/example/repo", "0" * 40),
        ("https://github.com/example/repo#main", "0" * 40),
        ("https://github.com/example/repo", "short"),
    ],
)
def test_proof_inputs_fail_closed(url, commit):
    with pytest.raises(ContributionProofError):
        contribution_payload(url, commit)
