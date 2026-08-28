from __future__ import annotations

import argparse
import base64
import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

COMMIT_PATTERN = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class ContributionProofError(ValueError):
    pass


def contribution_payload(artifact_url: str, commit: str) -> bytes:
    if not isinstance(artifact_url, str) or artifact_url != artifact_url.strip():
        raise ContributionProofError("artifact URL must be a trimmed string")
    try:
        parsed = urlsplit(artifact_url)
        _port = parsed.port
    except ValueError as exc:
        raise ContributionProofError("artifact URL is malformed") from exc
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ContributionProofError(
            "artifact URL must be absolute HTTPS without credentials or a fragment"
        )
    if not isinstance(commit, str) or COMMIT_PATTERN.fullmatch(commit) is None:
        raise ContributionProofError("commit must be a complete 40- or 64-character hex revision")
    record = {
        "artifact_url": artifact_url,
        "commit": commit.lower(),
        "schema": "technocore-contribution-v1",
    }
    return json.dumps(
        record, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()


def create_contribution_proof(
    key: Ed25519PrivateKey, did: str, artifact_url: str, commit: str
) -> dict[str, str]:
    payload = contribution_payload(artifact_url, commit)
    signature = base64.urlsafe_b64encode(key.sign(payload)).decode().rstrip("=")
    proof = {
        "schema": "technocore-contribution-proof-v1",
        "did": did,
        "artifact_url": artifact_url,
        "commit": commit.lower(),
        "signature": signature,
    }
    verify_contribution_proof(proof)
    return proof


def verify_contribution_proof(proof: dict) -> None:
    if not isinstance(proof, dict) or set(proof) != {
        "schema",
        "did",
        "artifact_url",
        "commit",
        "signature",
    }:
        raise ContributionProofError("proof has an invalid field set")
    if proof.get("schema") != "technocore-contribution-proof-v1":
        raise ContributionProofError("proof schema is unsupported")
    if any(not isinstance(proof.get(field), str) for field in proof):
        raise ContributionProofError("proof fields must be strings")
    payload = contribution_payload(proof["artifact_url"], proof["commit"])
    public_key = _public_key_from_did(proof["did"])
    signature = proof["signature"]
    if not re.fullmatch(r"[A-Za-z0-9_-]{86}", signature):
        raise ContributionProofError("proof signature is malformed")
    try:
        public_key.verify(base64.urlsafe_b64decode(signature + "=="), payload)
    except (InvalidSignature, ValueError) as exc:
        raise ContributionProofError("proof signature is invalid") from exc


def write_new_proof(path: Path, proof: dict) -> Path:
    verify_contribution_proof(proof)
    resolved = Path(path).resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(proof, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    descriptor = None
    created = False
    try:
        descriptor = os.open(resolved, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ContributionProofError("refusing to overwrite an existing proof") from exc
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        if created:
            try:
                resolved.unlink(missing_ok=True)
            except OSError:
                pass
        raise ContributionProofError("proof file could not be committed") from exc
    return resolved


def _public_key_from_did(did: str) -> Ed25519PublicKey:
    if not isinstance(did, str) or not did.startswith("did:key:z6Mk") or len(did) != 56:
        raise ContributionProofError("proof DID is malformed")
    number = 0
    encoded = did.removeprefix("did:key:z")
    try:
        for character in encoded:
            number = number * 58 + _B58.index(character)
    except ValueError as exc:
        raise ContributionProofError("proof DID is malformed") from exc
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big")
    decoded = (b"\0" * (len(encoded) - len(encoded.lstrip("1")))) + decoded
    if len(decoded) != 34 or decoded[:2] != b"\xed\x01":
        raise ContributionProofError("proof DID is not an Ed25519 did:key")
    return Ed25519PublicKey.from_public_bytes(decoded[2:])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a public Technocore contribution proof")
    parser.add_argument("proof_file", type=Path)
    args = parser.parse_args(argv)
    try:
        raw = args.proof_file.resolve().read_bytes()
        if len(raw) > 16_384:
            raise ContributionProofError("proof file exceeds the bounded limit")
        proof = json.loads(raw.decode("utf-8"))
        verify_contribution_proof(proof)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ContributionProofError) as exc:
        parser.exit(1, f"invalid proof: {exc}\n")
    print(f"valid proof for {proof['did']}")
    return 0
