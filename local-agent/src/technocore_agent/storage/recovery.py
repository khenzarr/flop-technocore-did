from __future__ import annotations

import base64
import json
import secrets
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

VERSION = 1
N, R, P = 2**14, 8, 1


class RecoveryError(ValueError):
    pass


def _key(passphrase: bytes, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=N, r=R, p=P).derive(passphrase)


def create(key: bytes, passphrase_provider) -> bytes:
    password = passphrase_provider()
    if not isinstance(password, bytes) or not password:
        raise RecoveryError("passphrase provider returned invalid data")
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    header = {"version": VERSION, "kdf": "scrypt", "n": N, "r": R, "p": P}
    aad = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    encrypted = AESGCM(_key(password, salt)).encrypt(nonce, key, aad)
    return json.dumps(
        {
            **header,
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(encrypted).decode(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def restore(bundle: bytes, passphrase_provider) -> bytes:
    try:
        item = json.loads(bundle)
        if not isinstance(item, dict):
            raise RecoveryError("recovery bundle is invalid")
        if item.get("version") != VERSION or item.get("kdf") != "scrypt":
            raise RecoveryError("unsupported recovery bundle")
        if (item["n"], item["r"], item["p"]) != (N, R, P):
            raise RecoveryError("unsupported KDF parameters")
        salt = base64.b64decode(item["salt"], validate=True)
        nonce = base64.b64decode(item["nonce"], validate=True)
        ciphertext = base64.b64decode(item["ciphertext"], validate=True)
        aad = json.dumps(
            {k: item[k] for k in ("kdf", "n", "p", "r", "version")},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        password = passphrase_provider()
        return AESGCM(_key(password, salt)).decrypt(nonce, ciphertext, aad)
    except RecoveryError:
        raise
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, InvalidTag):
        raise RecoveryError("recovery bundle is invalid or authentication failed") from None


def write(path: Path, key: bytes, provider) -> None:
    Path(path).write_bytes(create(key, provider))


def read(path: Path, provider) -> bytes:
    try:
        return restore(Path(path).read_bytes(), provider)
    except FileNotFoundError as exc:
        raise RecoveryError("recovery bundle is missing") from exc
