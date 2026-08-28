from __future__ import annotations

import json

MAX_ROOM_CHARS = 256
MAX_TEXT_CHARS = 4096
MAX_REQUEST_ID_CHARS = 128


class IPCError(ValueError):
    pass


def decode_request(raw: bytes) -> dict:
    if not isinstance(raw, bytes) or len(raw) > 16 * 1024:
        raise IPCError("request is too large")
    try:
        item = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IPCError("invalid request") from exc
    if not isinstance(item, dict) or set(item) - {
        "operation",
        "room",
        "text",
        "request_id",
    }:
        raise IPCError("request schema is invalid")
    if item.get("operation") != "sign_room" or not all(
        isinstance(item.get(k), str) for k in ("room", "text", "request_id")
    ):
        raise IPCError("only sign_room with safe string fields is supported")
    if not 1 <= len(item["room"]) <= MAX_ROOM_CHARS:
        raise IPCError("room is too long")
    if not 1 <= len(item["text"]) <= MAX_TEXT_CHARS:
        raise IPCError("text is too long")
    if not 1 <= len(item["request_id"]) <= MAX_REQUEST_ID_CHARS:
        raise IPCError("request_id is invalid")
    return item


def encode_response(item: dict) -> bytes:
    if any(
        term in json.dumps(item).lower() for term in ("private", "passphrase", "protected_blob")
    ):
        raise IPCError("secret-bearing response rejected")
    return (json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n").encode()
