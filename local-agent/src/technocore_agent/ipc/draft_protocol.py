from __future__ import annotations

import json

from .protocol import MAX_REQUEST_ID_CHARS, MAX_ROOM_CHARS, MAX_TEXT_CHARS, IPCError

_SUBMIT_FIELDS = frozenset({"operation", "request_id", "room", "text"})
_STATUS_FIELDS = frozenset({"operation", "request_id"})
_FORBIDDEN_TERMS = frozenset(
    {
        "approve",
        "human_reviewed",
        "operator_auth",
        "consume",
        "sign",
        "publish",
        "private_key",
        "recovery",
        "state_path",
    }
)


def decode_agent_request(raw: bytes) -> dict[str, str]:
    """Decode the complete, intentionally untrusted, agent capability surface."""
    if not isinstance(raw, bytes) or not raw or len(raw) > 16 * 1024:
        raise IPCError("request is invalid")
    try:
        item = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IPCError("request is invalid") from exc
    if not isinstance(item, dict) or not all(isinstance(k, str) for k in item):
        raise IPCError("request schema is invalid")
    operation = item.get("operation")
    expected = {
        "submit_draft": _SUBMIT_FIELDS,
        "get_own_draft_status": _STATUS_FIELDS,
    }.get(operation)
    if expected is None or set(item) != expected:
        raise IPCError("operation or request schema is not allowed")
    lowered = {key.lower() for key in item}
    if lowered & _FORBIDDEN_TERMS:
        raise IPCError("privileged semantics are not allowed")
    request_id = item.get("request_id")
    if not isinstance(request_id, str) or not 1 <= len(request_id) <= MAX_REQUEST_ID_CHARS:
        raise IPCError("request_id is invalid")
    if operation == "submit_draft":
        room, text = item.get("room"), item.get("text")
        if not isinstance(room, str) or not 1 <= len(room) <= MAX_ROOM_CHARS:
            raise IPCError("room is invalid")
        if not isinstance(text, str) or not 1 <= len(text) <= MAX_TEXT_CHARS:
            raise IPCError("text is invalid")
    return item


def encode_agent_response(item: dict) -> bytes:
    allowed = {"draft_id", "request_id", "status", "error"}
    if not isinstance(item, dict) or set(item) - allowed:
        raise IPCError("unsafe response")
    return (json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n").encode()
