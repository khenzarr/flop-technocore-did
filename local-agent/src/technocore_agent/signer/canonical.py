from __future__ import annotations

import unicodedata

MAX_TEXT_CHARS = 4096
_INVISIBLE = ("Cc", "Cf", "Cs", "Co", "Zl", "Zp")


class SignerInputError(ValueError):
    pass


def clean_text(text: str) -> str:
    if not isinstance(text, str):
        raise SignerInputError("text must be a string")
    result = "".join(" " if unicodedata.category(c) in _INVISIBLE else c for c in text).strip()
    if not result:
        raise SignerInputError("text must contain visible characters")
    if len(result) > MAX_TEXT_CHARS:
        raise SignerInputError("text exceeds the character limit")
    return result


def canonical_message(room: str, nonce: int, text: str) -> str:
    if not isinstance(room, str) or not room or "|" in room:
        raise SignerInputError("room is invalid")
    if not isinstance(nonce, int) or isinstance(nonce, bool) or not 1 <= nonce < 10**19:
        raise SignerInputError("nonce is invalid")
    return f"{room}|{nonce}|{clean_text(text)}"
