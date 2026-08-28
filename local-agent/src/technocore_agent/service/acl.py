"""Narrow Stage2D effective-rights model for Windows path evidence.

This intentionally models only the rights needed by the proof. It is not a
replacement for the Windows authorization engine.
"""

from __future__ import annotations

from dataclasses import dataclass

FILE_WRITE_DATA = 0x0002
FILE_APPEND_DATA = 0x0004
FILE_WRITE_EA = 0x0010
FILE_WRITE_ATTRIBUTES = 0x0100
DELETE_CHILD = 0x0040
WRITE_DAC = 0x40000
WRITE_OWNER = 0x80000
MODIFY = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE_CHILD
FULL_CONTROL = 0x1F01FF


@dataclass(frozen=True, slots=True)
class AccessAce:
    sid: str
    mask: int
    allow: bool
    inherited: bool = False


def effective_rights(aces: list[AccessAce], token_sids: set[str]) -> dict[str, bool]:
    """Apply deny-before-allow per bit for the Stage2D assertion set."""
    relevant = [ace for ace in aces if ace.sid in token_sids]
    denied = 0
    allowed = 0
    for ace in relevant:
        if ace.allow:
            allowed |= ace.mask & ~denied
        else:
            denied |= ace.mask
            allowed &= ~ace.mask
    return {
        "FILE_WRITE_DATA": bool(allowed & FILE_WRITE_DATA),
        "FILE_APPEND_DATA": bool(allowed & FILE_APPEND_DATA),
        "FILE_WRITE_ATTRIBUTES": bool(allowed & FILE_WRITE_ATTRIBUTES),
        "FILE_WRITE_EA": bool(allowed & FILE_WRITE_EA),
        "DELETE_CHILD": bool(allowed & DELETE_CHILD),
        "WRITE_DAC": bool(allowed & WRITE_DAC),
        "WRITE_OWNER": bool(allowed & WRITE_OWNER),
        "Modify": (allowed & MODIFY) == MODIFY,
        "FullControl": (allowed & FULL_CONTROL) == FULL_CONTROL,
    }


def assert_normal_user_denied(aces: list[AccessAce], token_sids: set[str]) -> dict[str, bool]:
    """Return the narrow Stage2D assertion; raise if any protected right grants."""
    rights = effective_rights(aces, token_sids)
    granted = [name for name, value in rights.items() if value]
    if granted:
        raise PermissionError("normal-user protected rights granted: " + ", ".join(granted))
    return rights
