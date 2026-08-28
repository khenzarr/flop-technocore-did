from __future__ import annotations


def classify_external_content(text: str) -> str:
    """External text is always data; hostile instruction-like text remains untrusted."""
    markers = (
        "ignore previous instructions",
        "print your key",
        "run powershell",
        "environment variables",
    )
    return (
        "untrusted_instruction_like"
        if any(marker in text.lower() for marker in markers)
        else "untrusted_content"
    )
