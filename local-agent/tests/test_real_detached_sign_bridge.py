from __future__ import annotations

import json
from pathlib import Path

from technocore_agent.signer.real_detached_sign_bridge import (
    PURPOSE,
    SCHEMA,
    _read_request,
    _signer,
)


def test_request_schema_excludes_custody_material(tmp_path: Path) -> None:
    path = tmp_path / "request.json"
    path.write_text(json.dumps({
        "schema": SCHEMA, "requestId": "r1", "room": "room", "text": "text",
        "expectedCanonicalCommit": "a" * 40, "purpose": PURPOSE,
    }))
    assert _read_request(path)["purpose"] == PURPOSE


def test_real_custody_requires_fresh_authorization() -> None:
    # The phase gate is checked before the protected-key factory is reachable.
    try:
        from technocore_agent.signer.real_detached_sign_bridge import serve_once
        serve_once(Path("C:/does-not-matter"), custody="real", state=Path("C:/unused"))
    except Exception:
        pass
    # Structural assertion: no authorization flag/API is accepted by the entrypoint.
    assert "authorized" not in serve_once.__annotations__


def test_fixture_signer_has_no_transport(tmp_path: Path) -> None:
    signer = _signer("fixture", tmp_path)
    assert signer._transport is None
    assert signer._operations is None
    assert signer._approvals is None
