from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from ..storage.nonce import _file_lock
from .drafts import Draft


class ApprovalError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Approval:
    approval_id: str
    draft_id: str
    approved_at: float
    session_id_hash: str
    draft_fingerprint: str
    status: str = "APPROVED"


class ApprovalStore:
    """Trusted control-plane records. Raw session credentials never enter this store."""

    def __init__(self, path: Path) -> None:
        self.path, self._lock = Path(path), threading.Lock()

    def create(self, draft: Draft, session_id_hash: str) -> Approval:
        if draft.status != "PENDING":
            raise ApprovalError("only pending drafts can be approved")
        with self._exclusive():
            records = self._read()
            if any(
                item["draft_id"] == draft.draft_id and item["status"] != "CONSUMED"
                for item in records.values()
            ):
                raise ApprovalError("draft already has an active approval")
            approval = Approval(
                str(uuid.uuid4()), draft.draft_id, time.time(), session_id_hash, draft.fingerprint
            )
            records[approval.approval_id] = (
                approval.__dict__
                if hasattr(approval, "__dict__")
                else {
                    "approval_id": approval.approval_id,
                    "draft_id": approval.draft_id,
                    "approved_at": approval.approved_at,
                    "session_id_hash": approval.session_id_hash,
                    "draft_fingerprint": approval.draft_fingerprint,
                    "status": approval.status,
                }
            )
            self._write(records)
            return approval

    def consume(self, approval_id: str, draft: Draft) -> Approval:
        with self._exclusive():
            records = self._read()
            item = records.get(approval_id)
            if item is None or item["status"] != "APPROVED":
                raise ApprovalError("approval is missing, consumed, or invalid")
            if (
                draft.status != "APPROVED"
                or item["draft_id"] != draft.draft_id
                or item["draft_fingerprint"] != draft.fingerprint
            ):
                raise ApprovalError("approval does not bind to the exact approved draft")
            item["status"] = "CONSUMED"
            self._write(records)
            return Approval(**item)

    def get(self, approval_id: str) -> Approval | None:
        item = self._read().get(approval_id)
        return Approval(**item) if item else None

    def for_draft(self, draft_id: str) -> Approval | None:
        matches = [
            Approval(**item) for item in self._read().values() if item["draft_id"] == draft_id
        ]
        return max(matches, key=lambda item: item.approved_at) if matches else None

    def validate_consumed(self, approval: Approval) -> None:
        stored = self.get(approval.approval_id)
        if stored != approval or stored is None or stored.status != "CONSUMED":
            raise ApprovalError("approval is not a valid consumed trusted record")

    def _exclusive(self):
        return _ApprovalLock(self, self.path.with_suffix(self.path.suffix + ".lock"))

    def _read(self) -> dict[str, dict]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, json.JSONDecodeError) as exc:
            raise ApprovalError("approval state cannot be read") from exc
        if not isinstance(value, dict):
            raise ApprovalError("approval state is corrupt")
        return value

    def _write(self, records: dict[str, dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(records, stream, sort_keys=True, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.path)
        except OSError as exc:
            try:
                os.unlink(name)
            except OSError:
                pass
            raise ApprovalError("approval state cannot be committed") from exc


class _ApprovalLock:
    def __init__(self, store, path):
        self.store, self.file_lock = store, _file_lock(path)

    def __enter__(self):
        self.store._lock.acquire()
        self.file_lock.__enter__()
        return self

    def __exit__(self, *_):
        self.file_lock.__exit__(*_)
        self.store._lock.release()
