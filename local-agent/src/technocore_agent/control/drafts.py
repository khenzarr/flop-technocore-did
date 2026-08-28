from __future__ import annotations

import builtins
import hashlib
import json
import os
import tempfile
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

from ..signer.canonical import clean_text
from ..storage.nonce import _file_lock


class DraftError(ValueError):
    pass


def draft_fingerprint(operation: str, room: str, cleaned_text: str) -> str:
    return hashlib.sha256(f"{operation}\0{room}\0{cleaned_text}".encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class Draft:
    draft_id: str
    external_request_id: str
    operation: str
    room: str
    cleaned_text: str
    created_at: float
    source: str
    status: str
    fingerprint: str


class DraftStore:
    """Durable, non-secret proposed work owned by the untrusted agent boundary."""

    STATUSES = frozenset({"PENDING", "APPROVED", "REJECTED", "EXPIRED", "CONSUMED"})

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def create(
        self, external_request_id: str, operation: str, room: str, text: str, source: str
    ) -> Draft:
        if not all(
            isinstance(value, str) and value for value in (external_request_id, room, source)
        ):
            raise DraftError("draft identifiers and source must be non-empty strings")
        if operation != "sign_room":
            raise DraftError("only sign_room drafts are supported")
        cleaned = clean_text(text)
        fingerprint = draft_fingerprint(operation, room, cleaned)
        with self._locked():
            records = self._read()
            for item in records.values():
                if item["external_request_id"] == external_request_id:
                    if item["fingerprint"] != fingerprint:
                        raise DraftError("external request id conflicts with an existing draft")
                    if item["status"] in {"REJECTED", "EXPIRED"}:
                        raise DraftError(
                            "terminal draft cannot be reactivated; use a new external request id"
                        )
                    return Draft(**item)
            item = Draft(
                str(uuid.uuid4()),
                external_request_id,
                operation,
                room,
                cleaned,
                time.time(),
                source,
                "PENDING",
                fingerprint,
            )
            records[item.draft_id] = asdict(item)
            self._write(records)
            return item

    def get(self, draft_id: str) -> Draft | None:
        item = self._read().get(draft_id)
        return Draft(**item) if item else None

    def list(self, statuses: set[str] | None = None) -> builtins.list[Draft]:
        records = [Draft(**item) for item in self._read().values()]
        return [item for item in records if statuses is None or item.status in statuses]

    def transition(self, draft_id: str, status: str) -> Draft:
        if status not in self.STATUSES:
            raise DraftError("invalid draft status")
        with self._locked():
            records = self._read()
            item = records.get(draft_id)
            if item is None:
                raise DraftError("unknown draft")
            allowed = {
                "PENDING": {"APPROVED", "REJECTED", "EXPIRED"},
                "APPROVED": {"CONSUMED"},
                "REJECTED": set(),
                "EXPIRED": set(),
                "CONSUMED": set(),
            }
            if status not in allowed[item["status"]]:
                raise DraftError(f"invalid draft transition: {item['status']} -> {status}")
            item["status"] = status
            self._write(records)
            return Draft(**item)

    def _locked(self):
        return _StoreLock(self, self.path.with_suffix(self.path.suffix + ".lock"))

    def _read(self) -> dict[str, dict]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, json.JSONDecodeError) as exc:
            raise DraftError("draft state cannot be read") from exc
        if not isinstance(value, dict) or any(not isinstance(v, dict) for v in value.values()):
            raise DraftError("draft state is corrupt")
        return value

    def _write(self, records: dict) -> None:
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
            raise DraftError("draft state cannot be committed") from exc


class _StoreLock:
    def __init__(self, store: DraftStore, path: Path) -> None:
        self.store, self.file_lock = store, _file_lock(path)

    def __enter__(self):
        self.store._lock.acquire()
        self.file_lock.__enter__()
        return self

    def __exit__(self, *_):
        self.file_lock.__exit__(*_)
        self.store._lock.release()
