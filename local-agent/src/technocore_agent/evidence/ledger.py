from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path

SAFE_FIELDS = frozenset(
    {
        "schema_version",
        "record_id",
        "timestamp_utc",
        "signer_version",
        "public_did",
        "did_fingerprint",
        "operation",
        "public_room",
        "nonce",
        "result_class",
        "text_hash",
        "text_length",
        "local_request_id",
        "reconciliation_status",
        "server_sequence",
        "server_timestamp",
    }
)


class LedgerError(ValueError):
    pass


class Ledger:
    def __init__(self, path: Path, signer_version: str = "local-0.1") -> None:
        self.path, self.signer_version = Path(path), signer_version
        self._lock = threading.Lock()

    def append(
        self,
        *,
        public_did: str,
        room: str,
        nonce: int,
        text: str,
        result_class: str,
        request_id: str,
        reconciliation_status: str,
        text_hash: str | None = None,
        text_length: int | None = None,
        server_sequence: int | None = None,
        server_timestamp: str | None = None,
    ) -> dict:
        record = {
            "schema_version": 1,
            "record_id": str(uuid.uuid4()),
            "timestamp_utc": datetime.now(UTC).isoformat(),
            "signer_version": self.signer_version,
            "public_did": public_did,
            "did_fingerprint": hashlib.sha256(public_did.encode()).hexdigest(),
            "operation": "sign_room",
            "public_room": room,
            "nonce": nonce,
            "result_class": result_class,
            "text_hash": text_hash
            if text_hash is not None
            else hashlib.sha256(text.encode()).hexdigest(),
            "text_length": text_length if text_length is not None else len(text),
            "local_request_id": request_id,
            "reconciliation_status": reconciliation_status,
            "server_sequence": server_sequence,
            "server_timestamp": server_timestamp,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        return record

    def read(self) -> list[dict]:
        if not self.path.exists():
            return []
        records = []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                if index == len(lines) - 1:
                    break
                continue
            if isinstance(item, dict) and set(item) <= SAFE_FIELDS:
                records.append(item)
        return records
