from __future__ import annotations

import hashlib
import json
import msvcrt
import os
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path


class NonceError(ValueError):
    pass


@contextmanager
def _file_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as stream:
        if stream.tell() == 0:
            stream.write(b"\0")
            stream.flush()
        while True:
            try:
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                break
            except OSError:
                time.sleep(0.001)
        try:
            yield
        finally:
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)


class NonceStore:
    def __init__(self, path: Path, fault=None) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self.fault = fault

    def reserve(self, lane: str, request_id: str | None = None) -> int:
        if not isinstance(lane, str) or not lane or "|" in lane:
            raise NonceError("invalid nonce lane")
        with self._lock:
            lock_path = self.path.with_suffix(self.path.suffix + ".lock")
            with _file_lock(lock_path):
                state = self._read_reservation_state()
                reservations = state["requests"]
                if request_id is not None and request_id in reservations:
                    reservation = reservations[request_id]
                    if reservation["lane"] != lane:
                        raise NonceError("request_id is bound to another nonce lane")
                    return reservation["nonce"]
                counters = state["counters"]
                value = counters.get(lane, 0) + 1
                if value >= 10**19:
                    raise NonceError("nonce exhausted")
                counters[lane] = value
                if request_id is not None:
                    reservations[request_id] = {"lane": lane, "nonce": value}
                self._write_reservation_state(state)
                return value

    def _read_reservation_state(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"version": 1, "counters": {}, "requests": {}}
        except (OSError, json.JSONDecodeError) as exc:
            raise NonceError("nonce state cannot be read") from exc
        # Accept the previously published counter-only representation, but publish the
        # unified representation on the next successful reservation.
        if (
            isinstance(data, dict)
            and "counters" not in data
            and all(
                isinstance(k, str) and isinstance(v, int) and not isinstance(v, bool) and v >= 0
                for k, v in data.items()
            )
        ):
            return {"version": 1, "counters": data, "requests": {}}
        if not isinstance(data, dict) or data.get("version") != 1:
            raise NonceError("nonce state is corrupt")
        counters, requests = data.get("counters"), data.get("requests")
        if not isinstance(counters, dict) or not isinstance(requests, dict):
            raise NonceError("nonce state is corrupt")
        if any(
            not isinstance(k, str) or not isinstance(v, int) or isinstance(v, bool) or v < 0
            for k, v in counters.items()
        ):
            raise NonceError("nonce counters are corrupt")
        if any(
            not isinstance(k, str)
            or not isinstance(v, dict)
            or not isinstance(v.get("lane"), str)
            or not isinstance(v.get("nonce"), int)
            or isinstance(v.get("nonce"), bool)
            or v["nonce"] < 1
            for k, v in requests.items()
        ):
            raise NonceError("nonce reservations are corrupt")
        return data

    def _write_reservation_state(self, state: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.fault:
            self.fault("before_temp_write")
        fd, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(state, stream, sort_keys=True, separators=(",", ":"))
                if self.fault:
                    self.fault("during_temp_write")
                stream.flush()
                if self.fault:
                    self.fault("after_temp_write_before_flush")
                os.fsync(stream.fileno())
                if self.fault:
                    self.fault("after_flush_before_replace")
            if self.fault:
                self.fault("before_replace")
            os.replace(temporary, self.path)
            if self.fault:
                self.fault("after_replace")
        except OSError as exc:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise NonceError("nonce state cannot be committed") from exc

    def _read(self) -> dict[str, int]:
        try:
            state = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, json.JSONDecodeError) as exc:
            raise NonceError("nonce state cannot be read") from exc
        if not isinstance(state, dict) or any(
            not isinstance(k, str) or not isinstance(v, int) or isinstance(v, bool) or v < 0
            for k, v in state.items()
        ):
            raise NonceError("nonce state is corrupt")
        return state

    def _write(self, state: dict[str, int]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.fault:
            self.fault("before_temp_write")
        fd, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(state, stream, sort_keys=True, separators=(",", ":"))
                if self.fault:
                    self.fault("during_temp_write")
                stream.flush()
                if self.fault:
                    self.fault("after_temp_write_before_flush")
                os.fsync(stream.fileno())
                if self.fault:
                    self.fault("after_flush_before_replace")
            if self.fault:
                self.fault("before_replace")
            os.replace(temporary, self.path)
            if self.fault:
                self.fault("after_replace")
        except OSError as exc:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise NonceError("nonce state cannot be committed") from exc


class Reconciliation:
    STATES = frozenset(
        {
            "ALLOCATED",
            "SIGNED",
            "SUBMISSION_STARTED",
            "ACCEPTED",
            "UNKNOWN",
            "RECONCILED",
            "FAILED_FINAL",
        }
    )

    def __init__(self) -> None:
        self.state = "ALLOCATED"

    def transition(self, state: str) -> None:
        allowed = {
            "ALLOCATED": {"SIGNED"},
            "SIGNED": {"SUBMISSION_STARTED"},
            "SUBMISSION_STARTED": {"ACCEPTED", "UNKNOWN", "FAILED_FINAL"},
            "UNKNOWN": {"RECONCILED", "FAILED_FINAL"},
            "ACCEPTED": set(),
            "RECONCILED": set(),
            "FAILED_FINAL": set(),
        }
        if state not in allowed.get(self.state, set()):
            raise NonceError(f"invalid reconciliation transition: {self.state} -> {state}")
        self.state = state

    @property
    def reusable(self) -> bool:
        return False


class OperationStore:
    """Durable non-secret request lifecycle and idempotency record."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    @contextmanager
    def _exclusive(self):
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        with _file_lock(lock_path):
            yield

    def get(self, request_id: str) -> dict | None:
        return self._read().get(request_id)

    def create(
        self,
        request_id: str,
        lane: str,
        text_hash: str,
        nonce: int | None = None,
        operation: str = "sign_room",
    ) -> dict:
        with self._lock, self._exclusive():
            records = self._read()
            if request_id in records:
                old = records[request_id]
                if (old["operation"], old["lane"], old["text_hash"]) != (
                    operation,
                    lane,
                    text_hash,
                ):
                    raise NonceError("request_id conflicts with an existing request")
                return old
            record = {
                "request_id": request_id,
                "operation": operation,
                "lane": lane,
                "nonce": nonce,
                "state": "ALLOCATED",
                "text_hash": text_hash,
                # Bound to the cleaned-text hash; signer separately proves the approved
                # plaintext hashes to text_hash before this operation can be created.
                "request_fingerprint": hashlib.sha256(
                    f"{operation}\0{lane}\0{text_hash}".encode()
                ).hexdigest(),
                "created_at": time.time(),
                "updated_at": time.time(),
            }
            records[request_id] = record
            self._write(records)
            return record.copy()

    def bind_nonce(self, request_id: str, nonce: int) -> dict:
        with self._lock, self._exclusive():
            records = self._read()
            try:
                record = records[request_id]
            except KeyError as exc:
                raise NonceError("unknown request_id") from exc
            if record["nonce"] is not None and record["nonce"] != nonce:
                raise NonceError("request_id is already bound to another nonce")
            record["nonce"] = nonce
            record["updated_at"] = time.time()
            self._write(records)
            return record.copy()

    def update(self, request_id: str, **fields) -> dict:
        with self._lock, self._exclusive():
            records = self._read()
            try:
                record = records[request_id]
            except KeyError as exc:
                raise NonceError("unknown request_id") from exc
            record.update(fields, updated_at=time.time())
            self._write(records)
            return record.copy()

    def transition(self, request_id: str, state: str) -> dict:
        with self._lock, self._exclusive():
            records = self._read()
            try:
                record = records[request_id]
            except KeyError as exc:
                raise NonceError("unknown request_id") from exc
            current = record["state"]
            allowed = {
                "ALLOCATED": {"SIGNED", "FAILED_FINAL"},
                "SIGNED": {"SUBMISSION_STARTED", "FAILED_FINAL"},
                "SUBMISSION_STARTED": {"ACCEPTED", "UNKNOWN", "FAILED_FINAL"},
                "UNKNOWN": {"RECONCILED", "FAILED_FINAL"},
                "ACCEPTED": set(),
                "RECONCILED": set(),
                "FAILED_FINAL": set(),
            }
            if state not in allowed.get(current, set()):
                raise NonceError(f"invalid reconciliation transition: {current} -> {state}")
            record["state"] = state
            record["updated_at"] = time.time()
            self._write(records)
            return record.copy()

    def _read(self) -> dict[str, dict]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, json.JSONDecodeError) as exc:
            raise NonceError("operation state cannot be read") from exc
        if not isinstance(data, dict) or any(not isinstance(v, dict) for v in data.values()):
            raise NonceError("operation state is corrupt")
        return data

    def _write(self, records: dict[str, dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(records, stream, sort_keys=True, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        except OSError as exc:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise NonceError("operation state cannot be committed") from exc
