from __future__ import annotations

import hashlib
import json
import msvcrt
import os
import re
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit


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
    # W2 shares the existing counter, atomic replace, and cross-process file lock.
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

    def reserve_w2(self, request_id: str, lane: str, signer_did: str,
                   venue_origin: str, text_sha256: str) -> dict:
        """Burn one nonce without constructing a key or creating a signature.

        The request id is idempotent only for the exact immutable draft binding.
        This deliberately shares the counter with the older room signer.
        """
        if not isinstance(request_id, str) or not re.fullmatch(r"w2draft1-[0-9a-f]{64}", request_id):
            raise NonceError("W2 request id is invalid")
        if not isinstance(lane, str) or not lane or "|" in lane:
            raise NonceError("W2 nonce lane is invalid")
        if not isinstance(signer_did, str) or not re.fullmatch(r"did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}", signer_did):
            raise NonceError("W2 signer DID is invalid")
        parsed = urlsplit(venue_origin) if isinstance(venue_origin, str) else None
        if (parsed is None or parsed.scheme != "https" or not parsed.netloc or
                parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment or
                venue_origin != f"https://{parsed.netloc.lower()}"):
            raise NonceError("W2 venue is invalid")
        if not isinstance(text_sha256, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", text_sha256):
            raise NonceError("W2 text hash is invalid")
        binding = {"request_id": request_id, "lane": lane, "signer_did": signer_did,
                   "venue_origin": venue_origin, "text_sha256": text_sha256}
        with self._lock:
            with _file_lock(self.path.with_suffix(self.path.suffix + ".lock")):
                state = self._read_reservation_state()
                w2 = state.setdefault("w2_reservations", {})
                history = state.setdefault("w2_reservation_history", {})
                if not isinstance(w2, dict):
                    raise NonceError("W2 reservation state is corrupt")
                if not isinstance(history, dict):
                    raise NonceError("W2 reservation history is corrupt")
                old = w2.get(request_id)
                if old is not None:
                    if not isinstance(old, dict) or any(old.get(k) != v for k, v in binding.items()):
                        raise NonceError("W2 request id conflicts with its reservation")
                    if old.get("state") != "BURNED":
                        return old.copy()
                    generations = history.setdefault(request_id, [])
                    if not isinstance(generations, list):
                        raise NonceError("W2 reservation history is corrupt")
                    generations.append(old.copy())
                if request_id in state["requests"]:
                    raise NonceError("W2 request id conflicts with a legacy reservation")
                value = state["counters"].get(lane, 0) + 1
                if value >= 10**19:
                    raise NonceError("W2 nonce exhausted")
                generation = len(history.get(request_id, [])) + 1
                reservation = {**binding, "nonce": str(value), "state": "RESERVED",
                               "generation": generation, "created_at": time.time()}
                state["counters"][lane] = value
                w2[request_id] = reservation
                self._write_reservation_state(state)
                return reservation.copy()

    def consume_w2(self, request_id: str, *, lane: str, signer_did: str,
                   venue_origin: str, text_sha256: str, nonce: str,
                   operation_id: str, approval_hash: str) -> dict:
        """Spend the exact reservation before any W2 signature can be produced."""
        if not isinstance(nonce, str) or not (nonce == "0" or
                (nonce.isascii() and nonce.isdecimal() and nonce[0] != "0" and len(nonce) <= 19)):
            raise NonceError("W2 nonce is not canonical decimal text")
        if not isinstance(operation_id, str) or not re.fullmatch(r"w2op1-[0-9a-f]{64}", operation_id):
            raise NonceError("W2 operation id is invalid")
        if not isinstance(approval_hash, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", approval_hash):
            raise NonceError("W2 approval hash is invalid")
        with self._lock:
            with _file_lock(self.path.with_suffix(self.path.suffix + ".lock")):
                state = self._read_reservation_state()
                reservation = state.get("w2_reservations", {}).get(request_id)
                if not isinstance(reservation, dict):
                    raise NonceError("W2 reservation is missing")
                expected = {"lane": lane, "signer_did": signer_did,
                            "venue_origin": venue_origin, "text_sha256": text_sha256,
                            "nonce": nonce, "state": "APPROVED",
                            "operation_id": operation_id, "approval_hash": approval_hash}
                if any(reservation.get(k) != v for k, v in expected.items()):
                    raise NonceError("W2 reservation binding or state mismatch")
                reservation["state"] = "SIGNING_OUTCOME_UNCERTAIN"
                reservation["operation_id"] = operation_id
                reservation["approval_hash"] = approval_hash
                reservation["consumed_at"] = time.time()
                self._write_reservation_state(state)
                return reservation.copy()

    def approve_w2(self, request_id: str, *, lane: str, signer_did: str,
                   venue_origin: str, text_sha256: str, nonce: str,
                   operation_id: str, approval_hash: str) -> dict:
        """Persist the exact terminal-approved binding before signature consumption."""
        with self._lock:
            with _file_lock(self.path.with_suffix(self.path.suffix + ".lock")):
                state = self._read_reservation_state()
                reservation = state.get("w2_reservations", {}).get(request_id)
                expected = {"request_id": request_id, "lane": lane, "signer_did": signer_did,
                            "venue_origin": venue_origin, "text_sha256": text_sha256, "nonce": nonce}
                if not isinstance(reservation, dict) or any(reservation.get(k) != v for k, v in expected.items()):
                    raise NonceError("W2 approval reservation binding mismatch")
                if reservation["state"] == "APPROVED":
                    if reservation.get("operation_id") != operation_id or reservation.get("approval_hash") != approval_hash:
                        raise NonceError("W2 approval binding mismatch")
                    return reservation.copy()
                if reservation["state"] != "RESERVED":
                    raise NonceError("W2 reservation is not approvable")
                reservation["state"] = "APPROVED"
                reservation["operation_id"] = operation_id
                reservation["approval_hash"] = approval_hash
                reservation["approved_at"] = time.time()
                self._write_reservation_state(state)
                return reservation.copy()

    def cancel_w2(self, request_id: str, *, lane: str, signer_did: str,
                  venue_origin: str, text_sha256: str, nonce: str,
                  operation_id: str, approval_hash: str, reason: str = "CANCELLED") -> dict:
        """Burn only the exact un-signed W2 reservation; repeat is read-only."""
        if reason not in {"CANCELLED", "EXPIRED"}:
            raise NonceError("W2 cancellation reason is invalid")
        with self._lock:
            with _file_lock(self.path.with_suffix(self.path.suffix + ".lock")):
                state = self._read_reservation_state()
                reservation = state.get("w2_reservations", {}).get(request_id)
                expected = {"request_id": request_id, "lane": lane, "signer_did": signer_did,
                            "venue_origin": venue_origin, "text_sha256": text_sha256, "nonce": nonce}
                if not isinstance(reservation, dict) or any(reservation.get(k) != v for k, v in expected.items()):
                    raise NonceError("W2 cancellation reservation binding mismatch")
                if reservation["state"] == "BURNED":
                    if (reservation.get("burn_reason") != reason or reservation.get("operation_id") != operation_id
                            or reservation.get("approval_hash") != approval_hash):
                        raise NonceError("W2 cancellation terminal binding mismatch")
                    return reservation.copy()
                if reservation["state"] not in {"RESERVED", "APPROVED"}:
                    raise NonceError("W2 reservation crossed signing boundary")
                if reservation["state"] == "APPROVED" and (
                        reservation.get("operation_id") != operation_id or reservation.get("approval_hash") != approval_hash):
                    raise NonceError("W2 cancellation approval binding mismatch")
                reservation["state"] = "BURNED"
                reservation["operation_id"] = operation_id
                reservation["approval_hash"] = approval_hash
                reservation["burn_reason"] = reason
                reservation["burned_at"] = time.time()
                reservation["audit_event"] = "CANCELED_BEFORE_SIGNING" if reason == "CANCELLED" else "APPROVAL_EXPIRED"
                self._write_reservation_state(state)
                return reservation.copy()

    def signed_w2(self, request_id: str, signature_sha256: str) -> dict:
        """Record success after signing; never re-enable the spent reservation."""
        if not isinstance(signature_sha256, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", signature_sha256):
            raise NonceError("W2 signature hash is invalid")
        with self._lock:
            with _file_lock(self.path.with_suffix(self.path.suffix + ".lock")):
                state = self._read_reservation_state()
                reservation = state.get("w2_reservations", {}).get(request_id)
                if not isinstance(reservation, dict) or reservation.get("state") != "SIGNING_OUTCOME_UNCERTAIN":
                    raise NonceError("W2 signature completion state is invalid")
                reservation["state"] = "SIGNED"
                reservation["signature_sha256"] = signature_sha256
                self._write_reservation_state(state)
                return reservation.copy()

    def burn_w2(self, request_id: str, reason: str) -> dict:
        if reason not in {"CANCELLED", "EXPIRED", "SIGN_FAILURE", "ABANDONED"}:
            raise NonceError("W2 burn reason is invalid")
        with self._lock:
            with _file_lock(self.path.with_suffix(self.path.suffix + ".lock")):
                state = self._read_reservation_state()
                reservation = state.get("w2_reservations", {}).get(request_id)
                if not isinstance(reservation, dict) or reservation.get("state") != "RESERVED":
                    raise NonceError("W2 reservation cannot be burned from this state")
                reservation["state"] = "BURNED"
                reservation["burn_reason"] = reason
                reservation["burned_at"] = time.time()
                self._write_reservation_state(state)
                return reservation.copy()

    def get_w2(self, request_id: str) -> dict | None:
        state = self._read_reservation_state()
        item = state.get("w2_reservations", {}).get(request_id)
        return item.copy() if isinstance(item, dict) else None

    def get_w2_history(self, request_id: str) -> list[dict]:
        state = self._read_reservation_state()
        history = state.get("w2_reservation_history", {}).get(request_id, [])
        return [item.copy() for item in history]

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
        w2 = data.get("w2_reservations", {})
        if not isinstance(w2, dict):
            raise NonceError("W2 nonce reservations are corrupt")
        history = data.get("w2_reservation_history", {})
        if not isinstance(history, dict):
            raise NonceError("W2 nonce reservation history is corrupt")

        def valid_w2(request_id: str, reservation: dict, *, history_item: bool = False) -> bool:
            if not isinstance(request_id, str) or not re.fullmatch(r"w2draft1-[0-9a-f]{64}", request_id) or not isinstance(reservation, dict):
                return False
            lane = reservation.get("lane")
            nonce = reservation.get("nonce")
            generation = reservation.get("generation", 1)
            return not (reservation.get("request_id") != request_id or not isinstance(lane, str)
                    or not lane or "|" in lane or not isinstance(nonce, str)
                    or not re.fullmatch(r"[1-9][0-9]{0,18}", nonce)
                    or counters.get(lane, 0) < int(nonce)
                    or reservation.get("state") not in {"RESERVED", "APPROVED", "SIGNING_OUTCOME_UNCERTAIN", "SIGNED", "BURNED"}
                    or (history_item and reservation.get("state") != "BURNED")
                    or not isinstance(generation, int) or isinstance(generation, bool) or generation < 1
                    or not isinstance(reservation.get("signer_did"), str)
                    or not isinstance(reservation.get("venue_origin"), str)
                    or not isinstance(reservation.get("text_sha256"), str)
                    or not isinstance(reservation.get("created_at"), (int, float)))

        for request_id, reservation in w2.items():
            if not valid_w2(request_id, reservation):
                raise NonceError("W2 nonce reservations are corrupt")
        for request_id, generations in history.items():
            if not isinstance(generations, list) or not generations:
                raise NonceError("W2 nonce reservation history is corrupt")
            for index, reservation in enumerate(generations, start=1):
                if not valid_w2(request_id, reservation, history_item=True) or reservation.get("generation", index) != index:
                    raise NonceError("W2 nonce reservation history is corrupt")
            current = w2.get(request_id)
            if not isinstance(current, dict) or current.get("generation") != len(generations) + 1:
                raise NonceError("W2 nonce reservation generation is corrupt")
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

    def transition(self, request_id: str, state: str, **fields) -> dict:
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
            if set(fields) - {"receipt"}:
                raise NonceError("unsupported operation transition field")
            receipt = fields.get("receipt")
            if receipt is not None:
                if state not in {"ACCEPTED", "RECONCILED"} or not isinstance(receipt, dict):
                    raise NonceError("receipt is invalid for this operation transition")
                record["receipt"] = receipt
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
