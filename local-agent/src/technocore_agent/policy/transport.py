from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

ROOM_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
MAX_RESPONSE_BYTES = 1024 * 1024


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


@dataclass(frozen=True, slots=True)
class SubmissionResult:
    status: str
    receipt: dict[str, object] | None = None


class TechnocoreTransport:
    """Bounded HTTPS transport for the official signed Technocore room lane."""

    def __init__(
        self,
        base_url: str = "https://technocore.chat",
        *,
        timeout: float = 15.0,
        opener=None,
        clock=None,
    ) -> None:
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "https"
            or parsed.netloc != "technocore.chat"
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise ValueError("only the canonical Technocore HTTPS origin is allowed")
        if not isinstance(timeout, (int, float)) or not 1 <= timeout <= 30:
            raise ValueError("transport timeout must be between 1 and 30 seconds")
        self.base_url = "https://technocore.chat"
        self.timeout = float(timeout)
        self._opener = opener or build_opener(_RejectRedirects())
        self._clock = clock or time.time_ns
        self._public_did: str | None = None

    def bind_did(self, did: str) -> None:
        if self._public_did is not None and self._public_did != did:
            raise ValueError("transport DID is already bound")
        if not isinstance(did, str) or not did.startswith("did:key:z6Mk"):
            raise ValueError("transport DID is invalid")
        self._public_did = did

    def submit(self, operation) -> SubmissionResult:
        if not ROOM_PATTERN.fullmatch(operation.room):
            return SubmissionResult("rejected")
        body = json.dumps(
            {
                "did": operation.did,
                "sig": operation.signature,
                "nonce": operation.nonce,
                "text": operation.text,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        request = Request(
            f"{self.base_url}/r/{quote(operation.room, safe='')}?format=json",
            data=body,
            method="POST",
            headers={
                "Accept": "application/json, text/plain;q=0.9",
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": "flop-technocore-did/1",
            },
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                raw = self._read_bounded(response)
                if not 200 <= response.status < 300:
                    return SubmissionResult("unknown")
                receipt = self._parse_receipt(raw, operation)
                return SubmissionResult("accepted", receipt) if receipt else SubmissionResult("unknown")
        except HTTPError as exc:
            self._drain_error(exc)
            if exc.code in {408, 425, 429} or 500 <= exc.code <= 599:
                return SubmissionResult("unknown")
            return SubmissionResult("rejected" if 400 <= exc.code <= 499 else "unknown")
        except (OSError, TimeoutError, URLError, ValueError):
            return SubmissionResult("unknown")

    def reconcile(self, operation) -> SubmissionResult:
        if self._public_did is None or not ROOM_PATTERN.fullmatch(operation["lane"]):
            return SubmissionResult("unknown")
        query = urlencode({"format": "json", "limit": 200, "n": self._clock()})
        request = Request(
            f"{self.base_url}/r/{quote(operation['lane'], safe='')}?{query}",
            method="GET",
            headers={"Accept": "application/json", "User-Agent": "flop-technocore-did/1"},
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                value = json.loads(self._read_bounded(response).decode("utf-8"))
        except (HTTPError, OSError, TimeoutError, URLError, ValueError):
            return SubmissionResult("unknown")
        if not isinstance(value, dict) or value.get("room") != operation["lane"]:
            return SubmissionResult("unknown")
        messages = value.get("messages") if isinstance(value, dict) else None
        if not isinstance(messages, list):
            return SubmissionResult("unknown")
        expected_nonce = operation.get("nonce")
        for item in messages:
            if not isinstance(item, dict):
                continue
            nonce = item.get("nonce")
            text = item.get("text")
            expected_hash = operation.get("text_hash")
            text_matches = (
                isinstance(text, str)
                and (expected_hash is None or hashlib.sha256(text.encode()).hexdigest() == expected_hash)
            )
            if (
                item.get("from") == self._public_did
                and str(nonce) == str(expected_nonce)
                and text_matches
            ):
                receipt = self._sanitize_message_receipt(operation["lane"], item)
                if receipt is not None:
                    return SubmissionResult("accepted", receipt)
        return SubmissionResult("unknown")

    @classmethod
    def _parse_receipt(cls, raw: bytes, operation) -> dict[str, object] | None:
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict) or value.get("room") != operation.room:
            return None
        messages = value.get("messages")
        if not isinstance(messages, list):
            return None
        posted = value.get("posted")
        if not isinstance(posted, dict):
            return None
        receipt = cls._sanitize_message_receipt(operation.room, posted)
        if (
            receipt is None
            or receipt["from"] != operation.did
            or receipt["text"] != operation.text
            or str(receipt["nonce"]) != str(operation.nonce)
            or not any(
                isinstance(item, dict) and item.get("seq") == receipt["seq"]
                for item in messages
            )
        ):
            return None
        return receipt

    @staticmethod
    def _sanitize_message_receipt(room: str, item: dict) -> dict[str, object] | None:
        sequence, timestamp = item.get("seq"), item.get("ts")
        sender, text, nonce = item.get("from"), item.get("text"), item.get("nonce")
        if (
            not isinstance(sequence, int)
            or isinstance(sequence, bool)
            or sequence < 1
            or not isinstance(timestamp, str)
            or not 1 <= len(timestamp) <= 64
            or not isinstance(sender, str)
            or not sender.startswith("did:key:z6Mk")
            or not isinstance(text, str)
            or not 1 <= len(text) <= 4096
            or not isinstance(nonce, int)
            or isinstance(nonce, bool)
            or nonce < 1
        ):
            return None
        return {
            "room": room,
            "seq": sequence,
            "ts": timestamp,
            "from": sender,
            "nonce": nonce,
            "text": text,
        }

    @staticmethod
    def _read_bounded(response) -> bytes:
        data = response.read(MAX_RESPONSE_BYTES + 1)
        if len(data) > MAX_RESPONSE_BYTES:
            raise ValueError("Technocore response exceeds the bounded limit")
        return data

    @staticmethod
    def _drain_error(error: HTTPError) -> None:
        try:
            error.read(MAX_RESPONSE_BYTES + 1)
        except OSError:
            pass


@dataclass
class RecordingTransport:
    outcomes: list[str]
    mode: str = "accepted"

    @property
    def submission_count(self) -> int:
        return sum(1 for item in self.outcomes if item == "submission_started")

    def submit(self, operation) -> str:
        if self.mode in {"before_send_failure", "pre_send_failure"}:
            self.outcomes.append("failed_before_send")
            return "failed_before_send"
        self.outcomes.extend(("submitted", "submission_started"))
        if self.mode in {"rejected", "definite_rejection"}:
            return "rejected"
        if self.mode == "accepted_response_lost":
            return "unknown"
        if self.mode in {"timeout", "timeout_unknown"}:
            return "unknown"
        return "accepted"

    def reconcile(self, operation) -> str:
        if self.mode == "reconcile_accepted":
            return "accepted"
        if self.mode == "reconcile_rejected":
            return "rejected"
        if self.mode == "reconcile_unknown":
            return "unknown"
        return "unknown"
