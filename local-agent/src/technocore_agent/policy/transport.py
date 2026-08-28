from __future__ import annotations

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

    def submit(self, operation) -> str:
        if not ROOM_PATTERN.fullmatch(operation.room):
            return "rejected"
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
            f"{self.base_url}/r/{quote(operation.room, safe='')}",
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
                self._read_bounded(response)
                return "accepted" if 200 <= response.status < 300 else "unknown"
        except HTTPError as exc:
            self._drain_error(exc)
            if exc.code in {408, 425, 429} or 500 <= exc.code <= 599:
                return "unknown"
            return "rejected" if 400 <= exc.code <= 499 else "unknown"
        except (OSError, TimeoutError, URLError):
            return "unknown"

    def reconcile(self, operation) -> str:
        if self._public_did is None or not ROOM_PATTERN.fullmatch(operation["lane"]):
            return "unknown"
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
            return "unknown"
        messages = value.get("messages") if isinstance(value, dict) else None
        if not isinstance(messages, list):
            return "unknown"
        expected_nonce = operation.get("nonce")
        for item in messages:
            if not isinstance(item, dict):
                continue
            nonce = item.get("nonce")
            if item.get("from") == self._public_did and str(nonce) == str(expected_nonce):
                return "accepted"
        return "unknown"

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
