from __future__ import annotations

import io
import json
from email.message import Message
from urllib.error import HTTPError, URLError

import pytest

from technocore_agent.policy.transport import TechnocoreTransport
from technocore_agent.signer.service import SignedOperation


class Response:
    def __init__(self, body=b"ok", status=200):
        self.body = io.BytesIO(body)
        self.status = status

    def read(self, size=-1):
        return self.body.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class Opener:
    def __init__(self, result):
        self.result = result
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def operation():
    return SignedOperation("did:key:z6MkExample", "lobby", 7, "s" * 86, "hello")


def room_response(*, text="hello", nonce=7, sender="did:key:z6MkExample", seq=42):
    return json.dumps(
        {
            "room": "lobby",
            "count": 1,
            "last_seq": seq,
            "messages": [
                {
                    "seq": seq,
                    "ts": "2026-08-28T12:52:29.000000+00:00",
                    "from": sender,
                    "nonce": nonce,
                    "text": text,
                }
            ],
        }
    ).encode()


def test_submit_uses_canonical_https_post_and_accepts_success():
    opener = Opener(Response(room_response()))
    transport = TechnocoreTransport(opener=opener)
    result = transport.submit(operation())
    assert result.status == "accepted"
    assert result.receipt == {
        "room": "lobby",
        "seq": 42,
        "ts": "2026-08-28T12:52:29.000000+00:00",
        "from": "did:key:z6MkExample",
        "nonce": 7,
        "text": "hello",
    }
    request, timeout = opener.requests[0]
    assert request.full_url == "https://technocore.chat/r/lobby"
    assert request.method == "POST"
    assert timeout == 15
    assert json.loads(request.data) == {
        "did": "did:key:z6MkExample",
        "sig": "s" * 86,
        "nonce": 7,
        "text": "hello",
    }


@pytest.mark.parametrize("code, expected", [(403, "rejected"), (409, "rejected"), (429, "unknown"), (503, "unknown")])
def test_submit_classifies_http_failures(code, expected):
    error = HTTPError(
        "https://technocore.chat", code, "failure", Message(), io.BytesIO(b"x")
    )
    assert TechnocoreTransport(opener=Opener(error)).submit(operation()).status == expected


def test_submit_treats_transport_failure_as_unknown():
    assert TechnocoreTransport(opener=Opener(URLError("offline"))).submit(operation()).status == "unknown"


def test_reconcile_matches_exact_bound_did_and_nonce():
    payload = room_response()
    transport = TechnocoreTransport(opener=Opener(Response(payload)), clock=lambda: 123)
    transport.bind_did("did:key:z6MkExample")
    result = transport.reconcile({"lane": "lobby", "nonce": 7})
    assert result.status == "accepted"
    assert result.receipt is not None and result.receipt["seq"] == 42


def test_reconcile_never_claims_rejection_when_message_is_absent():
    transport = TechnocoreTransport(opener=Opener(Response(b'{"room":"lobby","messages":[]}')))
    transport.bind_did("did:key:z6MkExample")
    assert transport.reconcile({"lane": "lobby", "nonce": 7}).status == "unknown"


@pytest.mark.parametrize(
    "payload",
    [
        b"ok",
        b"{}",
        room_response(text="changed"),
        room_response(nonce=8),
        room_response(sender="did:key:z6MkOther"),
        room_response(seq=True),
    ],
)
def test_submit_never_accepts_without_an_exact_structured_receipt(payload):
    result = TechnocoreTransport(opener=Opener(Response(payload))).submit(operation())
    assert result.status == "unknown" and result.receipt is None


@pytest.mark.parametrize(
    "url",
    [
        "http://technocore.chat",
        "https://www.technocore.chat",
        "https://technocore.chat/path",
        "https://user@technocore.chat",
    ],
)
def test_transport_rejects_noncanonical_origins(url):
    with pytest.raises(ValueError, match="canonical"):
        TechnocoreTransport(url)
