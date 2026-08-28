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


def test_submit_uses_canonical_https_post_and_accepts_success():
    opener = Opener(Response())
    transport = TechnocoreTransport(opener=opener)
    assert transport.submit(operation()) == "accepted"
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
    assert TechnocoreTransport(opener=Opener(error)).submit(operation()) == expected


def test_submit_treats_transport_failure_as_unknown():
    assert TechnocoreTransport(opener=Opener(URLError("offline"))).submit(operation()) == "unknown"


def test_reconcile_matches_exact_bound_did_and_nonce():
    payload = json.dumps(
        {"messages": [{"from": "did:key:z6MkExample", "nonce": "7", "text": "hello"}]}
    ).encode()
    transport = TechnocoreTransport(opener=Opener(Response(payload)), clock=lambda: 123)
    transport.bind_did("did:key:z6MkExample")
    assert transport.reconcile({"lane": "lobby", "nonce": 7}) == "accepted"


def test_reconcile_never_claims_rejection_when_message_is_absent():
    transport = TechnocoreTransport(opener=Opener(Response(b'{"messages":[]}')))
    transport.bind_did("did:key:z6MkExample")
    assert transport.reconcile({"lane": "lobby", "nonce": 7}) == "unknown"


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
