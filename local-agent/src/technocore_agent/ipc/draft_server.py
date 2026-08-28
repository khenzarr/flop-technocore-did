from __future__ import annotations

import socket
import socketserver
from typing import Any, cast

from .draft_protocol import decode_agent_request, encode_agent_response


class _DraftHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        try:
            raw = self.rfile.readline(16 * 1024 + 1)
            request = decode_agent_request(raw)
            server = cast(Any, self.server)
            response = server.agent_handler(request)
        except (OSError, TypeError, ValueError) as exc:
            response = {"error": str(exc)}
        self.wfile.write(encode_agent_response(response))


class DraftIPCServer(socketserver.ThreadingTCPServer):
    """Loopback-only, unprivileged draft endpoint; never a signer control endpoint."""

    allow_reuse_address = False
    daemon_threads = True
    address_family = socket.AF_INET

    def __init__(self, handler, port: int = 0) -> None:
        self.agent_handler = handler
        super().__init__(("127.0.0.1", port), _DraftHandler)


def request(port: int, item: dict, timeout: float = 5.0) -> dict:
    import json

    raw = (json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n").encode()
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as connection:
        connection.sendall(raw)
        stream = connection.makefile("rb")
        response = stream.readline(16 * 1024 + 1)
    value = json.loads(response)
    if not isinstance(value, dict):
        raise ValueError("invalid service response")
    return value
