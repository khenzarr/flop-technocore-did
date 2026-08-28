"""Minimal local Windows named-pipe server using Python's standard library."""

from __future__ import annotations

import multiprocessing.connection
import sys

from .protocol import decode_request, encode_response


def ensure_windows_named_pipe() -> None:
    if sys.platform != "win32":
        raise RuntimeError("named-pipe proof is Windows-only")


class NamedPipeServer:
    """LEGACY TEST ONLY; AF_PIPE/authkey is not an approved production trust boundary."""

    def __init__(self, pipe_name: str, handler, authkey: bytes) -> None:
        ensure_windows_named_pipe()
        if not pipe_name.startswith("\\\\.\\pipe\\"):
            raise ValueError("pipe name must be local")
        if not isinstance(authkey, bytes) or not authkey:
            raise ValueError("a non-empty IPC authkey is required")
        self.pipe_name, self.handler, self.authkey = pipe_name, handler, authkey
        # Bind before the worker thread starts so a client cannot race pipe
        # publication. The listener is still closed after the single request.
        self._listener = multiprocessing.connection.Listener(
            self.pipe_name, family="AF_PIPE", authkey=self.authkey
        )

    def serve_once(self) -> None:
        listener = self._listener
        try:
            with listener.accept() as connection:
                try:
                    request = decode_request(connection.recv_bytes())
                    response = self.handler(request)
                except (ValueError, TypeError) as exc:
                    response = {"error": str(exc)}
                connection.send_bytes(encode_response(response))
        finally:
            listener.close()
