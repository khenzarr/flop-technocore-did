"""Secretless IPC boundary for a signer launched as a trusted child process.

The caller writes one schema-validated JSON request to the child's standard input and reads one
safe JSON response from standard output. Authentication is the inherited parent/child handle
relationship: no persistent IPC credential exists or crosses the request schema.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import BinaryIO

from .protocol import decode_request, encode_response


def serve_once(
    input_stream: BinaryIO, output_stream: BinaryIO, handler: Callable[[dict], dict]
) -> None:
    raw = input_stream.readline(16 * 1024 + 1)
    try:
        request = decode_request(raw)
        response = handler(request)
    except (TypeError, ValueError) as exc:
        response = {"error": str(exc)}
    output_stream.write(encode_response(response))
    output_stream.flush()
