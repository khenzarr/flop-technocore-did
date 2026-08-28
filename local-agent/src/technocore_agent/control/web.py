from __future__ import annotations

import html
import json
from dataclasses import asdict
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from .operator import OperatorAuthError


def make_handler(control, expected_origin: str):
    class Handler(BaseHTTPRequestHandler):
        server_version = "TechnocoreControl/0.1"

        def log_message(self, format: str, *_args: object) -> None:
            return

        def do_GET(self):
            try:
                if self.path == "/":
                    session = self._session(required=False)
                    drafts = control.pending() if session else []
                    csrf = session.csrf_token if session else ""
                    live = control.mode == "live"
                    mode_label = "LIVE — SIGNED TECHNOCORE WRITES" if live else "TEST MODE — NETWORK OFFLINE"
                    rows = "".join(
                        f"<article><b>{html.escape(d.room)}</b><pre>{html.escape(d.cleaned_text)}</pre>"
                        f"<small>{html.escape(d.source)}</small>"
                        f"<form method=post action=/draft/{d.draft_id}/approve><input type=hidden name=csrf value='{csrf}'><label>Fresh operator passphrase <input type=password name=passphrase autocomplete=current-password required></label><button>Approve signed message</button></form>"
                        f"<form method=post action=/draft/{d.draft_id}/reject><input type=hidden name=csrf value='{csrf}'><button>Reject</button></form></article>"
                        for d in drafts
                    )
                    body = (
                        f"<!doctype html><title>Technocore Agent</title><h1>TECHNOCORE AGENT — {mode_label}</h1>"
                        f"<p>Public DID: <code>{html.escape(control.public_did)}</code></p>"
                        "<p>Private key: Windows DPAPI protected; never shown in this page.</p>"
                        + (
                            "<p>Every live write requires a pending draft, an unlocked local session, and fresh passphrase confirmation.</p>"
                            if live
                            else "<p>NETWORK OFFLINE · LIVE WRITES DISABLED</p>"
                        )
                        + (
                            f"<form method=post action=/lock><input type=hidden name=csrf value='{csrf}'><button>Lock</button></form>"
                            if session
                            else "<p>Operator locked.</p><form method=post action=/unlock><label>Operator passphrase <input type=password name=passphrase autocomplete=current-password required></label><button>Unlock</button></form>"
                        )
                        + rows
                    )
                    return self._send(200, body, "text/html; charset=utf-8")
                if self.path == "/api/status":
                    return self._json(
                        200,
                        {
                            "mode": control.mode,
                            "public_did": control.public_did,
                            "operator_configured": control.auth.configured(),
                            "unlocked": self._session(required=False) is not None,
                        },
                    )
                if self.path == "/api/drafts":
                    self._session()
                    return self._json(200, [asdict(d) for d in control.pending()])
                if self.path == "/api/activity":
                    self._session()
                    return self._json(200, [asdict(d) for d in control.activity()])
                self._send(404, "not found")
            except OperatorAuthError as exc:
                self._send(403, str(exc))

        def do_POST(self):
            if self.headers.get("Origin") != expected_origin:
                return self._send(403, "origin rejected")
            data = parse_qs(self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode())
            if self.path == "/unlock":
                try:
                    session = control.auth.unlock(data.get("passphrase", [""])[0])
                except OperatorAuthError:
                    return self._send(401, "unlock failed")
                self.send_response(204)
                self.send_header(
                    "Set-Cookie",
                    f"tc_session={session.session_id}; HttpOnly; SameSite=Strict; Path=/; Max-Age={control.auth.session_ttl}",
                )
                self.end_headers()
                return
            try:
                session = self._session(csrf=data.get("csrf", [None])[0])
                parts = self.path.strip("/").split("/")
                if len(parts) == 3 and parts[0] == "draft" and parts[2] == "approve":
                    result = control.approve_and_execute(
                        parts[1], session, data.get("passphrase", [""])[0]
                    )
                    return self._json(200, result if isinstance(result, dict) else asdict(result))
                if len(parts) == 3 and parts[0] == "draft" and parts[2] == "reject":
                    result = control.reject(parts[1], session)
                    return self._json(200, result if isinstance(result, dict) else asdict(result))
                if self.path == "/lock":
                    control.auth.logout(session.session_id)
                    return self._send(204, "", clear_cookie=True)
            except (OperatorAuthError, ValueError) as exc:
                return self._send(403, str(exc))
            self._send(404, "not found")

        def _session(self, required=True, csrf=None):
            jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
            morsel = jar.get("tc_session")
            try:
                if self.command == "POST" and csrf is None:
                    raise OperatorAuthError("CSRF token is required")
                return control.auth.validate(morsel.value if morsel else None, csrf)
            except OperatorAuthError:
                if required:
                    raise
                return None

        def _json(self, status, value):
            self._send(status, json.dumps(value), "application/json")

        def _send(
            self,
            status,
            body,
            content_type="text/plain; charset=utf-8",
            *,
            clear_cookie=False,
        ):
            raw = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'self'; form-action 'self'; "
                "base-uri 'none'; frame-ancestors 'none'",
            )
            if clear_cookie:
                self.send_header(
                    "Set-Cookie",
                    "tc_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
                )
            self.end_headers()
            self.wfile.write(raw)

    return Handler


def create_server(control, port: int = 0):
    origin = f"http://127.0.0.1:{port}" if port else None
    server = ThreadingHTTPServer(("127.0.0.1", port), BaseHTTPRequestHandler)
    actual_origin = origin or f"http://127.0.0.1:{server.server_port}"
    server.server_close()
    return ThreadingHTTPServer(
        ("127.0.0.1", server.server_port), make_handler(control, actual_origin)
    )
