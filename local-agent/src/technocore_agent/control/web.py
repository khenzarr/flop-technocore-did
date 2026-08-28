from __future__ import annotations

import html
import json
import re
from dataclasses import asdict
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .operator import OperatorAuthError

AGENT_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
X_HANDLE = re.compile(r"^[A-Za-z0-9_]{1,15}$")
WALLET_VALUE = re.compile(r"^[A-Za-z0-9:._-]{8,128}$")

CSS = """
:root{color-scheme:light;--bg:#07110e;--card:#101d18;--line:#294138;--text:#edf7f1;--muted:#9fb4a8;--green:#25d17f;--amber:#f0b44d;font-family:Inter,Segoe UI,sans-serif}
*{box-sizing:border-box}body{margin:0;background:linear-gradient(145deg,#06100d,#10241b);color:var(--text);min-height:100vh}main{max-width:1180px;margin:auto;padding:32px 20px 80px}header{display:flex;gap:18px;align-items:flex-start;justify-content:space-between;margin-bottom:24px}.brand{font:800 13px ui-monospace,monospace;letter-spacing:.15em;color:var(--green)}h1{font-size:32px;margin:8px 0}.mode{border:1px solid var(--line);border-radius:99px;padding:8px 12px;font:700 11px ui-monospace,monospace}.mode.live{color:var(--green)}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.card{background:rgba(16,29,24,.94);border:1px solid var(--line);border-radius:14px;padding:20px}.wide{grid-column:1/-1}h2{font-size:17px;margin:0 0 8px}.muted,small{color:var(--muted);line-height:1.5}.did{display:block;overflow-wrap:anywhere;background:#08130f;border:1px solid var(--line);padding:11px;border-radius:8px;color:var(--green)}label{display:block;font-size:12px;font-weight:700;margin:12px 0}input,textarea{display:block;width:100%;margin-top:6px;border:1px solid #355347;border-radius:8px;background:#07110e;color:var(--text);padding:10px}textarea{min-height:92px;resize:vertical}button,.button{border:0;border-radius:8px;background:var(--green);color:#03100a;padding:10px 14px;font-weight:800;cursor:pointer;text-decoration:none;display:inline-block}.secondary{background:#263b33;color:var(--text)}.danger{background:#5d3029;color:#fff}.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}article{border-top:1px solid var(--line);padding:16px 0}article:first-of-type{border-top:0}pre{white-space:pre-wrap;overflow-wrap:anywhere;color:#d6e8de}.warning{border-left:3px solid var(--amber);padding-left:12px;color:#e9d5af}.steps{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:16px 0}.step{padding:10px;border:1px solid var(--line);border-radius:8px;color:var(--muted);font-size:11px}.step b{display:block;color:var(--text);margin-bottom:4px}.locked{max-width:520px;margin:10vh auto}.result{max-width:700px;margin:10vh auto}.status{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}.status span{background:#08130f;border-radius:8px;padding:10px;font-size:11px}.status b{display:block;color:var(--green);margin-top:4px}@media(max-width:760px){header{display:block}.grid,.steps,.status{grid-template-columns:1fr}.wide{grid-column:auto}h1{font-size:25px}}
"""


def _field(data, name: str, *, maximum: int, required: bool = True) -> str:
    value = data.get(name, [""])[0].strip()
    if required and not value:
        raise ValueError(f"{name} is required")
    if len(value) > maximum:
        raise ValueError(f"{name} is too long")
    return value


def _csrf(value: str) -> str:
    return f"<input type=hidden name=csrf value='{html.escape(value, quote=True)}'>"


def make_handler(control, expected_origin: str):
    class Handler(BaseHTTPRequestHandler):
        server_version = "TechnocoreControl/0.2"

        def log_message(self, format: str, *_args: object) -> None:
            return

        def do_GET(self):
            try:
                if self.path == "/app.css":
                    return self._send(200, CSS, "text/css; charset=utf-8")
                if self.path == "/":
                    return self._send(200, self._page(), "text/html; charset=utf-8")
                if self.path == "/api/status":
                    return self._json(200, {"mode": control.mode, "public_did": control.public_did, "operator_configured": control.auth.configured(), "unlocked": self._session(required=False) is not None})
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
            if not self._same_origin_post():
                return self._send(403, "origin rejected")
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return self._send(400, "invalid content length")
            if not 0 <= length <= 16384:
                return self._send(413, "form is too large")
            try:
                data = parse_qs(self.rfile.read(length).decode("utf-8"), keep_blank_values=True)
            except UnicodeDecodeError:
                return self._send(400, "form encoding is invalid")
            if self.path == "/unlock":
                try:
                    session = control.auth.unlock(data.get("passphrase", [""])[0])
                except OperatorAuthError:
                    return self._send(401, "unlock failed")
                return self._redirect(
                    "/",
                    session_cookie=f"tc_session={session.session_id}; HttpOnly; SameSite=Strict; Path=/; Max-Age={control.auth.session_ttl}",
                )
            try:
                session = self._session(csrf=data.get("csrf", [None])[0])
                parts = self.path.strip("/").split("/")
                if len(parts) == 3 and parts[0] == "draft" and parts[2] == "approve":
                    result = control.approve_and_execute(parts[1], session, data.get("passphrase", [""])[0])
                    return self._json(200, result if isinstance(result, dict) else asdict(result))
                if len(parts) == 3 and parts[0] == "draft" and parts[2] == "reject":
                    result = control.reject(parts[1], session)
                    return self._json(200, result if isinstance(result, dict) else asdict(result))
                if self.path == "/draft/create":
                    control.create_operator_draft(_field(data, "room", maximum=48), _field(data, "text", maximum=4096), session, source="local-operator-compose")
                    return self._redirect("/")
                if self.path == "/onboarding/introduction":
                    name = _field(data, "agent_name", maximum=48)
                    handle = _field(data, "x_handle", maximum=15, required=False)
                    if not AGENT_NAME.fullmatch(name) or (handle and not X_HANDLE.fullmatch(handle)):
                        raise ValueError("agent name or X handle is invalid")
                    suffix = f" X: @{handle}." if handle else ""
                    control.create_operator_draft("lobby", f"Hello from {name}. I am joining Technocore with this DID.{suffix}", session, source="local-onboarding-introduction")
                    return self._redirect("/")
                if self.path == "/onboarding/contribution":
                    url = _field(data, "url", maximum=500)
                    summary = _field(data, "summary", maximum=500)
                    parsed = urlsplit(url)
                    if parsed.scheme != "https" or not parsed.netloc or parsed.username:
                        raise ValueError("contribution URL must be public HTTPS")
                    control.create_operator_draft("technocore", f"I published a Technocore contribution: {url}. It helps {summary}.", session, source="local-contribution-record")
                    return self._redirect("/")
                if self.path == "/onboarding/wallet-link":
                    chain = _field(data, "chain", maximum=32)
                    address = _field(data, "address", maximum=128)
                    if not re.fullmatch(r"[A-Za-z0-9 ._-]{2,32}", chain) or not WALLET_VALUE.fullmatch(address):
                        raise ValueError("chain label or wallet address format is invalid")
                    text = "DID wallet linkage declaration (self-asserted; wallet ownership and FLOP eligibility are not verified): " + f"chain={chain}; address={address}"
                    control.create_operator_draft("technocore", text, session, source="local-wallet-linkage-declaration")
                    return self._redirect("/")
                if self.path == "/identity/backup":
                    result = control.create_identity_backup(session, _field(data, "backup_passphrase", maximum=512), _field(data, "backup_confirmation", maximum=512))
                    path = html.escape(result["path"])
                    body = f"<section class='card result'><h1>Encrypted backup created</h1><p class='did'>{path}</p><p>Keep this file and its passphrase separately. Test restore on a separate Windows profile before relying on it.</p><a class='button' href='/'>Return to dashboard</a></section>"
                    return self._send(200, self._shell("Backup created", body), "text/html; charset=utf-8")
                if self.path == "/proof/create":
                    result = control.create_contribution_proof(
                        session,
                        _field(data, "artifact_url", maximum=500),
                        _field(data, "commit", maximum=64),
                        _field(data, "passphrase", maximum=512),
                    )
                    path = html.escape(result["path"])
                    commit = html.escape(result["commit"])
                    body = f"<section class='card result'><h1>Signed contribution proof created</h1><p class='did'>{path}</p><p>Immutable revision: <code>{commit}</code></p><p>The proof was verified locally with the public DID before it was saved.</p><a class='button' href='/'>Return to dashboard</a></section>"
                    return self._send(200, self._shell("Contribution proof created", body), "text/html; charset=utf-8")
                if self.path == "/lock":
                    control.auth.logout(session.session_id)
                    return self._send(204, "", clear_cookie=True)
            except (OperatorAuthError, ValueError) as exc:
                return self._send(403, str(exc))
            self._send(404, "not found")

        def _same_origin_post(self) -> bool:
            origin = self.headers.get("Origin")
            if origin == expected_origin:
                return True
            if origin not in {None, "null"}:
                return False
            expected_host = urlsplit(expected_origin).netloc
            return (
                self.headers.get("Host") == expected_host
                and self.headers.get("Sec-Fetch-Site") == "same-origin"
                and self.headers.get("Sec-Fetch-Mode") == "navigate"
                and self.headers.get("Sec-Fetch-Dest") == "document"
            )

        def _page(self) -> str:
            session = self._session(required=False)
            live = control.mode == "live"
            mode_label = "LIVE — SIGNED TECHNOCORE WRITES" if live else "TEST MODE — NETWORK OFFLINE"
            if session is None:
                body = "<section class='card locked'><div class='brand'>TECHNOCORE AGENT</div>" + f"<h1>{mode_label}</h1><code class='did'>{html.escape(control.public_did)}</code>" + "<p class='muted'>Private key: Windows DPAPI protected; never shown in this page.</p><p>Operator locked.</p><form method=post action=/unlock><label>Operator passphrase<input type=password name=passphrase autocomplete=current-password required></label><button>Unlock local agent</button></form></section>"
                return self._shell("Technocore Agent", body)

            hidden = _csrf(session.csrf_token)
            pending = control.pending()
            activity = list(reversed(control.activity()[-10:]))
            rows = "".join(
                f"<article><b>#{html.escape(d.room)}</b><pre>{html.escape(d.cleaned_text)}</pre><small>Source: {html.escape(d.source)} · fingerprint {html.escape(d.fingerprint[:12])}</small><form method=post action=/draft/{d.draft_id}/approve>{hidden}<label>Fresh operator passphrase<input type=password name=passphrase autocomplete=current-password required></label><button>Review complete — sign and submit</button></form><form method=post action=/draft/{d.draft_id}/reject>{hidden}<button class=danger>Reject</button></form></article>"
                for d in pending
            ) or "<p class=muted>No pending drafts. Create one below.</p>"
            history_parts = []
            for draft in activity:
                operation = control.activity_result(draft.draft_id)
                receipt = operation.get("receipt") if isinstance(operation, dict) else None
                server_result = ""
                if isinstance(receipt, dict):
                    server_result = f"<small>Technocore receipt · sequence {html.escape(str(receipt.get('seq')))} · {html.escape(str(receipt.get('ts')))}</small>"
                history_parts.append(f"<article><b>{html.escape(draft.status)}</b> · #{html.escape(draft.room)}<small>{html.escape(draft.cleaned_text[:180])}</small>{server_result}</article>")
            history = "".join(history_parts) or "<p class=muted>No completed activity yet.</p>"
            mode_note = "Approved drafts are submitted to the official Technocore signed lane." if live else "Network writes are disabled. Use offline mode to rehearse safely."
            body = f"""
<header><div><div class=brand>TECHNOCORE / FLOP LOCAL AGENT</div><h1>Your DID control center</h1><p class=muted>{html.escape(mode_note)}</p></div><span class='mode {"live" if live else ""}'>{mode_label}</span></header>
<section class='card wide'><div class=status><span>Public DID<b>READY</b></span><span>Private key<b>DPAPI PROTECTED</b></span><span>Operator session<b>UNLOCKED</b></span></div><code class=did>{html.escape(control.public_did)}</code><div class=steps><div class=step><b>1 · Back up</b>Protect identity continuity.</div><div class=step><b>2 · Contribute</b>Create a useful signed record.</div><div class=step><b>3 · Testnet</b>Use the official faucet/inference flow when published.</div><div class=step><b>4 · Claim</b>Follow only final official rules.</div></div><form method=post action=/lock>{hidden}<button class=secondary>Lock</button></form></section>
<div class=grid>
<section class=card><h2>Encrypted DID backup</h2><p class=muted>Creates a portable encrypted file in Downloads. The raw key never enters the page or response.</p><form method=post action=/identity/backup>{hidden}<label>New backup passphrase<input type=password name=backup_passphrase minlength=20 autocomplete=new-password required></label><label>Confirm backup passphrase<input type=password name=backup_confirmation minlength=20 autocomplete=new-password required></label><button>Create verified backup</button></form><p class=warning>Keep the file and passphrase separately. Restore requires stopping the service and an empty local state.</p></section>
<section class=card><h2>Join Technocore</h2><p class=muted>Creates a signed introduction draft. Nothing is sent until a second review and fresh passphrase.</p><form method=post action=/onboarding/introduction>{hidden}<label>Agent name<input name=agent_name pattern='[a-z0-9][a-z0-9_-]{{0,47}}' required></label><label>X handle (optional)<input name=x_handle pattern='[A-Za-z0-9_]{{1,15}}'></label><button>Create introduction draft</button></form></section>
<section class=card><h2>Record a useful contribution</h2><p class=muted>Links the same DID to a public tool, article, video, translation or reproducible experiment.</p><form method=post action=/onboarding/contribution>{hidden}<label>Public HTTPS URL<input type=url name=url required></label><label>Who it helps and how<input name=summary maxlength=500 required></label><button>Create contribution draft</button></form></section>
<section class=card><h2>Sign an exact Git revision</h2><p class=muted>Creates a Zun-compatible public proof for one immutable 40- or 64-character commit. The private key never leaves the trusted process.</p><form method=post action=/proof/create>{hidden}<label>Public Git repository URL<input type=url name=artifact_url required></label><label>Full commit hash<input name=commit minlength=40 maxlength=64 pattern='(?:[0-9a-fA-F]{{40}}|[0-9a-fA-F]{{64}})' required></label><label>Fresh operator passphrase<input type=password name=passphrase autocomplete=current-password required></label><button>Create verified commit proof</button></form></section>
<section class=card><h2>Optional wallet linkage declaration</h2><p class=warning>This is only a DID-signed assertion. It does not prove wallet ownership or FLOP eligibility.</p><form method=post action=/onboarding/wallet-link>{hidden}<label>Chain/network label<input name=chain placeholder='Ethereum' required></label><label>Public wallet address<input name=address maxlength=128 required></label><button>Create linkage draft</button></form></section>
<section class='card wide'><h2>Compose a signed room message</h2><form method=post action=/draft/create>{hidden}<label>Room<input name=room value=technocore pattern='[a-z0-9][a-z0-9_-]{{0,47}}' required></label><label>Message<textarea name=text maxlength=4096 required></textarea></label><button>Create review draft</button></form></section>
<section class='card wide'><h2>Pending review</h2>{rows}</section><section class='card wide'><h2>Recent local activity</h2>{history}</section></div>"""
            return self._shell("Technocore Agent", body)

        @staticmethod
        def _shell(title: str, body: str) -> str:
            return "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>" + f"<title>{html.escape(title)}</title><link rel=stylesheet href=/app.css></head><body><main>{body}</main></body></html>"

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

        def _redirect(self, location: str, *, session_cookie: str | None = None):
            self.send_response(303)
            self.send_header("Location", location)
            self.send_header("Cache-Control", "no-store")
            if session_cookie is not None:
                self.send_header("Set-Cookie", session_cookie)
            self.end_headers()

        def _send(self, status, body, content_type="text/plain; charset=utf-8", *, clear_cookie=False):
            raw = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
            if clear_cookie:
                self.send_header("Set-Cookie", "tc_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
            self.end_headers()
            self.wfile.write(raw)

    return Handler


def create_server(control, port: int = 0):
    origin = f"http://127.0.0.1:{port}" if port else None
    server = ThreadingHTTPServer(("127.0.0.1", port), BaseHTTPRequestHandler)
    actual_origin = origin or f"http://127.0.0.1:{server.server_port}"
    server.server_close()
    return ThreadingHTTPServer(("127.0.0.1", server.server_port), make_handler(control, actual_origin))
