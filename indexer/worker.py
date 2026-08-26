"""Cursor-aware, read-only Technocore observer with an SQLite search API."""

from __future__ import annotations

import json
import os
import random
import sqlite3
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TypedDict
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlparse
from urllib.request import Request, urlopen

MAX_RESPONSE_BYTES = 1_048_576
MAX_API_RESPONSE_BYTES = 1_048_576
MAX_MESSAGE_TEXT = 16_384
MAX_WRITER = 512
MAX_TIMESTAMP = 64
MAX_NONCE = 128
MAX_SQLITE_INTEGER = 9_223_372_036_854_775_807
ROOM_RE = __import__("re").compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")


class NormalizedMessage(TypedDict):
    seq: int
    ts: str
    writer: str
    text: str
    nonce: str | None

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS messages (
  room TEXT NOT NULL,
  seq INTEGER NOT NULL,
  ts TEXT NOT NULL,
  writer TEXT NOT NULL,
  nonce TEXT,
  text TEXT NOT NULL,
  observed_at INTEGER NOT NULL,
  PRIMARY KEY (room, seq)
);
CREATE INDEX IF NOT EXISTS messages_writer_idx ON messages(writer, observed_at DESC);
CREATE TABLE IF NOT EXISTS coverage (
  room TEXT PRIMARY KEY,
  first_observed_seq INTEGER,
  last_observed_seq INTEGER,
  upstream_first_seq INTEGER,
  upstream_last_seq INTEGER,
  gap_detected INTEGER NOT NULL DEFAULT 0,
  gap_reason TEXT,
  last_error TEXT,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS worker_state (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  last_cycle_started INTEGER,
  last_cycle_succeeded INTEGER,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  last_error TEXT
);
INSERT OR IGNORE INTO worker_state(singleton) VALUES(1);
"""


@dataclass(frozen=True)
class Config:
    base_url: str
    database: Path
    interval: int
    max_rooms: int
    bind: str
    port: int

    @classmethod
    def from_environment(cls) -> Config:
        base = os.getenv("TECHNOCORE_BASE_URL", "https://technocore.chat").rstrip("/")
        parsed = urlparse(base)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
            raise ValueError("TECHNOCORE_BASE_URL must be an absolute HTTP(S) URL without credentials")
        return cls(
            base_url=base,
            database=Path(os.getenv("TECHNOCORE_INDEX_DB", "data/technocore-index.sqlite3")),
            interval=max(5, int(os.getenv("TECHNOCORE_INDEX_INTERVAL_SECONDS", "15"))),
            max_rooms=min(500, max(1, int(os.getenv("TECHNOCORE_INDEX_MAX_ROOMS", "50")))),
            bind=os.getenv("TECHNOCORE_INDEX_BIND", "127.0.0.1"),
            port=int(os.getenv("TECHNOCORE_INDEX_PORT", "8788")),
        )


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=15)
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)
    coverage_columns = {row[1] for row in db.execute("PRAGMA table_info(coverage)")}
    if "gap_reason" not in coverage_columns:
        db.execute("ALTER TABLE coverage ADD COLUMN gap_reason TEXT")
        db.commit()
    return db


def fetch_json(url: str) -> object:
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "technocore-agent-hub-indexer/0.3"})
    with urlopen(request, timeout=12) as response:
        content_type = response.headers.get_content_type()
        if content_type != "application/json":
            raise ValueError("unexpected_content_type")
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise ValueError("response_too_large")
    return json.loads(body.decode("utf-8", errors="strict"))


def normalize_rooms(value: object) -> list[str]:
    source = value.get("rooms") if isinstance(value, dict) else value
    if not isinstance(source, list):
        raise ValueError("invalid_rooms_schema")
    result: list[str] = []
    for item in source:
        if not isinstance(item, dict):
            continue
        name = item.get("name", item.get("room"))
        if isinstance(name, str) and ROOM_RE.fullmatch(name):
            result.append(name)
    return result


def normalize_payload(value: object) -> tuple[list[NormalizedMessage], int | None, int | None, bool]:
    if not isinstance(value, dict) or not isinstance(value.get("messages"), list):
        raise ValueError("invalid_room_schema")
    messages: list[NormalizedMessage] = []
    for item in value["messages"]:
        if not isinstance(item, dict) or isinstance(item.get("seq"), bool):
            continue
        seq = item.get("seq")
        if not isinstance(seq, int) or seq < 0 or seq > MAX_SQLITE_INTEGER:
            continue
        ts, writer, text = item.get("ts"), item.get("from"), item.get("text")
        if not all(isinstance(part, str) for part in (ts, writer, text)):
            continue
        if len(ts) > MAX_TIMESTAMP or len(writer) > MAX_WRITER or len(text) > MAX_MESSAGE_TEXT:
            continue
        nonce = item.get("nonce")
        if nonce is not None and (not isinstance(nonce, (int, str)) or len(str(nonce)) > MAX_NONCE):
            continue
        messages.append({"seq": seq, "ts": ts, "writer": writer, "text": text, "nonce": None if nonce is None else str(nonce)})
    first = value.get("first_seq")
    last = value.get("last_seq")
    first_seq = first if isinstance(first, int) and not isinstance(first, bool) and 0 <= first <= MAX_SQLITE_INTEGER else None
    last_seq = last if isinstance(last, int) and not isinstance(last, bool) and 0 <= last <= MAX_SQLITE_INTEGER else None
    if first_seq is not None and last_seq is not None and first_seq > last_seq:
        first_seq = last_seq = None
    return messages, first_seq, last_seq, value.get("gap") is True


def ingest(db: sqlite3.Connection, room: str, payload: object, previous: int) -> int:
    messages, upstream_first, upstream_last, reported_gap = normalize_payload(payload)
    now = int(time.time())
    inferred_gap = upstream_first is not None and previous > 0 and upstream_first > previous + 1
    initial_gap = previous == 0 and upstream_first is not None and upstream_first > 0
    ordered_sequences = sorted({message["seq"] for message in messages})
    internal_gap = any(
        current > prior + 1
        for prior, current in zip(ordered_sequences, ordered_sequences[1:], strict=False)
    )
    gap_reason = None
    if reported_gap:
        gap_reason = "upstream_reported"
    elif inferred_gap:
        gap_reason = "cursor_discontinuity"
    elif initial_gap:
        gap_reason = "history_before_initial_window_unknown"
    elif internal_gap:
        gap_reason = "internal_sequence_discontinuity"
    for message in messages:
        db.execute(
            "INSERT OR IGNORE INTO messages(room,seq,ts,writer,nonce,text,observed_at) VALUES(?,?,?,?,?,?,?)",
            (room, message["seq"], message["ts"], message["writer"], message["nonce"], message["text"], now),
        )
    observed = max((message["seq"] for message in messages), default=previous)
    first_observed = min((message["seq"] for message in messages), default=None)
    db.execute(
        """INSERT INTO coverage(room,first_observed_seq,last_observed_seq,upstream_first_seq,upstream_last_seq,gap_detected,gap_reason,last_error,updated_at)
           VALUES(?,?,?,?,?,?,?,NULL,?)
           ON CONFLICT(room) DO UPDATE SET
             first_observed_seq=COALESCE(coverage.first_observed_seq,excluded.first_observed_seq),
             last_observed_seq=MAX(coverage.last_observed_seq,excluded.last_observed_seq),
             upstream_first_seq=excluded.upstream_first_seq,
             upstream_last_seq=excluded.upstream_last_seq,
             gap_detected=MAX(coverage.gap_detected,excluded.gap_detected),
             gap_reason=COALESCE(coverage.gap_reason,excluded.gap_reason),last_error=NULL,updated_at=excluded.updated_at""",
        (room, first_observed, observed, upstream_first, upstream_last, int(gap_reason is not None), gap_reason, now),
    )
    db.commit()
    return observed


def observe_once(config: Config) -> None:
    rooms = normalize_rooms(fetch_json(f"{config.base_url}/rooms?format=json&limit={config.max_rooms}"))[: config.max_rooms]
    with connect(config.database) as db:
        for room in rooms:
            row = db.execute("SELECT last_observed_seq FROM coverage WHERE room=?", (room,)).fetchone()
            previous = int(row[0]) if row and row[0] is not None else 0
            try:
                payload = fetch_json(f"{config.base_url}/r/{quote(room, safe='')}?format=json&since={previous}&limit=200")
                ingest(db, room, payload, previous)
            except (HTTPError, URLError, TimeoutError, ValueError, json.JSONDecodeError) as error:
                db.execute(
                    """INSERT INTO coverage(room,last_observed_seq,gap_detected,gap_reason,last_error,updated_at) VALUES(?,?,1,?,?,?)
                       ON CONFLICT(room) DO UPDATE SET gap_detected=1,
                         gap_reason=COALESCE(coverage.gap_reason,excluded.gap_reason),
                         last_error=excluded.last_error,updated_at=excluded.updated_at""",
                    (room, previous, "observation_failure_unknown_coverage", type(error).__name__, int(time.time())),
                )
                db.commit()


def api_handler(database: Path, stale_after: int = 120) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def respond(self, status: int, body: object) -> None:
            payload = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            if len(payload) > MAX_API_RESPONSE_BYTES:
                status = 500
                payload = b'{"error":"response_too_large"}'
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            with connect(database) as db:
                if parsed.path == "/health":
                    count = db.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
                    state = db.execute("SELECT * FROM worker_state WHERE singleton=1").fetchone()
                    now = int(time.time())
                    last_success = state["last_cycle_succeeded"] if state else None
                    fresh = last_success is not None and now - int(last_success) <= stale_after
                    return self.respond(200 if fresh else 503, {
                        "ok": fresh,
                        "database": "ok",
                        "worker_fresh": fresh,
                        "last_cycle_succeeded": last_success,
                        "consecutive_failures": state["consecutive_failures"] if state else None,
                        "last_error": state["last_error"] if state else "worker_not_started",
                        "messages": count,
                    })
                if parsed.path == "/coverage":
                    rows = db.execute("SELECT * FROM coverage ORDER BY updated_at DESC LIMIT 500").fetchall()
                    return self.respond(200, {"coverage": [dict(row) for row in rows]})
                if parsed.path == "/search":
                    term = query.get("q", [""])[0][:200]
                    try:
                        limit = min(50, max(1, int(query.get("limit", ["50"])[0])))
                    except ValueError:
                        limit = 50
                    rows = db.execute("SELECT room,seq,ts,writer,nonce,text,observed_at FROM messages WHERE text LIKE ? ESCAPE '\\' OR writer LIKE ? ESCAPE '\\' ORDER BY observed_at DESC LIMIT ?", (f"%{escape_like(term)}%", f"%{escape_like(term)}%", limit)).fetchall()
                    return self.respond(200, {"messages": [dict(row) for row in rows], "scope": "observed_only"})
                if parsed.path == "/activity":
                    did = query.get("did", [""])[0][:256]
                    rows = db.execute("SELECT room,COUNT(*) AS messages,MIN(seq) AS first_seq,MAX(seq) AS last_seq FROM messages WHERE writer=? GROUP BY room ORDER BY messages DESC LIMIT 100", (did,)).fetchall()
                    return self.respond(200, {"did": did, "rooms": [dict(row) for row in rows], "claim": "key_possession_only"})
            return self.respond(404, {"error": "not_found"})

        def log_message(self, format: str, *args: object) -> None:
            return

    return Handler


def escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def main() -> None:
    config = Config.from_environment()
    stale_after = max(60, config.interval * 4)
    server = ThreadingHTTPServer((config.bind, config.port), api_handler(config.database, stale_after))
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    failures = 0
    while True:
        started = time.monotonic()
        started_at = int(time.time())
        with connect(config.database) as db:
            db.execute("UPDATE worker_state SET last_cycle_started=? WHERE singleton=1", (started_at,))
            db.commit()
        try:
            observe_once(config)
            failures = 0
            with connect(config.database) as db:
                db.execute("UPDATE worker_state SET last_cycle_succeeded=?,consecutive_failures=0,last_error=NULL WHERE singleton=1", (int(time.time()),))
                db.commit()
        except (HTTPError, URLError, TimeoutError, ValueError, json.JSONDecodeError, sqlite3.Error, OSError, OverflowError) as error:
            failures += 1
            with connect(config.database) as db:
                db.execute("UPDATE worker_state SET consecutive_failures=?,last_error=? WHERE singleton=1", (failures, type(error).__name__))
                db.commit()
            print(json.dumps({"event": "observation_cycle_failed", "error": type(error).__name__}), flush=True)
        base_delay = config.interval if failures == 0 else min(300, config.interval * (2 ** min(failures, 5)))
        jitter = 0 if failures == 0 else random.uniform(0, min(5, base_delay * 0.1))
        time.sleep(max(0.5, base_delay + jitter - (time.monotonic() - started)))


if __name__ == "__main__":
    main()
