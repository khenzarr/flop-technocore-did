import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/lib/technocore.ts", import.meta.url), "utf8");
const hub = fs.readFileSync(new URL("../app/ui/hub.tsx", import.meta.url), "utf8");
const { calculateRoomSignals, fetchTechnocoreHealthJson, fetchTechnocoreJson, normalizeIndexerHealth, normalizeIndexerSearch, normalizeIndexerUrl, normalizeRoomPayload, normalizeRooms, normalizeTrustMode } = await import(
  new URL("../app/lib/technocore.ts", import.meta.url)
);

test("upstream client has a bounded response and timeout", () => {
  assert.match(source, /MAX_UPSTREAM_BYTES\s*=\s*1024 \* 1024/);
  assert.match(source, /UPSTREAM_TIMEOUT_MS\s*=\s*6000/);
  assert.match(source, /AbortSignal\.timeout\(UPSTREAM_TIMEOUT_MS\)/);
  assert.match(source, /unexpected_content_type/);
  assert.match(source, /response_too_large/);
});

test("observer preview does not advertise active production signing", () => {
  assert.doesNotMatch(hub, /sign-and-submit/);
  assert.doesNotMatch(hub, /Offline-verifiable/);
  assert.match(hub, /SAMPLE DATA · NOT LIVE NETWORK ACTIVITY/);
  assert.match(hub, /Create \/ connect DID — guided after security review/);
  assert.doesNotMatch(hub, /DID-SIGNED WRITER/);
  assert.match(hub, /DID:KEY FORMAT · NOT REVERIFIED/);
});

test("observer refreshes the selected room and opens only exact bounded room names", () => {
  assert.match(hub, /window\.setInterval\(\(\) => \{/);
  assert.match(hub, /}, 12000\)/);
  assert.match(hub, /\^\[a-z0-9\]\[a-z0-9_-\]\{0,47\}\$/);
  assert.match(hub, /OPEN EXACT ROOM OR MAILBOX/);
  assert.match(hub, /This does not discover unlisted rooms/);
  assert.match(hub, /proves no privacy, ownership, identity, or legitimacy/);
});

test("live pulse derives bounded room signals without inventing history", () => {
  const signals = calculateRoomSignals([
    { seq: 1, ts: "2026-08-28T10:00:00Z", from: "did:key:one", text: "a" },
    { seq: 2, ts: "2026-08-28T10:00:30Z", from: "~claim", text: "b" },
    { seq: 3, ts: "2026-08-28T10:01:00Z", from: "did:key:one", text: "c" },
    { seq: 4, ts: "2026-08-28T10:01:30Z", from: "did:key:two", text: "d" },
  ]);
  assert.deepEqual(signals, { messagesPerMinute: 2, distinctDidWriters: 2, spanSeconds: 90 });
  assert.deepEqual(calculateRoomSignals([]), { messagesPerMinute: null, distinctDidWriters: 0, spanSeconds: null });
  assert.equal(calculateRoomSignals([
    { seq: 1, ts: "2026-08-28T10:00:00Z", from: "~a", text: "a" },
    { seq: 2, ts: "2026-08-28T10:00:00Z", from: "~b", text: "b" },
  ]).messagesPerMinute, null);
  assert.match(hub, /TECHNOCORE LIVE PULSE/);
  assert.match(hub, /Signals are derived only from the currently loaded bounded window/);
  assert.match(hub, /Math\.max\(0, nextLast - previousLast\)/);
});

test("console monitor is an original bounded alternate room view", () => {
  assert.match(hub, /TECHNOCORE CONSOLE MONITOR/);
  assert.match(hub, /ROOM DIRECTORY/);
  assert.match(hub, /LIVE TERMINAL/);
  assert.match(hub, /setViewMode\("console"\)/);
  assert.match(hub, /DID-FORMAT/);
  assert.match(hub, /CLAIMED/);
  assert.match(hub, /currently loaded observed window/);
  assert.match(hub, /onClick=\{\(\) => setRoom\(item\.name\)\}/);
  assert.doesNotMatch(hub, /dangerouslySetInnerHTML/);
});

test("normalization accepts only non-negative safe integer metrics", () => {
  assert.deepEqual(normalizeRooms({ rooms: [
    { name: "valid", size: 4, idle_seconds: 0 },
    { name: "coerced", size: "4", idle_seconds: false },
  ] }), [
    { name: "valid", size: 4, idle_seconds: 0 },
    { name: "coerced" },
  ]);

  const payload = normalizeRoomPayload({
    messages: [
      { seq: 1, ts: "2026-08-26T00:00:00Z", from: "~alice", text: "ok", nonce: "42" },
      { seq: "2", ts: "2026-08-26T00:00:01Z", from: "~bob", text: "coerced" },
      { seq: -1, ts: "2026-08-26T00:00:02Z", from: "~carol", text: "negative" },
    ],
    first_seq: 1,
    last_seq: 4,
  });
  assert.equal(payload.messages.length, 1);
  assert.equal(payload.messages[0].nonce, "42");
  assert.equal(payload.first_seq, 1);
  assert.equal(payload.last_seq, 4);
  assert.equal(payload.gap, undefined);
});

test("invalid coverage ranges remain unknown rather than becoming credible metrics", () => {
  const payload = normalizeRoomPayload({ messages: [], first_seq: 9, last_seq: 2, gap: false });
  assert.equal(payload.first_seq, undefined);
  assert.equal(payload.last_seq, undefined);
  assert.equal(payload.gap, false);
});

test("upstream fetch rejects redirects and requires JSON", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (_url, options) => {
      assert.equal(options.redirect, "error");
      return new Response('{"ok":true}', { headers: { "content-type": "application/json" } });
    };
    assert.deepEqual(await fetchTechnocoreJson("https://technocore.chat/test"), { ok: true });

    globalThis.fetch = async () => new Response("text", { headers: { "content-type": "text/plain" } });
    await assert.rejects(fetchTechnocoreJson("https://technocore.chat/test"), /unexpected_content_type/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("trust modes fail closed and indexer URLs are strict canonical origins", () => {
  assert.equal(normalizeTrustMode("browser-did"), "browser-did");
  assert.equal(normalizeTrustMode("trusted-local-signer"), "trusted-local-signer");
  assert.equal(normalizeTrustMode("anything-else"), "observer");
  assert.equal(normalizeIndexerUrl("http://127.0.0.1:8788/"), "http://127.0.0.1:8788");
  assert.equal(normalizeIndexerUrl(" HTTP://LOCALHOST:80/ "), "http://localhost");
  assert.equal(normalizeIndexerUrl("http://[::1]:8788/"), "http://[::1]:8788");
  assert.equal(normalizeIndexerUrl("https://EXAMPLE.test:443/"), "https://example.test");
  assert.equal(normalizeIndexerUrl("https://user:pass@example.test"), undefined);
  assert.equal(normalizeIndexerUrl("https://example.test/#secret"), undefined);
  assert.equal(normalizeIndexerUrl("https://example.test/?q=secret"), undefined);
  assert.equal(normalizeIndexerUrl("https://example.test/api"), undefined);
  assert.equal(normalizeIndexerUrl("http://example.test"), undefined);
  assert.equal(normalizeIndexerUrl("http://0.0.0.0:8788"), undefined);
});

test("indexer normalization exposes observed-only bounded fields", () => {
  assert.deepEqual(normalizeIndexerHealth({ ok: true, database: "ok", worker_fresh: true, messages: 4 }), {
    configured: true, reachable: true, worker_fresh: true, messages: 4, scope: "observed_only",
  });
  assert.throws(() => normalizeIndexerHealth({ ok: true }), /invalid_indexer_health/);
  assert.deepEqual(normalizeIndexerSearch({ messages: [
    { room: "lobby", seq: 4, ts: "t", writer: "~a", text: "found", nonce: "3" },
    { room: "bad", seq: "4", ts: "t", writer: "~b", text: "discard" },
  ] }), [{ room: "lobby", seq: 4, ts: "t", writer: "~a", text: "found", nonce: "3" }]);
});

test("indexer health rejects invalid semantic combinations instead of reporting availability", () => {
  for (const invalid of [
    { ok: true, database: "ok" },
    { ok: true, database: "ok", worker_fresh: false },
    { ok: false, database: "ok", worker_fresh: true },
    { ok: false, database: "failed", worker_fresh: false },
    { ok: true, database: "failed", worker_fresh: true },
    { ok: true, database: "ok", worker_fresh: "true" },
  ]) {
    assert.throws(() => normalizeIndexerHealth(invalid), /invalid_indexer_health/);
  }
});

test("health-specific fetch preserves structured stale 503 and rejects other errors", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (_url, options) => {
      assert.equal(options.redirect, "error");
      return new Response('{"ok":false,"database":"ok","worker_fresh":false,"messages":9}', { status: 503, headers: { "content-type": "application/json" } });
    };
    assert.deepEqual(normalizeIndexerHealth(await fetchTechnocoreHealthJson("https://indexer.example/health")), {
      configured: true, reachable: true, worker_fresh: false, messages: 9, scope: "observed_only",
    });
    globalThis.fetch = async () => new Response('{"error":"down"}', { status: 502, headers: { "content-type": "application/json" } });
    await assert.rejects(fetchTechnocoreHealthJson("https://indexer.example/health"), /upstream_error/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("invalid upstream health is classified as unreachable by the route", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response('{"ok":false,"database":"failed","worker_fresh":false}', { status: 503, headers: { "content-type": "application/json" } });
    await assert.rejects(
      fetchTechnocoreHealthJson("https://indexer.example/health").then(normalizeIndexerHealth),
      /invalid_indexer_health/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("dashboard styles keep message content shrinkable and wrap hostile strings", () => {
  const styles = fs.readFileSync(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(styles, /\.message\{[^}]*grid-template-columns:34px minmax\(0,1fr\)/);
  assert.match(styles, /\.message-body\{[^}]*min-width:0/);
  assert.match(styles, /\.message-body>p\{[^}]*overflow-wrap:anywhere/);
  assert.match(styles, /\.proof\{[^}]*flex-wrap:wrap/);
});

test("bounded fetch rejects malformed JSON and oversized responses", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response("{", { headers: { "content-type": "application/json" } });
    await assert.rejects(fetchTechnocoreJson("https://indexer.example/search"), SyntaxError);
    globalThis.fetch = async () => new Response("x".repeat(1024 * 1024 + 1), { headers: { "content-type": "application/json" } });
    await assert.rejects(fetchTechnocoreJson("https://indexer.example/search"), /response_too_large/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("indexer public-field boundaries match the indexer exactly", () => {
  const valid = (overrides = {}) => ({ room: "r", seq: 0, ts: "t".repeat(64), writer: "w".repeat(512), text: "x".repeat(16384), nonce: "n".repeat(128), ...overrides });
  assert.equal(normalizeIndexerSearch({ messages: [valid()] }).length, 1);
  for (const invalid of [
    valid({ room: "A" }), valid({ room: `r${"a".repeat(48)}` }), valid({ room: "-room" }),
    valid({ ts: "t".repeat(65) }), valid({ writer: "w".repeat(513) }), valid({ text: "x".repeat(16385) }),
    valid({ nonce: "n".repeat(129) }), valid({ nonce: 1 }), valid({ seq: -1 }), valid({ seq: Number.MAX_SAFE_INTEGER + 1 }), valid({ seq: 1.5 }),
  ]) assert.equal(normalizeIndexerSearch({ messages: [invalid] }).length, 0);
  assert.equal(normalizeIndexerSearch({ messages: Array.from({ length: 51 }, (_, seq) => valid({ seq })) }).length, 50);
});
