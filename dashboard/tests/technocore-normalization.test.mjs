import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../app/lib/technocore.ts", import.meta.url), "utf8");
const hub = fs.readFileSync(new URL("../app/ui/hub.tsx", import.meta.url), "utf8");
const { fetchTechnocoreJson, normalizeRoomPayload, normalizeRooms } = await import(
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
  assert.match(hub, /Create \/ connect DID — after security-core freeze/);
  assert.doesNotMatch(hub, /DID-SIGNED WRITER/);
  assert.match(hub, /DID:KEY FORMAT · NOT REVERIFIED/);
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
