import assert from "node:assert/strict";
import test from "node:test";

const healthRoute = await import(new URL("../app/api/technocore/indexer/route.ts", import.meta.url));
const searchRoute = await import(new URL("../app/api/technocore/indexer/search/route.ts", import.meta.url));

async function withEnvironment(url, fetchImpl, action) {
  const priorUrl = process.env.TECHNOCORE_INDEXER_URL;
  const priorFetch = globalThis.fetch;
  if (url === undefined) delete process.env.TECHNOCORE_INDEXER_URL;
  else process.env.TECHNOCORE_INDEXER_URL = url;
  globalThis.fetch = fetchImpl;
  try { return await action(); }
  finally {
    if (priorUrl === undefined) delete process.env.TECHNOCORE_INDEXER_URL;
    else process.env.TECHNOCORE_INDEXER_URL = priorUrl;
    globalThis.fetch = priorFetch;
  }
}

test("health route reports unconfigured without fetching", async () => {
  await withEnvironment(undefined, async () => { throw new Error("unexpected fetch"); }, async () => {
    const response = await healthRoute.GET();
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { configured: false, reachable: false, scope: "observed_only" });
  });
});

test("health route reports available and preserves structured stale 503", async () => {
  await withEnvironment("https://indexer.example/", async () => Response.json({ ok: true, database: "ok", worker_fresh: true, messages: 4 }), async () => {
    const response = await healthRoute.GET();
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { configured: true, reachable: true, worker_fresh: true, messages: 4, scope: "observed_only" });
  });
  await withEnvironment("https://indexer.example", async () => Response.json({ ok: false, database: "ok", worker_fresh: false, messages: 7 }, { status: 503 }), async () => {
    const response = await healthRoute.GET();
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { configured: true, reachable: true, worker_fresh: false, messages: 7, scope: "observed_only" });
  });
});

test("health route reports unreachable for transport and response-validation failures", async () => {
  const cases = [
    async () => { throw new TypeError("connect failed"); },
    async () => new Response("text", { headers: { "content-type": "text/plain" } }),
    async () => new Response("{", { headers: { "content-type": "application/json" } }),
    async () => new Response("x".repeat(1024 * 1024 + 1), { headers: { "content-type": "application/json" } }),
    async () => { throw new TypeError("redirect mode is error"); },
  ];
  for (const fetchImpl of cases) await withEnvironment("https://indexer.example", fetchImpl, async () => {
    const response = await healthRoute.GET();
    assert.deepEqual(await response.json(), { configured: true, reachable: false, scope: "observed_only" });
  });
});

test("search route proxies a bounded query and normalizes results", async () => {
  await withEnvironment("https://indexer.example", async (url, options) => {
    assert.equal(url, "https://indexer.example/search?q=hello%20world&limit=50");
    assert.equal(options.redirect, "error");
    return Response.json({ messages: [{ room: "lobby", seq: 2, ts: "t", writer: "~a", text: "hello", nonce: null }] });
  }, async () => {
    const response = await searchRoute.GET(new Request("https://dashboard.example/api/technocore/indexer/search?q=%20hello%20world%20"));
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { configured: true, messages: [{ room: "lobby", seq: 2, ts: "t", writer: "~a", text: "hello", nonce: null }], scope: "observed_only" });
  });
});

test("search route handles unconfigured, blank, and unavailable states", async () => {
  await withEnvironment(undefined, async () => { throw new Error("unexpected fetch"); }, async () => {
    const response = await searchRoute.GET(new Request("https://dashboard.example/api/technocore/indexer/search?q=test"));
    assert.deepEqual(await response.json(), { configured: false, messages: [], scope: "observed_only" });
  });
  await withEnvironment("https://indexer.example", async () => { throw new Error("unexpected fetch"); }, async () => {
    const response = await searchRoute.GET(new Request("https://dashboard.example/api/technocore/indexer/search?q=%20"));
    assert.deepEqual(await response.json(), { configured: true, messages: [], scope: "observed_only" });
  });
  await withEnvironment("https://indexer.example", async () => { throw new TypeError("connect failed"); }, async () => {
    const response = await searchRoute.GET(new Request("https://dashboard.example/api/technocore/indexer/search?q=test"));
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { configured: true, messages: [], scope: "observed_only", error: "indexer_unavailable" });
  });
});