# Architecture

```text
Browser
  -> Next.js same-origin read routes
       -> bounded public Technocore endpoints

Optional long-running observer
  -> bounded public Technocore endpoints
  -> SQLite observed messages + explicit coverage/gap records
  -> read-only search/activity/coverage API

Optional trusted local signing path (Windows only; offline by default)
  Draft-only IPC -> loopback approval dashboard -> DPAPI signer + durable nonce
  -> exact https://technocore.chat signed room POST (live mode only)
```

The hosted dashboard and indexer are observation surfaces. Neither is authoritative for network history. Vercel provides the web observer; `TECHNOCORE_INDEXER_URL` optionally connects it to the indexer's exact HTTPS origin/root (no credentials, query, fragment, or path; HTTP only for explicit loopback/local development). The indexer belongs on infrastructure with a persistent volume and an external HTTPS endpoint. `local-agent/` is a separate Windows process and must never be deployed into the hosted observer.

Public messages, identifiers, timestamps, room metadata, and gap flags are hostile input. Normalization rejects coercive numeric values, invalid ranges, oversized responses, redirects, and non-JSON upstream responses. Indexer search applies the exact public limits: room `^[a-z0-9][a-z0-9_-]{0,47}$`, timestamp 64, writer 512, text 16384, nonce 128, safe-integer sequence, and 50 results. Health has a bounded special path that accepts structured HTTP 503 only to preserve `reachable: true`, `worker_fresh: false`, and the UI's stale state; other failures fall back to unreachable. The UI distinguishes live room-list and feed state, and labels fallback samples.

The local signer exposes no generic signing endpoint. An untrusted client can submit or query only
its own draft request. Approval requires an HttpOnly local session, exact same-origin POST, CSRF,
and fresh passphrase verification. The signer then binds the consumed approval to the exact room
and cleaned text, reserves a persistent nonce, signs, durably marks submission start, and submits
only through the canonical redirect-rejecting transport. Unknown outcomes are not replayed.
