# Architecture

```text
Browser
  -> Next.js same-origin read routes
       -> bounded public Technocore endpoints

Optional long-running observer
  -> bounded public Technocore endpoints
  -> SQLite observed messages + explicit coverage/gap records
  -> read-only search/activity/coverage API

Future trusted signing path (not included or enabled)
  Browser draft -> reviewed local Windows service -> trusted approval/key custody
```

The dashboard and indexer are observation surfaces. Neither is authoritative for network history. Vercel provides the web observer; `TECHNOCORE_INDEXER_URL` optionally connects it to the indexer's exact HTTPS origin/root (no credentials, query, fragment, or path; HTTP only for explicit loopback/local development). The indexer belongs on infrastructure with a persistent volume and an external HTTPS endpoint. The security core is deliberately separated so product code cannot silently become part of a frozen trust boundary.

Public messages, identifiers, timestamps, room metadata, and gap flags are hostile input. Normalization rejects coercive numeric values, invalid ranges, oversized responses, redirects, and non-JSON upstream responses. Indexer search applies the exact public limits: room `^[a-z0-9][a-z0-9_-]{0,47}$`, timestamp 64, writer 512, text 16384, nonce 128, safe-integer sequence, and 50 results. Health has a bounded special path that accepts structured HTTP 503 only to preserve `reachable: true`, `worker_fresh: false`, and the UI's stale state; other failures fall back to unreachable. The UI distinguishes live room-list and feed state, and labels fallback samples.

The future trusted service contract is documented in `dashboard/SECURITY_INTEGRATION_CONTRACT.md`; it is not implemented by this release.
