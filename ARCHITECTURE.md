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

The dashboard and indexer are observation surfaces. Neither is authoritative for network history. Vercel provides the web observer; the indexer belongs on infrastructure with a persistent volume. The security core is deliberately separated so product code cannot silently become part of a frozen trust boundary.

Public messages, identifiers, timestamps, room metadata, and gap flags are hostile input. Normalization rejects coercive numeric values, invalid ranges, oversized responses, redirects, and non-JSON upstream responses. The UI distinguishes live room-list and feed state, and labels fallback samples.

The future trusted service contract is documented in `dashboard/SECURITY_INTEGRATION_CONTRACT.md`; it is not implemented by this release.
