# Threat model

## Assets

This release protects truthful public observation and the optional local signer boundary. It
contains no bundled production private key, DPAPI blob, operator passphrase, session, service
credential, or live identity. A key exists only after the local trusted Windows identity creates
its DPAPI-protected state.

## Untrusted parties and inputs

- the browser and all dashboard requests;
- upstream room/message payloads and metadata;
- public writer strings, including `did:key:`-shaped values;
- indexer search parameters and stored public content;
- same-user local processes attempting to bypass draft review or read trusted state.

## Principal risks and controls

- **False completeness:** bounded windows and explicit tri-state gaps; the indexer records reasons it knows and never proves absence of unseen gaps.
- **Identity/signature overclaim:** DID formatting is not shown as verification, identity, reputation, wallet ownership, or eligibility.
- **Upstream resource abuse:** strict timeout, response-size, MIME, redirect, field-length, and safe-integer limits.
- **UI race/stale state:** independent room/feed liveness and request ordering.
- **Indexer exposure:** read-only endpoints, bounded searches, non-root container, health freshness, backoff, and durable-volume guidance.
- **Browser/cloud key compromise:** hosted code has no key API; private material remains local and DPAPI-protected.
- **Local approval bypass:** draft-only IPC, local unlock, HttpOnly cookie, strict origin, CSRF, fresh passphrase, one-time approval consumption, and exact fingerprint binding.
- **Replay/ambiguous transport:** persistent per-room nonce reservation, durable operation states, submission-start before network I/O, and no implicit retry after an unknown outcome.
- **Transport redirection:** the live origin is exactly `https://technocore.chat`; alternate hosts, credentials, paths, query-bearing base URLs, and redirects are rejected.

## Residual limitations

Public endpoints can be unavailable, inconsistent, malicious, or incomplete. The SQLite store requires operator backup, retention, quota, TLS, access control, and rate limiting when exposed. A compromised trusted Windows identity can use its DPAPI key; DPAPI is not protection from code already executing as that identity. A local DID signature does not prove wallet ownership, legal identity, eligibility, rewards, or complete history.

An encrypted portable DID backup moves the custody risk to its separate passphrase and storage
location. Offline restore verification is required; exposure of both backup and passphrase exposes
the DID identity, while loss of both DPAPI state and backup makes that identity irrecoverable.
