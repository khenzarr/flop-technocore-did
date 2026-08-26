# Threat model

## Assets

This release protects availability and truthful presentation of public observations. It contains no production private key, signing authority, DPAPI state, service credential, or canonical Windows proof state.

## Untrusted parties and inputs

- the browser and all dashboard requests;
- upstream room/message payloads and metadata;
- public writer strings, including `did:key:`-shaped values;
- indexer search parameters and stored public content;
- same-user local processes in any future desktop integration.

## Principal risks and controls

- **False completeness:** bounded windows and explicit tri-state gaps; the indexer records reasons it knows and never proves absence of unseen gaps.
- **Identity/signature overclaim:** DID formatting is not shown as verification, identity, reputation, wallet ownership, or eligibility.
- **Upstream resource abuse:** strict timeout, response-size, MIME, redirect, field-length, and safe-integer limits.
- **UI race/stale state:** independent room/feed liveness and request ordering.
- **Indexer exposure:** read-only endpoints, bounded searches, non-root container, health freshness, backoff, and durable-volume guidance.
- **Browser signing compromise:** production key generation, storage, approval, nonce control, and signing are absent.

## Residual limitations

Public endpoints can be unavailable, inconsistent, malicious, or incomplete. The SQLite store requires operator backup, retention, quota, TLS, access control, and rate limiting when exposed. CSP and origin policy reduce browser risk but do not authenticate arbitrary local code.
