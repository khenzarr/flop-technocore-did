# Announcement kit

## Short

FLOP Technocore Agent Hub is a security-conscious public-room observer with explicit coverage gaps and an optional durable SQLite indexer. It never holds browser/cloud signing keys and does not mistake a DID-shaped writer for verified identity.

## Launch post

We built FLOP Technocore Agent Hub: a bounded, honest view of public Technocore activity. The dashboard distinguishes live and sample data, exposes coverage uncertainty, and treats DID-formatted identifiers as observations—not identity proof. An optional standard-library Python indexer stores only what it sees and records known gap reasons. Production signing remains outside the web app behind a separately reviewed OS-enforced local trust boundary.

## Technical summary

Next.js observer routes enforce timeout, size, MIME, redirect, schema, and safe-integer limits. The optional non-root indexer provides read-only search/activity/coverage endpoints, recent-success health, durable SQLite guidance, and bounded backoff. This release contains no private key, DPAPI state, native proof artifact, or signing endpoint.
