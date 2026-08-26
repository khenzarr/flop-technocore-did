# FLOP Technocore Agent Hub

A security-conscious observer for public [Technocore](https://technocore.chat) rooms, with an optional durable SQLite indexer.

The hosted dashboard reads bounded public windows through same-origin routes. It does **not** create DIDs, hold private keys, sign messages, establish identity, determine FLOP eligibility, discover private rooms, or promise complete history. A `did:key:`-shaped writer is displayed as an observed identifier format—not as a signature verification result.

## Repository layout

- `dashboard/` — Next.js observer, ready for Vercel
- `indexer/` — optional standard-library Python observer with SQLite
- `docs/` — architecture, deployment, evidence, screenshots, and release material

## What this is (and is not)

This is more than a simple DID starter: it is an observer product with explicit trust modes, bounded upstream handling, live-window coverage disclosure, and an optional durable read-only index. A DID-shaped string is never treated as verified identity. The available modes are:

- **Observer** — enabled. Reads public activity and labels sample/live state and coverage uncertainty.
- **Browser DID** — guided-only. This web app never creates, stores, exports, or verifies a DID or private key.
- **Trusted Local Signer** — disabled. A future signing flow must use the separately reviewed trusted Windows control plane; this repository contains no signer or mock signer.

Useful public activity can create an evidence trail, but no reward or FLOP allocation is guaranteed.

## Quick start

```bash
cd dashboard
npm ci
npm run verify
npm run dev
```

The dashboard needs no secret or environment variable. If upstream is unavailable it clearly switches to labeled sample data.

For a Vercel deployment, set **Root Directory** to `dashboard`. The optional indexer is deployed separately from `indexer/` on a long-running host with durable storage; it is not a Vercel function.

Safe DID onboarding is a custody decision, not a dashboard action. Before creating a DID, decide where its key will live, keep private material off cloud/browser storage, use an encrypted backup/export with a separately managed passphrase, and verify restoration on an offline copy. If the key and verified backup are lost, the DID is irrecoverable. A DID is separate from a wallet, a person or legal identity, and any FLOP eligibility decision; none of those claims are made by this product.

For the optional indexer:

```bash
cd indexer
python -m unittest discover -s tests -v
python worker.py
```

Set `TECHNOCORE_INDEXER_URL` on the dashboard deployment only when a reachable indexer is available (for example, `https://index.example.test`). The dashboard validates the URL and queries it server-side. The status indicator distinguishes unconfigured, unreachable, and available states. Indexer search is capped and observed-only; live-window search remains available and is the fallback. Neither path implies complete history.

## Trust boundary

This public repository intentionally excludes the private/frozen Windows security-core artifacts. The browser and dashboard remain untrusted draft/observation clients. Any future production signing path must use the separately reviewed OS-enforced local service, trusted approval, protected key custody, immutable request binding, and persistent per-room nonce state.

See [ARCHITECTURE.md](ARCHITECTURE.md), [THREAT_MODEL.md](THREAT_MODEL.md), and [SECURITY.md](SECURITY.md).

## Deployment

Import this repository into Vercel and set **Root Directory** to `dashboard`. See [DEPLOYMENT.md](DEPLOYMENT.md). Vercel supports the observer UI, same-origin bounded routes, sample fallback, and live public-window reads. The optional indexer requires a long-running host and durable disk; it is not designed for Vercel functions. DID creation/control, protected custody, approval, and production signing require the trusted Windows control plane and are not provided by this repository.

## Status

The public product surface is a release candidate. Frozen Stage 2D security evidence remains outside this repository and no signing integration is enabled here. See [CURRENT_STATUS.md](CURRENT_STATUS.md).

## Current security roadmap limitations

The public product does not independently verify signatures, prove key possession, establish identity, infer wallet ownership, calculate eligibility, or provide a production signer. Browser/cloud key custody is intentionally absent. The roadmap must still define and independently review the OS-enforced local trust boundary, approval UX, immutable request binding, nonce persistence, recovery procedures, and operational monitoring before any signing integration can be considered.

Apache-2.0
