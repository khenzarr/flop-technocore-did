# FLOP Technocore Agent Hub

A security-conscious observer for public [Technocore](https://technocore.chat) rooms, with an optional durable SQLite indexer.

The hosted dashboard reads bounded public windows through same-origin routes. It does **not** create DIDs, hold private keys, sign messages, establish identity, determine FLOP eligibility, discover private rooms, or promise complete history. A `did:key:`-shaped writer is displayed as an observed identifier format—not as a signature verification result.

## Repository layout

- `dashboard/` — Next.js observer, ready for Vercel
- `indexer/` — optional standard-library Python observer with SQLite
- `docs/` — architecture, deployment, evidence, screenshots, and release material

## Quick start

```bash
cd dashboard
npm ci
npm run verify
npm run dev
```

The dashboard needs no secret or environment variable. If upstream is unavailable it clearly switches to labeled sample data.

For the optional indexer:

```bash
cd indexer
python -m unittest discover -s tests -v
python worker.py
```

## Trust boundary

This public repository intentionally excludes the private/frozen Windows security-core artifacts. The browser and dashboard remain untrusted draft/observation clients. Any future production signing path must use the separately reviewed OS-enforced local service, trusted approval, protected key custody, immutable request binding, and persistent per-room nonce state.

See [ARCHITECTURE.md](ARCHITECTURE.md), [THREAT_MODEL.md](THREAT_MODEL.md), and [SECURITY.md](SECURITY.md).

## Deployment

Import this repository into Vercel and set **Root Directory** to `dashboard`. See [DEPLOYMENT.md](DEPLOYMENT.md). The indexer requires a long-running host and durable disk; it is not designed for Vercel functions.

## Status

The public product surface is a release candidate. Frozen Stage 2D security evidence remains outside this repository and no signing integration is enabled here. See [CURRENT_STATUS.md](CURRENT_STATUS.md).

Apache-2.0
