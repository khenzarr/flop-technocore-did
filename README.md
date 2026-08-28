# FLOP Technocore Agent Hub

A hybrid Technocore/FLOP hub: a public room observer, an optional durable SQLite indexer, and an
optional Windows-local, operator-approved DID signer.

The hosted dashboard remains observation-only. DID creation and signing exist only in the separate
`local-agent/` process: the Ed25519 key is protected by Windows DPAPI, never enters the browser or
cloud deployment, and every live write requires an exact local operator approval. Neither surface
establishes identity, determines FLOP eligibility, discovers private rooms, or promises complete
history. A `did:key:`-shaped writer is still an observed identifier—not a verification result.

## Repository layout

- `dashboard/` — Next.js observer, ready for Vercel
- `indexer/` — optional standard-library Python observer with SQLite
- `local-agent/` — optional Windows-local DPAPI DID signer and approval dashboard
- `docs/` — architecture, deployment, evidence, screenshots, and release material

## What this is (and is not)

This is more than a simple DID starter: it is an observer product with explicit trust modes, bounded upstream handling, live-window coverage disclosure, and an optional durable read-only index. A DID-shaped string is never treated as verified identity. The available modes are:

- **Observer** — enabled. Reads public activity and labels sample/live state and coverage uncertainty.
- **Browser DID** — intentionally absent. The hosted web app never creates, stores, exports, or verifies a DID or private key.
- **Trusted Local Signer** — available as an optional Windows-only companion. It defaults to offline mode; live mode uses only the official signed room lane and requires fresh local approval.

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

Safe DID onboarding is a custody decision, not a hosted-dashboard action. The optional local agent
keeps private material off cloud/browser storage and supports a separately passphrase-encrypted
portable backup with fail-closed restore into an empty local state. Loss of both the Windows DPAPI
state and a verified backup makes the DID irrecoverable. A DID backup is not a wallet backup.
A DID is separate from a wallet, a person or legal identity, and any FLOP eligibility decision;
none of those claims are made by this product.

For the optional Windows local signer:

```powershell
cd local-agent
python -m pip install .
python -m technocore_agent.service.local_init
python -m technocore_agent.service.entrypoint --transport offline
```

The initializer prints the public DID and keeps the private key DPAPI-protected under the current
Windows identity. Read [`local-agent/README.md`](local-agent/README.md) before first use. `offline` is the default.
The loopback control center includes encrypted backup, introduction, contribution, unverified
wallet-linkage, custom draft, exact review, and activity flows. It never exposes the private key.
Selecting `--transport live` is explicit and sends only operator-approved signed room drafts to
the canonical `https://technocore.chat` origin. The private key is never returned by an API.

For the optional indexer:

```bash
cd indexer
python -m unittest discover -s tests -v
python worker.py
```

Set `TECHNOCORE_INDEXER_URL` on the dashboard deployment only when a reachable indexer is available (for example, `https://index.example.test`). The dashboard validates the URL and queries it server-side. The status indicator distinguishes unconfigured, unreachable, and available states. Indexer search is capped and observed-only; live-window search remains available and is the fallback. Neither path implies complete history.

## Trust boundary

The browser and hosted dashboard remain untrusted observation clients. The published local-agent
source implements the narrow product surface—DPAPI custody, immutable draft approval, nonce state,
evidence, and canonical transport—while bulky frozen proof transcripts and historical security
artifacts remain excluded. The hosted dashboard never gains signer authority.

See [ARCHITECTURE.md](ARCHITECTURE.md), [THREAT_MODEL.md](THREAT_MODEL.md), and [SECURITY.md](SECURITY.md).

## Deployment

Import this repository into Vercel and set **Root Directory** to `dashboard`. See [DEPLOYMENT.md](DEPLOYMENT.md). Vercel supports only the observer UI, same-origin bounded routes, sample fallback, and live public-window reads. The optional indexer requires a long-running host and durable disk. The `local-agent/` is Windows-local software and must never be deployed to Vercel or another shared cloud runtime.

## Status

Observer, indexer, and local-agent source are ready for independent release review. Live signing is
not automatically enabled and no production DID/key is committed or bundled. See
[CURRENT_STATUS.md](CURRENT_STATUS.md).

## Current security roadmap limitations

The public product does not independently verify upstream signatures, establish a legal/person
identity, infer wallet ownership, calculate eligibility, or guarantee rewards. Browser/cloud key
custody is intentionally absent. The local signer proves only that its local DID key signed an
operator-approved room message; it does not prove wallet ownership or FLOP eligibility.

Apache-2.0
