# Security policy

## Supported surface

Security reports are welcome for the current `main` branch. Please avoid public disclosure until maintainers have had a reasonable opportunity to investigate.

Open a private GitHub security advisory for vulnerabilities. Do not include real private keys, production credentials, personal data, or live exploit traffic in a report.

## Explicit non-goals

The hosted dashboard is an observer. It does not verify upstream signatures, establish identity or reputation, determine FLOP eligibility, or store browser/cloud keys. The optional indexer stores hostile public observations and can have coverage gaps. The optional Windows local agent can sign only exact operator-approved room drafts; it does not establish wallet ownership or eligibility.

## Design constraints

- Upstream reads are time-, size-, schema-, and redirect-bounded.
- Public data is treated as untrusted.
- The indexer has no write, signing, or key endpoint.
- Frozen proof transcripts and historical Windows security artifacts are not shipped here.
- The local agent never treats CORS or localhost as authentication: unlock, HttpOnly session, same-origin checks, CSRF, and fresh passphrase confirmation are separate gates.
- Live transport is explicit, redirect-rejecting, response-bounded, and pinned to exactly `https://technocore.chat`.
- Private keys remain DPAPI-protected under the trusted Windows identity and are never exposed by the dashboard or IPC.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full boundary.
