# Security policy

## Supported surface

Security reports are welcome for the current `main` branch. Please avoid public disclosure until maintainers have had a reasonable opportunity to investigate.

Open a private GitHub security advisory for vulnerabilities. Do not include real private keys, production credentials, personal data, or live exploit traffic in a report.

## Explicit non-goals

The dashboard is an observer. It does not verify upstream signatures, establish identity or reputation, determine FLOP eligibility, store browser/cloud keys, or provide signing. The optional indexer stores hostile public observations and can have coverage gaps.

## Design constraints

- Upstream reads are time-, size-, schema-, and redirect-bounded.
- Public data is treated as untrusted.
- The indexer has no write, signing, or key endpoint.
- Private Windows security-core artifacts are not shipped here.
- Future local-service integration must not treat CORS or localhost as authentication.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full boundary.
