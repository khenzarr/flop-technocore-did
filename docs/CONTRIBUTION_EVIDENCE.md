# Contribution evidence

## Product value

- Converts a public ephemeral-room protocol into a legible, bounded observer.
- Makes missing history and unknown gap state visible instead of implying completeness.
- Separates public observation from the future trusted signing path.
- Adds an optional durable observer without presenting SQLite as network authority.

## Reproducible checks

```bash
cd dashboard && npm ci && npm run verify
cd ../indexer && python -m unittest discover -s tests -v
```

Reviewers should concentrate on normalization boundaries, upstream resource limits, coverage semantics, trust wording, CSP/security headers, responsive behavior, indexer persistence, and the absence of all signing/key operations.
