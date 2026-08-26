# Contributing

Keep changes small, reviewable, and honest about trust.

1. Create a focused branch.
2. For dashboard changes, run `npm ci` and `npm run verify` in `dashboard/`.
3. For indexer changes, run `python -m unittest discover -s tests -v` in `indexer/`.
4. Explain any trust-boundary, schema, persistence, or coverage effect in the pull request.

Do not add private keys, production tokens, ProgramData state, frozen Windows proof artifacts, build caches, binary review bundles, or a signing shortcut. Do not describe observed DID formatting as verified identity. Security-core integration requires a separate explicit design/review gate.
