# Current status — 2026-08-26

## Project checkpoint

- **Project goal:** a hybrid Technocore/FLOP agent hub whose public observer never inherits signing authority.
- **Current stage:** Stage 2D — OS-enforced Windows security core, plus separately quarantined product surface.
- **Closed/pass:** Stage 1 Recon; Stage 2A Signer; Stage 2B Crypto/Storage/Recovery; Trusted CPython; reviewed source/wheelhouse; V4 Windows install boundary; operator bootstrap; R3R3A2 evidence/manifest/orchestration; M3 R5 source freeze; M3V Windows validation as declared by the authoritative continuation checkpoint.
- **Rejected/superseded:** historical/intermediate security artifacts remain evidence only and are not shipped in this public repository.
- **Current product artifact:** public observer dashboard plus optional read-only SQLite observation indexer.
- **Confirmed tooling/evidence state:** a legacy canonical SHA manifest outside this public repository contains a stale M3V harness hash. It is not used as current proof and is not published here. The current M3V JSON and the authoritative continuation checkpoint remain the recorded closure basis.
- **Single next gate:** independent review and deployment of this public product surface.
- **Forbidden here:** live signing, service start, DPAPI access, native proof execution, ProgramData proof-state mutation, production DID/key creation, or importing frozen security artifacts into the dashboard.

## Verification snapshot

- Dashboard typecheck, lint, 15 behavior tests, and production build: **PASS**.
- Dashboard production dependency audit (`npm audit --omit=dev`): **0 vulnerabilities**.
- Indexer unit tests: **7/7 PASS**.
- Active Python source Ruff and ty checks: **PASS**.
- Broader historical Python suite: **76 passed, 1 skipped, 2 failed** because two old source-text assertions no longer match preserved historical proof scripts. Frozen/historical scripts were not edited to manufacture a pass.
- Optional indexer is observed-only: it reports what the worker reached and cannot prove complete history, identity, eligibility, rewards, or FLOP allocation. No reward or FLOP allocation is guaranteed.

## Frozen evidence hashes (not distributed here)

- M1F: `c5153c40585329bd0ffddca9366c68c5ec9a4053b52ff64571a94391a46d3890`
- M2F: `b31d4c8888619d36cb24a4f64d608154aca900c2565fb2ff7eb556307203805b`
- NativeBridge R2: `0f2e372a296f5a24f1d941c0a050036676be4806643e99afb1fddf6b47b3a1f2`
- M3 R5 module: `bdfd4547f143785013c86d815d29cb58bc83a9232ea71f97d8613f3b4f149f3c`
- M3 R5 checker: `b2b428f355c37569d1551010814f579504225adb854816dc1e37ad27edd059cd`
- M3 R5 review ZIP: `44d0c4916c49009ab52ab90aa27be1dd642d85760bae66a96f733eef895ad7de`
- M3V harness (current file): `b0ccaad3fd27c6fefa80bded7975edea9e1d940826c26a27e0d11c3ccc97ccf9`
- M3V result JSON: `c46122e83e2fb060b52ee3591e340099bb4b7cd04c549e57eeb9f7b93e95a2ee`

M4 was not started in this release pass; finishing the public release and preserving the security boundary took precedence.
