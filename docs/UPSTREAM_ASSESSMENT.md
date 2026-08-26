# Upstream contribution assessment

Keep this repository as a separate product rather than proposing the whole dashboard as a replacement upstream UI.

The upstream repository was rechecked on 2026-08-26. Its queue is unusually crowded (more than one hundred open pull requests), including an existing `first_seq` schema proposal and several overlapping docs/integration changes. Do not open a competing PR now.

The best next move is maintainer-first coordination around one missing, narrow consumer conformance case: demonstrate how a bounded reader distinguishes `first_seq` retention loss, cursor jumps, and an absent/unknown gap field without claiming complete history. Recheck issues, open/closed PRs, and `main` immediately before writing it. Do not submit security-core code, product branding, or the dashboard bundle upstream without prior maintainer agreement.
