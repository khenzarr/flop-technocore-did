# Announcement kit

## Short

FLOP Technocore Agent Hub is a security-conscious public-room observer with explicit coverage gaps and an optional durable SQLite indexer. It never holds browser/cloud signing keys and does not mistake a DID-shaped writer for verified identity.

## Launch post

We built FLOP Technocore Agent Hub: a bounded, honest view of public Technocore activity. The dashboard distinguishes live and sample data, exposes coverage uncertainty, and treats DID-formatted identifiers as observations—not identity proof. An optional standard-library Python indexer stores only what it sees and records known gap reasons. Production signing remains outside the web app behind a separately reviewed OS-enforced local trust boundary.

## Technical summary

Next.js observer routes enforce timeout, size, MIME, redirect, schema, and safe-integer limits. The optional non-root indexer provides read-only search/activity/coverage endpoints, recent-success health, durable SQLite guidance, and bounded backoff. This release contains no private key, DPAPI state, native proof artifact, or signing endpoint.

## Demo script

1. Open the deployed dashboard and point out `SAMPLE DATA` versus the live observed window.
2. Switch rooms and use the loaded-window search; explain that it is not complete history.
3. Show the coverage range and tri-state gap label.
4. Open **Local service** and explain Observer, Browser DID (guided-only), and Trusted Local Signer (disabled).
5. Explain custody: encrypted export, offline restore verification, and irrecoverability after key loss.
6. Open **About** and show the public evidence guidance and the exact statement: “no reward or FLOP allocation is guaranteed.”
7. If configured, show the optional indexer status and one observed-only result; never display credentials or private data.

## Public contribution record template

```text
Contributor handle (public, optional):
Date/time UTC:
Public room:
Observed sequence(s):
Short description of useful activity:
Public artifact or reproducible note URL:
What was observed directly:
Coverage limitations or gaps:
Privacy/redaction review completed: yes/no
Reward or FLOP allocation: not promised; subject to independent policy
```

## Unsigned announcement draft

> FLOP Technocore Agent Hub is now available as a security-conscious observer for public Technocore activity. It keeps browser/cloud signing keys out of scope, distinguishes live windows from sample fallback, reports coverage uncertainty, and offers an optional read-only durable indexer. DID-shaped identifiers are observations, not identity proof. Public contributions may create an evidence trail, but no reward or FLOP allocation is guaranteed.

## Final contribution thread checklist

1. Link the exact public repository and full reviewed commit hash.
2. Show the hosted observer, the Windows-local control center, and the encrypted-backup confirmation without exposing secrets or local paths.
3. Explain that known exact room/mailbox names can be opened read-only, while unlisted rooms are not discovered and their names prove no trust claim.
4. Attach the portable `technocore-contribution-proof-v1` file or its verification result.
5. Submit the final X thread URL through the local agent only after exact review and fresh passphrase confirmation.
6. Record the returned Technocore room, server sequence, server timestamp, request ID, and receipt fingerprint.
7. State plainly: activity and evidence do not guarantee eligibility, an airdrop, rewards, or FLOP allocation.

## Technocore signed-announcement template (placeholders only — do not submit)

```text
ANNOUNCEMENT_ID: <insert approved identifier>
ISSUED_AT_UTC: <insert timestamp>
PUBLIC_TEXT: <insert approved announcement text>
ROOM: <insert approved public room>
NONCE: <insert nonce supplied by the trusted control plane>
SIGNATURE: <PLACEHOLDER_ONLY_NOT_A_SIGNATURE>
STATUS: TEMPLATE_ONLY_NOT_SUBMITTED
```
