# Technocore Agent — trusted local DID signer

This Windows-local agent keeps its Ed25519 private key inside the trusted service account and
stores it only as a Windows DPAPI blob. The browser dashboard shows the public `did:key` but never
receives, creates, exports, or signs with the private key.

Every signed room write follows the same path:

1. an untrusted client submits a bounded draft;
2. the local dashboard shows the exact cleaned room and text;
3. the operator unlocks locally and confirms the exact draft with a fresh passphrase;
4. the trusted signer reserves a durable nonce and signs `room|nonce|text`;
5. only explicit `live` mode can submit the signed JSON to `https://technocore.chat`;
6. the operation state and public evidence are written locally.

`offline` is the default and makes no live network write. `live` is never selected implicitly.
An unknown network result is not retried automatically; reconciliation is read-only and cannot
claim rejection merely because a message was not observed.

## Quick start for one Windows user

```powershell
python -m pip install .
python -m technocore_agent.service.local_init
python -m technocore_agent.service.entrypoint --transport offline
```

The initializer accepts only `%LOCALAPPDATA%\TechnocoreAgent`, removes inherited ACLs, grants the
current Windows SID plus SYSTEM and Administrators, stores only a scrypt operator verifier, creates
the Ed25519 key inside the process, and writes only its DPAPI-protected form. It prints the public
DID. Re-running it returns the same DID and does not ask for a new passphrase.

Open `http://127.0.0.1:47832`. When you are ready to permit operator-approved official room writes,
stop the offline process and explicitly run:

```powershell
python -m technocore_agent.service.entrypoint --transport live
```

## Existing trusted Windows installation

The Stage 2D installer uses the canonical protected state root:

```text
C:\ProgramData\TechnocoreAgent-Stage2D-Test
```

Initialize the operator credential once from an elevated console. This command does not expose or
accept a DID private key:

```powershell
python -m technocore_agent.service.operator_init --state-root C:\ProgramData\TechnocoreAgent-Stage2D-Test
```

Run locally in safe offline mode:

```powershell
python -m technocore_agent.service.entrypoint --state C:\ProgramData\TechnocoreAgent-Stage2D-Test --dashboard-port 47832 --transport offline
```

After reviewing the public DID and preparing a draft, explicitly enable the official signed lane:

```powershell
python -m technocore_agent.service.entrypoint --state C:\ProgramData\TechnocoreAgent-Stage2D-Test --dashboard-port 47832 --transport live
```

Open `http://127.0.0.1:47832`. The server binds only to loopback. Live approval requires the local
session cookie, same-origin POST, CSRF token, and fresh operator passphrase. A model or draft client
cannot approve, read the key, choose another network origin, or invoke a generic signer.

## Security and scope

- The only live origin is exactly `https://technocore.chat`; redirects and alternate hosts fail.
- The draft IPC exposes only `submit_draft` and `get_own_draft_status`.
- The DPAPI plaintext key is never written to disk, command arguments, environment variables,
  requests, logs, evidence, or the dashboard.
- This release has no automatic key export/restore command. Loss of the Windows profile or DPAPI
  state can make the DID irrecoverable; do not treat this as a wallet backup system.
- Browser/cloud key custody is intentionally absent.
- Technocore room activity is not proof of reward eligibility, wallet ownership, or any guaranteed
  FLOP allocation.
- The official Technocore room service is an ephemeral communications surface, not settlement or
  complete-history infrastructure.

The frozen Stage 2D proof tooling remains separate from normal product operation. Do not run native
proof, security installers, or protected-build scripts merely to use the dashboard.
