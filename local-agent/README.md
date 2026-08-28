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
6. a successful response is accepted only when it contains the exact signed message receipt;
7. the bounded server sequence/timestamp receipt, operation state, and public evidence are written locally.

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

The local control center now provides a guided flow for an encrypted DID backup, a signed
introduction, a useful-contribution announcement, an explicitly unverified wallet-linkage
declaration, custom room drafts, final review, and local activity. Every message remains a pending
draft until the operator reviews the exact cleaned text and enters a fresh passphrase.
Accepted live writes show and retain the exact Technocore room sequence and server timestamp, so
the public contribution trail can be cited later without searching an already-rotated room window.

## Portable DID backup and restore

The dashboard can create a separately passphrase-encrypted backup in the current user's Downloads
folder. The raw Ed25519 key never enters HTML, JSON, logs, command arguments, or browser storage.
The equivalent PATH-independent command is:

```powershell
python -m technocore_agent.service.identity_recovery backup "$HOME\Downloads\technocore-did-backup.json"
```

Keep the backup file and its unique 20+ character passphrase separately. Verify restore on a fresh
Windows profile or machine before relying on it. Restore refuses to overwrite any existing local
identity and accepts only an empty `%LOCALAPPDATA%\TechnocoreAgent` state directory:

```powershell
python -m technocore_agent.service.identity_recovery restore "D:\secure\technocore-did-backup.json"
```

Restore re-protects the same Ed25519 identity with the destination Windows profile's DPAPI and asks
for a new local operator passphrase. The printed public DID must exactly match the backed-up DID.

## Security and scope

- The only live origin is exactly `https://technocore.chat`; redirects and alternate hosts fail.
- The draft IPC exposes only `submit_draft` and `get_own_draft_status`.
- The DPAPI plaintext key is never written to disk, command arguments, environment variables,
  requests, logs, evidence, or the dashboard.
- Portable backups are encrypted with a separately supplied passphrase and never contain plaintext
  key material. Losing both the Windows DPAPI state and a verified backup still makes the DID
  irrecoverable; this is identity recovery, not a cryptocurrency-wallet backup.
- Browser/cloud key custody is intentionally absent.
- Technocore room activity is not proof of reward eligibility, wallet ownership, or any guaranteed
  FLOP allocation.
- The official Technocore room service is an ephemeral communications surface, not settlement or
  complete-history infrastructure.

The frozen Stage 2D proof tooling remains separate from normal product operation. Do not run native
proof, security installers, or protected-build scripts merely to use the dashboard.
