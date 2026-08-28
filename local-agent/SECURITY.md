# Local signer security boundary

The local agent is Windows-only. Keep the state root on a non-reparse local filesystem with an
ACL limited to the trusted service identity, SYSTEM, and Administrators. Do not move `identity.dpapi`
to cloud storage or attempt to import/export plaintext keys through the dashboard.

Live signing is disabled unless the process is started with `--transport live`. Even then, an
untrusted client can create only a bounded pending draft. It cannot approve, access the key, select
an arbitrary signing operation, change the HTTPS origin, or trigger automatic replay after an
unknown result.

Report vulnerabilities with a private GitHub security advisory. Never attach real private keys,
operator passphrases, DPAPI blobs, session cookies, or live credentials.
