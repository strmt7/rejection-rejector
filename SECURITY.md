# Security

Sending is disabled by default. Google send scope, app sending permission and Automatic consent are separate. Demo cannot send.

Payloads use XChaCha20-Poly1305 with fresh random nonces and identity-bound associated data. Windows Credential Manager/macOS Keychain hold the master key; Linux uses an explicit strong Argon2-derived passphrase. No plaintext fallback exists. SQLite state/count/time/hash indexes remain clear: this is not SQLCipher/full-file encryption. Windows relies on private profile ACLs; do not use shared directories. Same-user malware, privileged attackers, process memory, clipboard, OS paging and a compromised runtime are outside this protection.

Only Gmail and loopback Ollama are used for mail/inference. Remote/cloud model endpoints and redirects are rejected; local requests ignore environment proxies. Model downloads/installations are explicit. Existing Ollama daemons require their own safe configuration.

Untrusted email receives no tool access. MIME/header/evidence checks and same-model verification reduce but do not eliminate prompt injection or false detections. Recipient/loop/thread guards and permanent pre-send reservations favor holding a reply over duplicates. Uncertain delivery is never blindly retried.

The API is read-only, loopback/token restricted and rejects browser Origin. Its token grants private data access. No portable key recovery/export, signed Windows installer, formal security audit, malware scanning, exactly-once delivery or enterprise compliance certification is claimed. Losing the OS key makes the database unrecoverable.

Never post real emails, OAuth files, tokens or decrypted databases in issues. Revoke exposed credentials and disable sending before investigating.
