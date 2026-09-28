# Security

Sending is disabled by default. Google send scope, app sending permission and Automatic consent are separate. Demo cannot send.

Payloads use XChaCha20-Poly1305 with fresh random nonces and identity-bound associated data. Windows Credential Manager/macOS Keychain hold the master key; Linux uses an explicit strong Argon2-derived passphrase. No plaintext fallback exists. SQLite state/count/time/hash indexes remain clear: this is not SQLCipher/full-file encryption. Windows relies on private profile ACLs; do not use shared directories. Same-user malware, privileged attackers, process memory, clipboard, OS paging and a compromised runtime are outside this protection.

Only Gmail and loopback Ollama are used for mail/inference. Remote/cloud model endpoints and redirects are rejected; local requests ignore environment proxies. Model downloads/installations are explicit. Existing Ollama daemons require their own safe configuration.

Untrusted email receives no tool access. MIME/header/evidence checks and same-model verification reduce but do not eliminate prompt injection or false detections. Automatic mode additionally requires a deterministic clear-rejection phrase in the current de-quoted message; Human Review does not impose that conservative gate. Recipient/loop/thread guards and durable per-message pre-send records favor holding a reply over duplicates. The same rejection message cannot be sent twice; active/uncertain deliveries temporarily block the whole Gmail thread, while a completed Sent record does not block a later distinct rejection. Uncertain delivery is never blindly retried.

The API is read-only, loopback/token restricted and rejects browser Origin. Its token grants private data access. Portable recovery never exports the raw master key: it uses an Argon2id-derived wrapping key plus XChaCha20-Poly1305, binds the envelope to the vault UUID, validates the recovered key against the backup before credential-store installation, and refuses automatic overwrite of an existing OS credential. Recovery envelopes remain sensitive and must be stored separately from backups with the passphrase protected independently. No signed Windows installer, formal security audit, malware scanning, exactly-once delivery or enterprise compliance certification is claimed.

Never post real emails, OAuth files, tokens or decrypted databases in issues. Revoke exposed credentials and disable sending before investigating.
