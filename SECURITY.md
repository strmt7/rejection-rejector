# Security Policy

Rejection Rejector reads private mailbox data and can send email, so security reports
are handled with priority. This policy tells you which versions are supported, how to
report a vulnerability privately, what happens after you report, and which parts of the
codebase are security-sensitive.

## Supported Versions

Only the latest released version of Rejection Rejector is actively supported with
security updates. Older releases receive no backported fixes.

## Reporting a Vulnerability

Do **not** open a public issue for security vulnerabilities. Report vulnerabilities
privately through GitHub private vulnerability reporting:
[Create a private report](https://github.com/strmt7/rejection-rejector/security/advisories/new).

Include:
- A description of the vulnerability
- Steps to reproduce
- Impact assessment

Useful extra evidence (optional but appreciated):
- The exact binary identity printed by `rr.exe build-info` (source commit and dependency
  hashes), or the Git commit SHA of the tree you built;
- The operating system and version, and whether the workspace was the synthetic demo
  or a real one;
- Redacted diagnostics from `rr.exe diagnostics --out report.json`, reviewed before
  sharing.

Never attach real mailbox content, OAuth client JSON, API bearer tokens, recovery-key
envelopes, passphrases or vault material to a report. Reproduce with the synthetic
`--demo` workspace wherever possible.

## Disclosure Timeline

We will acknowledge receipt of a vulnerability report within 48 hours and aim to provide
a fix or mitigation within 7 days for critical issues. Coordinated vulnerability
disclosure: details are published only after a fix or mitigation is available, normally
within 30 days of the initial report. If a fix needs more time, expect an update rather
than silence. This follows standard coordinated-vulnerability-disclosure practice
(ISO/IEC 29147).

## Scope

Security-sensitive Rejection Rejector areas include:

- Gmail Desktop OAuth PKCE flows, consent, and token handling.
- Authenticated encryption of database payloads (`src/vault.rs`) and recovery-key envelopes.
- The at-most-once delivery state machine (`src/store.rs`).
- The deterministic rejection gate and unattended-send authorization.
- The fail-closed emergency-stop sentinel.
- Enterprise policy SHA-256 pinning and Ed25519 signature verification.
- CI workflows and repository secrets.

Terms used above: **PKCE** (Proof Key for Code Exchange, RFC 7636) binds an OAuth
authorization code to the client that requested it; **authenticated encryption** (AEAD)
encrypts data and also detects tampering; **at-most-once** delivery means a given
rejection message is never sent twice by the application, even across crashes or
ambiguous network outcomes; **Ed25519** (RFC 8032) is the signature algorithm used to
authenticate enterprise policy files. The full security model, trust boundaries and
residual risks are in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

Out of scope (documented residual risks, not vulnerabilities): compromise of the
signed-in OS user account, administrator/root malware, a malicious kernel or drivers,
physical access to the machine, and memory extraction from a running process. See
"Residual risks and explicit non-goals" in the threat model.

## Sources (checked 2026-10-12)

- GitHub Docs, "Privately reporting a security vulnerability":
  https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability
- ISO/IEC 29147 (vulnerability disclosure) and ISO/IEC 29116 (incident handling
  coordination) as referenced practice for the timeline above.
- IETF RFC 7636 (PKCE) and RFC 8032 (Ed25519), cited in the scope glossary.
