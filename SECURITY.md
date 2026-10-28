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

## Known supply-chain advisories (triaged)

The dependency tree carries the following RustSec advisories. None is a
remotely-triggerable code-execution bug in this application's own logic; each is
triaged here with its reachability and remediation so operators can judge the
residual risk.

- **RUSTSEC-2023-0086 — `lexical-core` 0.7.6 (Unsound)** — reached transitively
  via `nom` 5 ← `imap` 2 (the IMAP client). The soundness flaws (`assume_init`
  on uninitialized data, out-of-bounds `BytesIter`) sit in number parsing, so a
  *malicious IMAP server* could in principle trigger undefined behaviour in the
  response parser. The app connects only to a trusted provider (Gmail) or the
  operator's own IMAP host, so practical exposure is low, but the dependency is
  unsound. **Remediation (planned, verified to build):** replace `imap` 2 with
  `io-imap` (Pimalaya), which parses via `nom` 7 + `minimal-lexical` and carries
  no `lexical-core`. `io-imap` compiles with a `nom`-`alloc` feature unification
  (see the migration note); the swap is an in-progress refactor of
  `src/imap_smtp.rs`.
- **RUSTSEC-2026-0370 / -0371 / -0372 — `zvariant` / `zbus_names` /
  `zvariant_derive` (Unmaintained)** — pulled only by the Linux accessibility
  stack (`accesskit`→`zbus`); not compiled into the Windows/MSVC target this
  app ships. No active vulnerability, and the crates are Linux-a11y-only.

Each triage entry above is owned by strmt7 (sole maintainer). Review date:
2026-10-28 (record created); re-review whenever the dependency graph changes
and at the next policy review (2027-04-28). Removal criterion: drop the
ignore when the advisory is fixed in range, the dependency path disappears
(as planned for RUSTSEC-2023-0086 via the `io-imap` migration), or the stated
reachability reasoning stops being true; a bare ignore without a current
reason is itself a defect.

These are accepted-by-triage in `deny.toml` and `tools/local_ci.py` with the
reasons above; re-review whenever the dependency graph changes.

## Sources (checked 2026-10-12)

- GitHub Docs, "Privately reporting a security vulnerability":
  https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability
- ISO/IEC 29147 (vulnerability disclosure) and ISO/IEC 29116 (incident handling
  coordination) as referenced practice for the timeline above.
- IETF RFC 7636 (PKCE) and RFC 8032 (Ed25519), cited in the scope glossary.
