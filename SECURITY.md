# Security Policy

## Supported Versions

Only the latest released version of Rejection Rejector is actively supported with security updates.

## Reporting a Vulnerability

Do **not** open a public issue for security vulnerabilities. Report vulnerabilities privately through GitHub private vulnerability reporting:
[Create a private report](https://github.com/strmt7/rejection-rejector/security/advisories/new).

Include:
- A description of the vulnerability
- Steps to reproduce
- Impact assessment

## Disclosure Timeline

We will acknowledge receipt of a vulnerability report within 48 hours and aim to provide a fix or mitigation within 7 days for critical issues. Coordinated vulnerability disclosure: details are published only after a fix or mitigation is available, normally within 30 days of the initial report.

## Scope

Security-sensitive Rejection Rejector areas include:

- Gmail Desktop OAuth PKCE flows, consent, and token handling.
- Authenticated encryption of database payloads (`src/vault.rs`) and recovery-key envelopes.
- The at-most-once delivery state machine (`src/store.rs`).
- The deterministic rejection gate and unattended-send authorization.
- The fail-closed emergency-stop sentinel.
- Enterprise policy SHA-256 pinning and Ed25519 signature verification.
- CI workflows and repository secrets.
