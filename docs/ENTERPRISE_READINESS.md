# Enterprise readiness

This document is a release gate, not marketing. A capability is listed as verified only when an automated test, CI workflow, or owner-environment acceptance check supports it.

## Current controls

- Native Rust application; no Electron, Node.js, Python backend, Docker or hosted AI runtime is required by the product.
- Gmail OAuth tokens and mailbox payloads are encrypted locally. Windows Credential Manager/macOS Keychain hold the application master key; no plaintext key fallback exists.
- Local inference is restricted to a literal loopback Ollama origin. Remote/cloud model markers are rejected.
- Human Review is the default and sending is disabled by default.
- Automatic dispatch requires model/digest/context/source/draft identity, complete input, model verification, full reported GPU residency, deterministic current-message rejection evidence, cooldown, rolling send cap and a fresh Gmail conversation preflight.
- Ambiguous network delivery is never blindly retried. Delivery enters an Uncertain state and requires reconciliation.
- SQLite uses WAL, FULL synchronization, foreign keys, secure-delete and authenticated encrypted payloads. Database migrations authenticate the existing vault marker before mutating old schemas.
- CI builds/tests Windows and Linux, treats clippy warnings as errors, runs native GUI smoke captures, and checks that validation does not modify tracked source.
- Supply-chain CI runs pinned cargo-audit, cargo-deny and cargo-cyclonedx tooling, produces a CycloneDX 1.5 SBOM artifact, and runs a full-history Gitleaks scan.
- OpenSSF Scorecard runs independently with least-privilege workflow permissions.

## Enterprise gaps still open

1. **Backup and recovery:** no tested same-vault database backup/verification command yet.
2. **Portable disaster recovery:** encrypted database backups cannot be decrypted on another machine without the original OS-protected master key. No key export is implemented.
3. **Publisher trust:** Windows binaries are not Authenticode-signed and there is no signed installer/update channel.
4. **Live acceptance:** CI does not authorize a real Gmail account, send a real reply, or certify provider-side behavior.
5. **Physical GPU certification:** Ollama residency is checked, but whole-device transient peaks and every driver/backend combination are not certified.
6. **Independent AI verifier:** drafting and verification currently use the same local model; deterministic Rust gates compensate for correlated model errors but do not make the verifier independent.
7. **Accessibility:** Linux native screenshots and geometry checks exist, but Windows Narrator, keyboard-only navigation, IME and 100/125/150/200% DPI acceptance remain owner-environment work.
8. **Enterprise deployment:** MSI/MSIX/Intune packaging, Windows service operation and centrally managed policy are not implemented.
9. **Security audit:** automated controls exist; no external penetration test or formal security certification is claimed.

## Release policy

A release candidate should not be described as enterprise-ready until, at minimum:

- main CI and supply-chain workflows are green on the exact release commit;
- the SBOM and SHA-256 evidence correspond to that commit;
- backup/restore has a tested recovery path;
- one controlled Gmail end-to-end acceptance run has been completed;
- the chosen local model has passed the task-specific bake-off on the target GPU and an independently labelled private mailbox sample;
- Windows accessibility/display scaling checks have been recorded;
- remaining limitations are published rather than silently waived.

All development for this repository is performed directly on `main` per repository-owner instruction.
