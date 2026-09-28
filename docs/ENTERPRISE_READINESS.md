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
- CodeQL scans Rust source, scheduled fuzzing exercises bounded parsers/policy surfaces, and coverage evidence is generated separately from correctness gates.
- Backups are checksum/audit-bound and deeply authenticate encrypted records. Offline restore stages and validates the backup, preserves the previous SQLite/WAL/SHM files, installs a clean image, verifies the result, and rolls back automatically on validation failure.
- Recovery can be exercised non-destructively with an isolated recovery drill that runs the production restore path in a temporary workspace, reopens the result, authenticates every encrypted record/audit-chain head and leaves live state unchanged.
- Shutdown-sensitive operations are explicitly classified. The desktop blocks accidental close during send/automatic-dispatch/backup/recovery-drill work, while the worker requests stop and performs a bounded graceful join; ambiguous provider writes still recover as Uncertain rather than being blindly retried.
- The integration contract exposes a SHA-256 fingerprint of the exact served OpenAPI document in capabilities/liveness and every API response header, allowing integrations to detect byte-level contract drift while `/v1` remains the semantic compatibility boundary.
- Enterprise deep verification supplements fast CI with pinned nextest, rustdoc warnings-as-errors, doctests, release-profile compilation and a synthetic create/verify/recovery-drill cycle. Fuzzing, coverage, mutation and deep verification all have path-aware `main` triggers for the subsystems that invalidate their evidence, plus scheduled/manual runs. The release gate requires the latest relevant evidence to be successful, recent and in the release commit's history.
- Portable disaster recovery can export the 256-bit vault key only as an Argon2id-derived, XChaCha20-Poly1305-wrapped recovery envelope bound to the vault UUID. Import authenticates the envelope against the backup before OS credential-store installation and never overwrites an existing credential automatically.
- Optional machine-wide enterprise policy can force Human Review, prohibit sending/API exposure, constrain local models, enforce retention/cooldown/send caps, and require independently protected audit anchoring. Policy v2 has local revision rollback protection; deployments can independently authenticate exact policy bytes with a SHA-256 pin, an Ed25519 detached signature, or both. Rollback evidence can live in an externally managed anchor file or, on Windows/macOS, as a monotonic OS credential-store checkpoint. Invalid or unauthenticated managed policy fails closed.
- The integration API exposes versioned OpenAPI 3.1, canonical readiness, typed worker-operation state, stable policy reason codes, request IDs and stable error envelopes. CI asserts every public route is represented by the contract, including metrics, snapshot cursor feeds and per-item Automatic-policy explanations.
- Operational troubleshooting uses a privacy-minimal typed JSONL runtime journal with bounded local rotation. It stores operation/event enums, stable codes and local operation-correlation UUIDs only; arbitrary errors and mailbox/profile/credential fields are structurally absent from the record schema.
- Safety-critical mutation testing is a hard release-quality gate: surviving mutants and timeouts fail the workflow rather than being treated as advisory evidence, and changes to the guarded policy/recovery/mail files trigger it automatically. Coverage is enforced at the measured baseline ratchet of at least 61% lines and 65% functions (baseline commit `555b708d42132d837e8cb291b47a9686f2a7f3b4` measured 61.48% / 65.13%).

## Enterprise gaps still open

1. **Publisher trust:** release ZIPs can be provenance/SBOM-attested and shipped binaries can embed dependency provenance, but Windows binaries are not Authenticode-signed and there is no signed MSIX/MSI/update channel.
2. **Live acceptance:** CI does not authorize a real Gmail account, send a real reply, or certify provider-side behavior.
3. **Physical GPU certification:** Ollama residency is checked, but whole-device transient peaks and every driver/backend combination are not certified.
4. **Independent AI verifier:** drafting and verification currently use the same local model; deterministic Rust gates compensate for correlated model errors but do not make the verifier independent.
5. **Accessibility:** Linux native screenshots and geometry checks exist, but Windows Narrator, keyboard-only navigation, IME and 100/125/150/200% DPI acceptance remain owner-environment work.
6. **Enterprise deployment:** a local administrator policy overlay exists, but signed MSI/MSIX/Intune packaging and Windows-service operation are not implemented.
7. **Portable-recovery usability:** the recovery-key cryptographic path is implemented, but GUI-first recovery/import and organization-managed key escrow integrations are not yet implemented.
8. **Security audit:** automated controls exist; no external penetration test or formal security certification is claimed.

## Release policy

A release candidate should not be described as enterprise-ready until, at minimum:

- main CI and supply-chain workflows are green on the exact release commit;
- for fuzzing, coverage, mutation and deep verification, the **latest** main-branch run is successful, recent, and its commit is an ancestor of the exact release commit; a newer failed/cancelled/in-progress run cannot be masked by older green evidence;
- the SBOM and SHA-256 evidence correspond to that commit;
- backup/restore has a tested recovery path;
- one controlled Gmail end-to-end acceptance run has been completed;
- the chosen local model has passed the task-specific bake-off on the target GPU and an independently labelled private mailbox sample;
- Windows accessibility/display scaling checks have been recorded;
- remaining limitations are published rather than silently waived.

All development for this repository is performed directly on `main` per repository-owner instruction.
