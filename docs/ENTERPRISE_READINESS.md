# Enterprise readiness

This document is a release gate, not marketing. A capability is listed as verified only when an automated test, CI workflow, or owner-environment acceptance check supports it.

## Current controls

- Native Rust application; no Electron, Node.js, Python backend, Docker or hosted AI runtime is required by the product.
- Gmail OAuth tokens and mailbox payloads are encrypted locally. Windows Credential Manager/macOS Keychain hold the application master key; no plaintext key fallback exists.
- Local inference is restricted to a literal loopback Ollama origin. Remote/cloud model markers are rejected.
- Human Review is the default and sending is disabled by default.
- Automatic dispatch requires model/digest/context/source/draft identity, complete input, model verification, full reported GPU residency, deterministic current-message rejection evidence, cooldown, rolling send cap and a fresh Gmail conversation preflight. Optional sequential independent verification can use a different pinned local model; policy v3 can require it and restrict verifier tags.
- Ambiguous network delivery is never blindly retried. Delivery enters an Uncertain state and requires reconciliation.
- SQLite uses WAL, FULL synchronization, foreign keys, secure-delete and authenticated encrypted payloads. Database migrations authenticate the existing vault marker before mutating old schemas.
- CI builds/tests Windows and Linux, treats clippy warnings as errors, runs native GUI smoke captures, and checks that validation does not modify tracked source.
- Supply-chain CI runs pinned cargo-audit, cargo-deny and cargo-cyclonedx tooling, produces a CycloneDX 1.5 SBOM artifact, and runs a full-history Gitleaks scan.
- OpenSSF Scorecard runs independently with least-privilege workflow permissions.
- CodeQL scans Rust source, scheduled fuzzing exercises bounded parsers/policy surfaces, and coverage evidence is generated separately from correctness gates.
- Backups are checksum/audit-bound and deeply authenticate encrypted records. Offline restore stages and validates the backup, preserves the previous SQLite/WAL/SHM files, installs a clean image, verifies the result, and rolls back automatically on validation failure.
- Recovery can be exercised non-destructively with an isolated recovery drill that runs the production restore path in a temporary workspace, reopens the result, authenticates every encrypted record/audit-chain head and leaves live state unchanged.
- Shutdown-sensitive operations are explicitly classified. The desktop blocks accidental close during send/automatic-dispatch/backup/recovery-drill work, while the worker requests stop and performs a bounded graceful join; ambiguous provider writes still recover as Uncertain rather than being blindly retried.
- A private runtime-session lease distinguishes clean shutdown from crash/power-loss/forced termination. A stale lease discovered only after acquiring the exclusive workspace lock is audited as a security event and disarms sending/Automatic fail-closed; mailbox synchronization and Human Review can still recover normally.
- The integration contract exposes a SHA-256 fingerprint of the exact served OpenAPI document in capabilities/liveness and every API response header, allowing integrations to detect byte-level contract drift while `/v1` remains the semantic compatibility boundary.
- Enterprise deep verification supplements fast CI with pinned nextest, rustdoc warnings-as-errors, doctests, release-profile compilation and a synthetic create/verify/recovery-drill cycle. Fuzzing, coverage, mutation and deep verification all have path-aware `main` triggers for the subsystems that invalidate their evidence, plus scheduled/manual runs. The release gate requires the latest relevant evidence to be successful, recent and in the release commit's history.
- Portable disaster recovery can export the 256-bit vault key only as an Argon2id-derived, XChaCha20-Poly1305-wrapped recovery envelope bound to the vault UUID. Import authenticates the envelope against the backup before OS credential-store installation and never overwrites an existing credential automatically.
- Optional machine-wide enterprise policy can force Human Review, prohibit sending/API exposure, constrain local models, enforce retention/cooldown/send caps, and require independently protected audit anchoring. Policy v2 has local revision rollback protection; deployments can independently authenticate exact policy bytes with a SHA-256 pin, an Ed25519 detached signature, or both. Rollback evidence can live in an externally managed anchor file or, on Windows/macOS, as a monotonic OS credential-store checkpoint. Invalid or unauthenticated managed policy fails closed.
- The integration API exposes versioned OpenAPI 3.1, canonical readiness, typed worker-operation state, stable policy reason codes, request IDs and stable error envelopes. Bearer credentials use verifier-only persistence: the application stores a domain-separated SHA-256 verifier, migrates legacy recoverable tokens without invalidating clients, and exposes new plaintext credentials only once after creation/rotation. CI asserts every public route is represented by the contract, including metrics, snapshot cursor feeds and per-item Automatic-policy explanations.
- Operational troubleshooting uses a privacy-minimal typed JSONL runtime journal with bounded local rotation. It stores operation/event enums, stable codes and local operation-correlation UUIDs only; arbitrary errors and mailbox/profile/credential fields are structurally absent from the record schema.
- Safety-critical mutation testing is a hard release-quality gate: surviving mutants and timeouts fail the workflow rather than being treated as advisory evidence, and changes to the guarded policy/recovery/mail files trigger it automatically. Coverage is enforced at the measured baseline ratchet of at least 61% lines and 65% functions (baseline commit `555b708d42132d837e8cb291b47a9686f2a7f3b4` measured 61.48% / 65.13%).

## Development and release governance

- Repository-owner development is **main-only**. Multi-file logical changes are applied as one atomic Git tree/commit so `main` is never intentionally left in a half-applied intermediate state.
- Critical Rust CI, public-API SemVer validation and supply-chain/SBOM validation preserve evidence for every `main` commit instead of cancelling predecessor runs merely because a newer commit arrived.
- `cargo-semver-checks` validates the public Rust library surface. The attested Windows release gate requires successful SemVer evidence for the **exact release commit**.
- The attested release gate also requires recent successful Windows byte-for-byte reproducibility evidence in release history, alongside fuzzing, coverage, mutation and enterprise deep-verification evidence.
- Model evaluation has a composition floor, not only a total-case floor: the 72-case synthetic corpus must preserve strong rejection/opportunity/uncertain/benign balance and repeated multilingual, interview, ambiguity, quoted-history, prompt-injection, assessment and ATS coverage.
- Privacy-safe runtime operation durations are retained only in the bounded local runtime journal and exposed as label-free aggregate OpenMetrics; no production availability or latency SLO is implied by those measurements.
- Production Rust library/binary builds deny panic-capable convenience macros (`unwrap`, `expect`, `panic!`, `unreachable!`) outside test builds; impossible-state branches return explicit errors/fail closed instead.
- Deterministic generated invariant tests exercise thousands of enterprise-policy/readiness/anti-rollback state combinations and verify monotonic restrictions, idempotence and fail-closed readiness.
- Binaries expose `contract-info` with exact OpenAPI, enterprise-policy-schema, settings/database, evaluation-suite and prompt-contract identities; release packaging verifies source files against those embedded fingerprints.
- Windows workstations can register the headless worker as a least-privilege per-user Task Scheduler job at logon. The task contract is drift-checked, single-instance, delayed 30 seconds after logon and bounded to three one-minute restart attempts; it deliberately preserves the signed-in user's Credential Manager boundary instead of claiming LocalSystem service semantics.
- Managed deployments can configure an out-of-band emergency-stop sentinel. It blocks manual and Automatic Gmail writes, is rechecked after reservation immediately before provider dispatch, fails closed on malformed configuration, and exposes only privacy-safe state through doctor/health/OpenMetrics.
- Unattended delivery has defense-in-depth rate containment: the configured global rolling daily cap is enforced transactionally, and a non-user-raiseable two-attempt rolling 24-hour ceiling applies per normalized recipient mailbox. The recipient identity is evaluated from the bounded encrypted recent-delivery set rather than persisted in a new plaintext/index field; Human Review is the explicit override path.

## Enterprise gaps still open

1. **Publisher trust:** the release workflow implements optional Azure Artifact Signing/OIDC for both Windows executables and fails unless Authenticode verifies as `Valid`. This closes the workflow path but not deployment acceptance by itself: no signed production artifact is claimed until that configured path has run successfully, and there is still no signed MSIX/MSI/update channel.
2. **Live acceptance:** CI does not authorize a real Gmail account, send a real reply, or certify provider-side behavior.
3. **Physical GPU certification:** Ollama residency is checked, but whole-device transient peaks and every driver/backend combination are not certified.
4. **Independent-verifier acceptance:** the sequential dual-model path is implemented and can be policy-required, but each chosen primary/verifier pair still requires target-GPU and independently labelled private-mailbox acceptance; model diversity reduces but does not eliminate correlated errors.
5. **Accessibility:** AccessKit-backed native controls, explicit Ctrl/Cmd+1–5 navigation, F5 refresh, Esc-safe dialog cancellation and label associations for critical editable fields are implemented. Linux native screenshots/geometry remain automated. Windows Narrator, IME and 100/125/150/200% DPI behavior must still be recorded on the exact release binary using the acceptance protocol in docs/ACCESSIBILITY.md; no accessibility certification is claimed.
6. **Enterprise deployment:** a local administrator policy overlay and least-privilege per-user Windows Task Scheduler worker are implemented, but signed MSI/MSIX/Intune packaging is not. A LocalSystem-style Windows service is intentionally not used because it would change the user Credential Manager trust boundary.
7. **Portable-recovery usability:** the recovery-key cryptographic path is implemented, but GUI-first recovery/import and organization-managed key escrow integrations are not yet implemented.
8. **Security audit:** automated controls exist; no external penetration test or formal security certification is claimed.

## Release policy

A release candidate should not be described as enterprise-ready until, at minimum:

- main CI and supply-chain workflows are green on the exact release commit;
- for fuzzing, coverage, mutation and deep verification, the **latest** main-branch run is successful, recent, and its commit is an ancestor of the exact release commit; a newer failed/cancelled/in-progress run cannot be masked by older green evidence;
- the SBOM, build identity, compatibility-contract identity and SHA-256 evidence correspond to that commit;
- if the artifact is described as publisher-signed, the signed release mode completed and its packaged `signing.json` reports valid signatures for both executables;
- backup/restore has a tested recovery path;
- one controlled Gmail end-to-end acceptance run has been completed;
- the chosen local model has passed the task-specific bake-off on the target GPU and an independently labelled private mailbox sample;
- Windows accessibility/display scaling checks have been recorded;
- remaining limitations are published rather than silently waived.

All development for this repository is performed directly on `main` per repository-owner instruction.
