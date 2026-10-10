# Changelog

## Unreleased

### Added
- Three graded reply tones (Professional / Assertive / Hardline) with Hardline
  as the default; legacy settings wire names still load unchanged.
- Automatic-mode arming gate: a 30-second risk-acknowledgment cooldown with an
  explicit warning modal before unattended sending can be enabled. Human
  review remains the default mode.

### Fixed
- Classification output budget: real recruiting mail needs ~6.5k think tokens
  before schema JSON; the previous 3072 budget failed closed on every real
  email while short fixtures passed. Budgets now scale with the context tier
  (32768 supported) and the email-text budget matches the output envelope.

## Unreleased

- Removes the legacy manual Windows-ZIP path from ordinary Rust CI so user-facing packages cannot bypass the attested release gates. Preserves normal Windows/Linux builds, source/debug evidence and manual verification runs.
- Records the original 100-commit incident scope and reproducible audit procedure, prohibits commit-count padding, and aligns testing documentation with actual source-bound release checks.

- Adds a read-only, bounded Windows ZIP verifier with adversarial package tests; validates exact file/checksum coverage, build/contract/source identities and complete recorded release evidence without extracting or executing the package.
- Tightens unsigned release verification to require `NotSigned`; error states cannot be labelled unsigned. Binds both signing records to executable SHA-256 values and requires publisher/timestamp evidence in signed mode.
- Stages only committed docs/scripts, excluding caches and other local artifacts, and verifies the package before attestation and again before upload. Operator-tool tests now run in both Windows and Linux CI.

- Requires successful exact-commit repository integrity before packaging, rejects tracked-source modifications during evidence collection, and invalidates deep evidence after checkout/encoding configuration changes.
- Checks both the fixed pre-corruption API milestone and the immediate parent with all and no Cargo features; persists compatibility logs rather than treating a broken baseline as a passing comparison.

- Diagnostics (`rr diagnostics`, GUI diagnostics export) now derive operational readiness from the live enterprise emergency-stop sentinel (fail-closed) and expose an `emergency_stop` field, matching `rr doctor`, `/v1/health` and the GUI status bar. Previously the report could report dispatch readiness as healthy while an active emergency stop blocked every automatic send.
- Replaced the stale "Version 0.1 exposes a read-only integration API" guard text with a version-neutral statement of the current read-only contract.
- Aligned the mutation-testing workflow trigger paths with the actual `cargo-mutants` examine scope, so a push can no longer imply mutation evidence for modules the campaign deliberately excludes.
- Corrected the evaluation corpus size in the testing documentation from 72 to the shipped 74-case suite.
- Documented `scripts/build-windows.ps1` as the full local verification helper (fmt, all-features tests, clippy, release bins).
- Hardened two test sites that used `Vec::remove(0)` to assert the expected queue length before popping, removing a latent panic on an empty list.

- Offline restore now plants a private reauthorization marker before database replacement. On the next normal startup, previously backed-up Automatic/sending permissions are disarmed durably before the marker is cleared; malformed markers fail closed.

- Cleans up partially copied encrypted restore staging files on I/O failure without touching pre-existing destinations, and removes an abandoned candidate on rename failure.
- Caps desktop recovery passphrases at 4 KiB, matching the CLI safety boundary; oversize input cannot start key derivation or a restore.
- Rejects Windows Task Scheduler autostart registration when rr.exe is in a versioned MSIX-managed path, which otherwise becomes stale after package updates.

- Preserves in-flight operation status when a bounded worker command queue is full or disconnected; prevents queue errors from hiding active Gmail sends or backup operations from the desktop close-safety guard, with queue-state regression tests.

- Revalidates the originally approved backup manifest, staged database checksum, schema and audit head throughout offline restore, and rejects symlinked backup databases. Adds anti-swap and symlink regression tests.

- Adds guarded desktop export and offline verification for passphrase-wrapped disaster-recovery keys, plus a pre-open native Recovery Mode that authenticates and exercises the backup/key pair in isolation before restoring a fresh/locked workspace; passphrases remain zeroizing and key-file creation is atomic/no-clobber. Recovery runs off the UI thread, remains intentionally non-cancellable once started, and blocks window close until the transactional operation finishes.
- Enforces Ollama 0.35.1 capability metadata so decision-only models cannot enter the production chat pipeline and general completion models cannot enter the typed-decision lane.
- Adds Clef Flash 9B Q8 to the non-sending decision-model bake-off and Gemma 4 12B Q4 as a higher-headroom generative challenger.
- Adds explicit Windows application-manifest verification for as-invoker startup, Per-Monitor V2 DPI awareness, UTF-8 code page and long-path opt-in.
- Extends unattended-send conflict guards with Dutch and Greek interview/offer/non-final-decision language and additional explicit-rejection phrases.
- Expands the synthetic model-evaluation corpus from 72 to 74 cases with Dutch and Greek mixed-role critical negatives that combine one rejection with an interview invitation for another role; the suite hash changes deliberately so prior task qualification cannot mask the stronger evaluation contract. The deterministic Dutch opportunity guard includes conversational interview invitations so mixed-role mails fail closed.
- Binds the outbound `X-Rejection-Rejector` loop-prevention header to the compiled package version instead of a stale hard-coded 0.1.0 value.

## 0.2.0

Enterprise AI-verification hardening.

- Adds opt-in sequential independent verification with a separately pinned local model while keeping one model intentionally GPU-resident at a time.
- Adds Granite 4.2 8B Q8 as the default verifier candidate plus smaller verifier choices.
- Persists verifier provenance on each analysis and binds verifier enablement/tag/digest into task qualification.
- Adds enterprise policy v3 controls to require independent verification and restrict verifier tags.
- Migrates encrypted settings format v1 to v2 fail-closed, invalidating prior task qualification and unattended delivery.
- Bumps the pre-1.0 Rust library version because public configuration/policy/status/analysis structs gain verifier fields.


## 0.1.0

Standalone Rust library, native Windows-oriented desktop application and CLI.

- Gmail Desktop OAuth with PKCE/state, explicit readonly/send scopes, incremental history synchronization, cursor-expiry recovery and page-batched insert-only deduplication.
- Local Ollama reasoning with configurable loopback model, quality-first `qwen3.5:9b-q8_0` default, structured classification/drafting/verification, digest pinning and full-pipeline GPU qualification.
- Exact polling presets **1 / 2 / 4 / 8 / 24 hours** and lookback presets **1 / 3 / 7 / 14 / 28 days**; tightening the lookback immediately clears out-of-window actionable content.
- Human Review mode with original/reply side-by-side, edit/save/regenerate/dismiss, stale-revision protection and exact-send confirmation.
- Explicit Automatic mode with enrollment/backlog controls, cooldown, rolling attempt caps, a multilingual affirmative current-rejection gate plus conflict guards, model/draft/context/fingerprint checks and fresh Gmail conversation preflight.
- Encrypted SQLite payloads, Windows Credential Manager key storage, durable at-most-once records per rejection message, thread blocking for active/uncertain delivery, and reconciliation without blind retries.
- Native Overview, Review, Activity, Local AI and Settings screens; Review is disabled in Automatic mode.
- Ollama install/start/download controls plus privacy-safe `rr doctor` and synthetic `rr evaluate` diagnostics.
- Reusable Rust core and optional authenticated read-only loopback integration API for later connection to the separate job-seeker application.
- Synthetic protocol/concurrency/recovery/UI tests, Windows/Linux CI, native GUI capture checks and packaged Windows binaries with source/toolchain/commit/hash evidence.

See setup, model, testing and security documents for limitations and owner-environment acceptance checks.
