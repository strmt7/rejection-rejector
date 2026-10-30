# Changelog

## Unreleased

Web-console pivot and advisory-suppression elimination (2026-10-30). Changed:

- **The desktop UI is gone**: `src/gui.rs`, `src/gui/`, `src/bin/desktop.rs`,
  the `gui` feature and the `eframe`/`rfd`/`image` dependencies are deleted;
  the product surface is now the `rr` CLI, `rr tui`, and the local web
  console (`rr web`) with its installer component. This also fixes security
  review finding 12 at the source: the unmaintained `zvariant`/`zbus_names`/
  `zvariant_derive` crates entered only through the `eframe` stack
  (`accesskit`→`zbus`), so the dependency graph now carries zero advisories
  (`cargo tree --target all -i zvariant` reports absence; `cargo audit --deny
  warnings` and `cargo deny check advisories` pass with zero ignores).
- **Every advisory suppression is removed** (`deny.toml` ignore array,
  `osv-scanner.toml` `IgnoredVulns` blocks, the `supply-chain.yml`
  `--ignore` flags and their triage comments) per the standing
  never-suppress policy, and `tests/release/test_no_advisory_suppressions.py`
  fails the repository if any suppression construct reappears in a tracked
  policy file. `cargo-audit` bumps to 0.23.1 in the pinned audit lane.
- The redundant `rr-train-monitor`/`src/train_monitor.rs` GUI twin dies; the
  GPU duty-cycle ceiling stays enforced by `training/duty_cycle.py` and
  `tools/gpu_util_watchdog.py` unchanged.
- First-run API credentials are surfaced exactly once by a CLI pre-flight in
  `rr run`/`rr web` (printed like `rr rotate-api-token`), replacing the
  deleted GUI snapshot reveal/hide flow — plaintexts never pass through logs
  or UI state (security review finding 1 remediation follow-through).
- The Windows installer ships two selectable components (command-line tools
  and the local web console); the package verifier requires one signing
  record per packaged executable instead of a hardcoded count.

Findings-policy wave (2026-10-29). Changed:

- Owner policy adopted and enforced: **static-analysis findings are fixed at
  source by complete professional rewrites; suppressions of any kind are
  banned** (no DeepSource ignore rules, no false-positive dispositions, no
  code-scanning dismissals). `docs/deepsource-dispositions.md` is now the
  policy statement with the accepted-open list (CII registration, Scorecard
  Code-Review/Maintained), replacing the former dispositions registry.
- All 15 DeepSource ignore rules were deleted and both manually dismissed
  code-scanning alerts reopened; the previously disposed patterns were
  eliminated at source instead: `String::default()` construction
  (RS-W1079), `Default`/`new` delegation inverted so `default()` is the
  constructor of record (RS-A1008), unit-lambda result normalization
  rewritten as explicit matches/statements (RS-E1015 ×3), explicit
  `drop(...)` lifetime calls rewritten as scopes (RS-E1011 ×5), envelope
  tests assert CRLF-only line breaks explicitly and split with `lines()`
  (RS-W1217), test/doc secret fixtures carry `example-` placeholders
  (SCT-A000), and the local-model probe talks to its endpoint through
  `http.client` with the same https/loopback restriction (BAN-B310).

DeepSource-parity and complexity wave (2026-10-29). Added:

- Ruff parity enforcement: `C901` (every function at McCabe 10 or below —
  DeepSource's threshold), `PIE790` (no stray `pass`) and `S101` (production
  code raises typed errors; asserts allowed only in tests via
  `per-file-ignores`) are now in the enforced rule set.
- `RS-W1079` disposition documented as a contradiction pair with the
  repo-wide `RS-A1008` idiom (`docs/deepsource-dispositions.md`).

Changed:

- `tools/contract/validate_contract.py`: complete class decomposition of the
  5,661-character `validate()` monolith (McCabe 178) into cohesive phase
  methods and per-record helpers; behavior proven unchanged by the three
  documented example outcomes and the 48-test reference suite.
- `tools/check_engineering_policy.py`, `tools/validate_receipt.py`,
  `training/calibrate_zero_fp.py`, `training/mine_enron.py`,
  `training/scale_campaign.py`, `training/train_lora.py`: every hot function
  split into cohesive checks/validators; the whole Python tree is now at
  McCabe 10 or below (ruff C901: zero findings over tools/ training/ tests/).

Fixed:

- Two production asserts and one stray `pass` (the BAN-B101/PTC-W0063
  classes) replaced with explicit typed errors or removed.

Audit and live-verification waves (2026-10-28). Added:

- `rr live-selftest`: operator-invoked self-addressed send-path probe with
  independent `find_sent` verification; fail-closed on demo workspaces,
  missing transport, missing send scope and conversation-bound backends.
- `Worker::wait_for`: one documented bounded-wait helper for test
  synchronization against worker state (replaces nine ad-hoc wall-clock
  polling loops that flaked under build saturation).
- Execution-receipt contract under `tools/contract/` (validator, schemas,
  synthetic examples, 48-test suite, hash-pinned package manifest) and the
  S01 policy record (`engineering.toml`) with its read-only validator.
- Python documentation contract enforced in lint (ruff D): every module,
  class, function, `__init__` and magic method carries a docstring with
  Inputs/Output documentation; 134 docstrings written across the tree.

Fixed:

- SMTP TLS pairing: the app-password send path paired lettre's implicit-TLS
  `relay()` with the STARTTLS submission port, failing every live handshake
  with a TLS-record error. TLS now follows IANA port semantics (465 implicit
  TLS, otherwise STARTTLS) via the tested `smtp_tls_mode()`.
- Load-flaky deadline tests: wall-clock waits sized for expected latency
  rather than scheduler starvation now use a 60s hung-worker guard.
- Python lint scope gaps: `training/` and `tools/` subdirectories were
  unenforced in "All" lint mode (shallow globs); scope is now recursive and
  pinned by test. 13 residual findings fixed at source, including
  `zip(strict=True)` semantics and overlapping except unions.
- Calibration decision boundaries (manual findings N03/N04): observed
  decision boundaries replace the 0.001 grid; invalid rows fail closed with
  line-numbered errors; reported counts reproduce at the reported threshold.

Engineering-contract adoption (common standard S01/S03/S07/S15):

- Adds `engineering.toml`, the S01 policy record (lifecycle, RS/PY profiles,
  supported runtimes, source roots, S03 command vocabulary mapped onto the
  existing native entry points, required test families, released artifact
  kinds, dated exceptions EX-001..EX-003).
- Adds `tools/check_engineering_policy.py`, a read-only S01 validator
  (missing fields, nonexistent paths, expired exceptions, undefined commands,
  required lanes without an execution path) with tests in `tests/release/`.
- Vendors the exact proposed policy/receipt contract under `tools/contract/`
  (reference validator, two JSON Schemas, synthetic examples, own regression
  suite) so execution receipts follow the mandated schemas rather than an
  illustrative shape; every vendored file matches `PACKAGE-MANIFEST.json`.
- Records S07 suppression governance (owner, review date, removal criterion)
  and the DeepSource analyzer capability boundary in
  `docs/deepsource-dispositions.md`; advisory triage gains owner/review fields
  in `SECURITY.md`.
- Documents the verification command map in `CONTRIBUTING.md` and the full
  claim-by-claim verification record in `docs/audit-common-standard.md`.

## 0.3.0

Breaking (0.x minor = breaking by Cargo semver convention; stored settings
keep loading through serde aliases):

- `Tone` is now Professional / Assertive / Hardline (default) / Insane;
  legacy wire names (firm/strong/reconsideration) still deserialize.
- `Settings` gains `reply_language` (Match email / Always English).
- `Command` gains variants for the web surface; the loopback API adds
  authenticated write endpoints (OpenAPI contract updated).

Added: `rr tui` and `rr web` surfaces, the component-selectable Windows
installer, corpus-proven twelve-language reply policy, and the coverage
doctrine (100% lines as a standing goal, never a CI gate).

### Added

- Multilingual reply policy: replies follow the email's first substantive
  language (deterministically detected and verified against the draft; a
  mismatch holds the message). Twelve languages are contractually guaranteed:
  English, Mandarin Chinese, Hindi, Spanish, French, Arabic, Bengali,
  Portuguese, Russian, Urdu, German and Greek; Auto covers all languages.
- Reply-language setting: match the email (default) or always English.
- Four graded reply tones (Professional / Assertive / Hardline / Insane) with
  Hardline as the default; Insane is offensive and borderline profane within
  strict legal limits. Legacy settings wire names still load unchanged.
- Automatic-mode arming gate: a 30-second risk-acknowledgment cooldown with an
  explicit warning modal before unattended sending can be enabled. Human
  review remains the default mode.

### Fixed

- Classification output budget: real recruiting mail needs ~6.5k think tokens
  before schema JSON; the previous 3072 budget failed closed on every real
  email while short fixtures passed. Budgets now scale with the context tier
  (32768 supported) and the email-text budget matches the output envelope.

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
