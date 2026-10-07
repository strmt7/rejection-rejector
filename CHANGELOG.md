# Changelog

## Unreleased

- Adds guarded desktop export and offline verification for passphrase-wrapped disaster-recovery keys, plus a pre-open native Recovery Mode that authenticates and exercises the backup/key pair in isolation before restoring a fresh/locked workspace; passphrases remain zeroizing and key-file creation is atomic/no-clobber. Recovery runs off the UI thread, remains intentionally non-cancellable once started, and blocks window close until the transactional operation finishes.
- Enforces Ollama 0.35.1 capability metadata so decision-only models cannot enter the production chat pipeline and general completion models cannot enter the typed-decision lane.
- Adds Clef Flash 9B Q8 to the non-sending decision-model bake-off and Gemma 4 12B Q4 as a higher-headroom generative challenger.
- Adds explicit Windows application-manifest verification for as-invoker startup, Per-Monitor V2 DPI awareness, UTF-8 code page and long-path opt-in.
- Extends unattended-send conflict guards with Dutch and Greek interview/offer/non-final-decision language and additional explicit-rejection phrases.
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
