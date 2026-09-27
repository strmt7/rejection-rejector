# Changelog

## 0.1.0

Standalone Rust library, native Windows-oriented desktop application and CLI.

- Gmail Desktop OAuth with PKCE/state, explicit readonly/send scopes, incremental history synchronization, cursor-expiry recovery and page-batched insert-only deduplication.
- Local Ollama reasoning with configurable loopback model, `qwen3.5:9b` default, structured classification/drafting/verification, digest pinning and full-pipeline GPU qualification.
- Exact polling presets **1 / 2 / 4 / 8 / 24 hours** and lookback presets **1 / 3 / 7 / 14 / 28 days**; tightening the lookback immediately clears out-of-window actionable content.
- Human Review mode with original/reply side-by-side, edit/save/regenerate/dismiss, stale-revision protection and exact-send confirmation.
- Explicit Automatic mode with enrollment/backlog controls, cooldown, rolling attempt caps, a multilingual affirmative current-rejection gate plus conflict guards, model/draft/context/fingerprint checks and fresh Gmail conversation preflight.
- Encrypted SQLite payloads, Windows Credential Manager key storage, durable at-most-once records per rejection message, thread blocking for active/uncertain delivery, and reconciliation without blind retries.
- Native Overview, Review, Activity, Local AI and Settings screens; Review is disabled in Automatic mode.
- Ollama install/start/download controls plus privacy-safe `rr doctor` and synthetic `rr evaluate` diagnostics.
- Reusable Rust core and optional authenticated read-only loopback integration API for later connection to the separate job-seeker application.
- Synthetic protocol/concurrency/recovery/UI tests, Windows/Linux CI, native GUI capture checks and packaged Windows binaries with source/toolchain/commit/hash evidence.

See setup, model, testing and security documents for limitations and owner-environment acceptance checks.
