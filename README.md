# Rejection Rejector

**Your voice, returned.** A standalone native Rust desktop application for detecting job-application rejections, generating assertive responses with a local Ollama model, and reviewing or automatically sending eligible replies.

> Early release. Sending starts **disabled** and **Human review** is the default. No real emails or credentials are bundled. Validate the model on your own mailbox before enabling Automatic.

## Implemented

| Component | Version 0.1 |
|---|---|
| Desktop | Native Rust egui/eframe: Overview, Review, Activity, Local AI, Settings |
| Mail | Gmail Desktop OAuth, system browser, PKCE, explicit read/send consent |
| AI | Local Ollama classification, drafting and a separate same-model audit; structured outputs and exact evidence checks |
| Model | `qwen3.5:9b-q8_0` provisional default; Granite 4.2 8B Q8, Gemma 4 12B Q8, Ministral 3 14B and other curated challengers can be compared locally on the full task pipeline |
| GPU target | 16 GiB; conservative 14 GiB reported-residency budget, not physical peak certification |
| Check interval | **1 / 2 / 4 / 8 / 24 hours** |
| Email age window | **1 / 3 / 7 / 14 / 28 days** |
| Sync | Durable incremental Gmail history queue; page-batched insert of missing identities only; cursor-expiry recovery |
| Database | Embedded SQLite with authenticated encrypted payloads; Windows Credential Manager holds the key |
| Review | Original and editable reply side by side; save, regenerate, dismiss, confirm exact reply and send |
| Automatic | Explicit authorization, cooldown, send-attempt cap, independent clear-current-rejection gate, source/draft/model checks and fresh conversation preflight |
| Mode-aware UI | Review tab is disabled in Automatic mode |
| Recovery | Durable at-most-once delivery records, checksum/audit-bound encrypted backups, offline transactional restore, and separate Argon2id/XChaCha20-Poly1305 wrapped recovery-key envelopes for portable disaster recovery |
| Integration | Reusable Rust library plus authenticated read-only loopback API with versioned OpenAPI, exact contract SHA-256 fingerprint, typed operation status, stable error codes and request IDs |
| Enterprise control | Optional machine policy with revision rollback protection, model/retention/send constraints, independently protected audit-anchor enforcement, SHA-256 pinning and detached Ed25519 signature verification |
| Testing | Windows/Linux CI plus scheduled nextest/rustdoc/recovery drills, fuzzing, mutation testing, CodeQL, coverage evidence and task-specific model fixtures |
| Operations | Privacy-minimal typed JSONL runtime journal with bounded local rotation; stable operation/event codes only, separate from encrypted semantic audit records |

## Windows

Development CI compiles and tests the Windows desktop/CLI on every `main` commit, but **does not publish a user-facing Windows package on normal pushes**. Packaging is intentionally gated behind an explicit manual workflow input and should remain unused until a release build is requested. When packaging is later enabled, the ZIP will include the desktop binary, `rr.exe`, documentation and exact build-commit/hash evidence.

Windows prerequisite: install Microsoft's latest **Visual C++ v14 Redistributable (x64)** if it is missing. Do not download individual DLLs. See [Windows runtime setup](docs/WINDOWS-RUNTIME.md).

Safe offline preview:

```powershell
.\rejection-rejector.exe --demo
```

After configuring the real workspace, run the non-sensitive readiness check with the GUI closed. The app requires Ollama 0.34.4 or newer so the current single-pass structured-output behavior for thinking models is part of the supported runtime contract:

```powershell
.\rr.exe doctor
```

It reports local Gmail permission/configuration state, the Ollama runtime version, model pin/install state and current GPU-residency status without printing message bodies or credentials. To compare curated models that you explicitly installed, run `rr compare-models --out model-bakeoff.json` or use **Compare installed candidates** in Local AI.

Real setup: [docs/SETUP.md](docs/SETUP.md). Configure your own Gmail OAuth Desktop client and signature, install/start Ollama, download the model, then **Qualify & pin**. Start in Human review with sending disabled.

## Build

Install stable Rust and Microsoft C++ Build Tools with the Windows SDK:

```powershell
cargo test --locked --lib --no-default-features
cargo build --locked --release --bins
.\target\release\rejection-rejector.exe --demo
```

No Node.js, Electron, Docker, Python backend or PostgreSQL service is needed. SQLite is compiled into the app. Initial downloads and Gmail require internet; inference uses only the configured literal loopback address.

## Important boundaries

The app or `rr run` must remain running for scheduled checks. One process and one connected Gmail account per data directory. Outlook/IMAP and attachment analysis are not implemented. Replies are English; multilingual detection is prompted but comprehensive language accuracy is unverified.

Automatic deliberately holds ambiguous, truncated, changed, non-replyable or unverifiable messages. It also requires an independent deterministic rejection phrase in the current, de-quoted message; the LLM classification and same-model verifier cannot authorize unattended sending by themselves. A strongly worded reply does not overturn an employer's decision. The second model pass is performed by the **same** model, not an independent verifier. Scores are not calibrated probabilities.

Enterprise policy can be independently authenticated with SHA-256 pinning, Ed25519 signatures, or both; signer fingerprints are exposed for audit without private key material. GPU qualification checks Ollama counters, not whole-device peaks or every graphics driver. Database payloads are encrypted, but state/count/time indexes are not. An attacker running as your OS user is outside that protection boundary. Portable recovery is available only as a **separately stored passphrase-wrapped recovery-key envelope**; no plaintext master-key export exists. Authenticode signing and formal security certification are still not claimed.

## Documentation

- [Setup and troubleshooting](docs/SETUP.md)
- [Architecture and state machine](docs/ARCHITECTURE.md)
- [Model choice and GPU qualification](docs/MODEL.md)
- [Integration API](docs/INTEGRATION.md)
- [Enterprise policy](docs/ENTERPRISE_POLICY.md)
- [Enterprise readiness](docs/ENTERPRISE_READINESS.md)
- [Operations and incident runbook](docs/OPERATIONS.md)
- [Contribution and main-only development policy](CONTRIBUTING.md)
- [Tests and acceptance checks](docs/TESTING.md)
- [Security](SECURITY.md)
- [Threat model and data-flow invariants](docs/THREAT_MODEL.md)
- [Original implementation plan](docs/PLAN.md)

CI runs actual builds/tests. A Linux native screenshot is not Windows visual acceptance. Live Gmail authorization/delivery and physical 16 GiB GPU verification require the owner's environment. Application code is MIT; Ollama and model weights retain their own licenses.
