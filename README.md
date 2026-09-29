# Rejection Rejector

**Your voice, returned.** A standalone native Rust desktop application for detecting job-application rejections, generating assertive responses with a local Ollama model, and reviewing or automatically sending eligible replies.

> Early release. Sending starts **disabled** and **Human review** is the default. No real emails or credentials are bundled. Validate the model on your own mailbox before enabling Automatic.

## Implemented

| Component | Version 0.2 |
|---|---|
| Desktop | Native Rust egui/eframe: Overview, Review, Activity, Local AI, Settings |
| Mail | Gmail Desktop OAuth, system browser, PKCE, explicit read/send consent |
| AI | Local Ollama classification/drafting plus same-model or optional sequential independent-model verification; structured outputs and deterministic safety gates |
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

Development CI compiles and tests the Windows desktop/CLI on every `main` commit, but **does not publish a user-facing Windows package on normal pushes**. Packaging is gated behind the manual **Attested Windows package** workflow and an explicit `PACKAGE` confirmation. The workflow produces an explicitly named `unsigned` package by default or, when administrator-provisioned Azure Artifact Signing/OIDC configuration is present, a `signed` flavor. Signed mode fails closed unless both executables are successfully signed and independently report `Valid` Authenticode status. No production package should be described as publisher-signed until that signed workflow path has actually completed successfully.

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

Fleet/deployment tooling can inspect compatibility without opening a workspace:

```powershell
.\rr.exe build-info
.\rr.exe contract-info
.\rr.exe policy-schema > enterprise-policy.schema.json
```

`contract-info` fingerprints the exact OpenAPI document, enterprise-policy schema, settings/database formats, evaluation suite and prompt contract embedded in the binary.

Real setup: [docs/SETUP.md](docs/SETUP.md). Configure your own Gmail OAuth Desktop client and signature, install/start Ollama, download the model, then **Qualify & pin**. Start in Human review with sending disabled.

Optional Windows background worker:

```powershell
.\rr.exe autostart install
.\rr.exe autostart status
# later, if desired:
.\rr.exe autostart remove
```

The task runs only in the signed-in user's session, at least privilege, uses `IgnoreNew` to avoid duplicate workers, and retries failure at one-minute intervals up to three times. Organization policy may prohibit task registration; failure is reported rather than bypassed.

## Build

Install stable Rust and Microsoft C++ Build Tools with the Windows SDK:

```powershell
cargo test --locked --lib --no-default-features
cargo build --locked --release --bins
.\target\release\rejection-rejector.exe --demo
```

No Node.js, Electron, Docker, Python backend or PostgreSQL service is needed. SQLite is compiled into the app. Initial downloads and Gmail require internet; inference uses only the configured literal loopback address.

## Important boundaries

The GUI or `rr run` must own the workspace for scheduled checks. On Windows 11, `rr autostart install` can register the headless worker to start 30 seconds after the current user logs on using Task Scheduler with InteractiveToken + LeastPrivilege; this preserves access to the user's Credential Manager vault while decoupling scheduling from whether the GUI stays open. One process and one connected Gmail account per data directory. Outlook/IMAP and attachment analysis are not implemented. Replies are English; multilingual detection is prompted but comprehensive language accuracy is unverified.

Automatic deliberately holds ambiguous, truncated, changed, non-replyable or unverifiable messages. It also requires an independent deterministic rejection phrase in the current, de-quoted message; model output alone cannot authorize unattended sending. Verification may use the primary model in the base configuration or an optional **sequential independent pinned local model**; enterprise policy v3 can require that independent verifier and constrain its exact tag. The models are intentionally loaded sequentially so only one is targeted for GPU residency at a time. Model diversity reduces correlated semantic error but does not eliminate it, and scores are not calibrated probabilities. A strongly worded reply does not overturn an employer's decision.

Enterprise policy can be independently authenticated with SHA-256 pinning, Ed25519 signatures, or both; signer fingerprints are exposed for audit without private key material. Its versioned JSON Schema is embedded/fingerprinted for deployment drift checks. GPU qualification checks Ollama counters, not whole-device peaks or every graphics driver. Database payloads are encrypted, but state/count/time indexes are not. An attacker running as your OS user is outside that protection boundary. Portable recovery is available only as a **separately stored passphrase-wrapped recovery-key envelope**; no plaintext master-key export exists. A fail-closed Azure Artifact Signing release path is implemented, but no signed production release or formal security certification is claimed merely because the path exists; MSI/MSIX/Intune packaging remains separate deployment work.

## Documentation

- [Setup and troubleshooting](docs/SETUP.md)
- [Architecture and state machine](docs/ARCHITECTURE.md)
- [Model choice and GPU qualification](docs/MODEL.md)
- [Integration API](docs/INTEGRATION.md)
- [Enterprise policy](docs/ENTERPRISE_POLICY.md) and [machine-readable policy schema](docs/enterprise-policy.schema.json)
- [Enterprise readiness](docs/ENTERPRISE_READINESS.md)
- [Operations and incident runbook](docs/OPERATIONS.md)
- [Contribution and main-only development policy](CONTRIBUTING.md)
- [Tests and acceptance checks](docs/TESTING.md)
- [Security](SECURITY.md)
- [Threat model and data-flow invariants](docs/THREAT_MODEL.md)
- [Original implementation plan](docs/PLAN.md)

CI runs actual builds/tests. A Linux native screenshot is not Windows visual acceptance. Live Gmail authorization/delivery and physical 16 GiB GPU verification require the owner's environment. Application code is MIT; Ollama and model weights retain their own licenses.
