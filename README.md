# Rejection Rejector

**Your voice, returned.** A standalone native Rust desktop application for detecting job-application rejections, generating assertive responses with a local Ollama model, and reviewing or automatically sending eligible replies.

> Early release. Sending starts **disabled** and **Human review** is the default. No real emails or credentials are bundled. Validate the model on your own mailbox before enabling Automatic.

## Implemented

| Component | Version 0.1 |
|---|---|
| Desktop | Native Rust egui/eframe: Overview, Review, Activity, Local AI, Settings |
| Mail | Gmail Desktop OAuth, system browser, PKCE, explicit read/send consent |
| AI | Local Ollama classification, drafting and a separate same-model audit; structured outputs and exact evidence checks |
| Model | `gemma4:12b-it-qat`, default 8,192 context, explicit download and digest qualification |
| GPU target | 16 GiB; conservative 14 GiB reported-residency budget, not physical peak certification |
| Check interval | **1 / 2 / 4 / 8 / 24 hours** |
| Email age window | **1 / 3 / 7 / 14 / 28 days** |
| Sync | Durable incremental Gmail history queue; insert missing identities only; cursor-expiry recovery |
| Database | Embedded SQLite with authenticated encrypted payloads; Windows Credential Manager holds the key |
| Review | Original and editable reply side by side; save, regenerate, dismiss, confirm exact reply and send |
| Automatic | Explicit authorization, cooldown, send-attempt cap, source/draft/model checks and conversation preflight |
| Mode-aware UI | Review tab is disabled in Automatic mode |
| Recovery | Durable per-conversation reservation; uncertain sends are reconciled, never blindly retried |
| Integration | Reusable Rust library plus optional authenticated read-only loopback API |
| Testing | Synthetic demo, Rust regression tests, model evaluation fixtures and Windows/Linux CI |

## Windows

Download the Windows package from a successful **Rust CI** run on `main`, extract `rejection-rejector-windows-x64.zip`, and launch `rejection-rejector.exe`. The package contains the desktop binary, `rr.exe`, documentation and exact build-commit evidence. The binaries are unsigned; verify their origin and hash. Do not disable Windows security globally.

Safe offline preview:

```powershell
.\rejection-rejector.exe --demo
```

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

Automatic deliberately holds ambiguous, truncated, changed, non-replyable or unverifiable messages. A strongly worded reply does not overturn an employer's decision. The second model pass is performed by the **same** model, not an independent verifier. Scores are not calibrated probabilities.

GPU qualification checks Ollama counters, not whole-device peaks or every graphics driver. Database payloads are encrypted, but state/count/time indexes are not. An attacker running as your OS user is outside that protection boundary. No key-export/recovery, signed installer or security certification is claimed.

## Documentation

- [Setup and troubleshooting](docs/SETUP.md)
- [Architecture and state machine](docs/ARCHITECTURE.md)
- [Model choice and GPU qualification](docs/MODEL.md)
- [Integration API](docs/INTEGRATION.md)
- [Tests and acceptance checks](docs/TESTING.md)
- [Security](SECURITY.md)
- [Original implementation plan](docs/PLAN.md)

CI runs actual builds/tests. A Linux native screenshot is not Windows visual acceptance. Live Gmail authorization/delivery and physical 16 GiB GPU verification require the owner's environment. Application code is MIT; Ollama and model weights retain their own licenses.
