# Rejection Rejector — v0.1 plan

## Product contract

A standalone, local-first Windows 11 desktop application. Application logic and GUI are Rust. Gmail is the first mail provider; the UI is not a browser wrapper. No mailbox credentials, messages, candidate information or model weights belong in this repository.

Required settings:

- Check interval: exactly 1, 2, 4, 8 or 24 hours.
- Lookback: exactly 1, 3, 7, 14 or 28 days.
- Human review or Automatic mode. Human review is the default; sending starts disabled.
- Review tab is available only in Human review. Show the original message and editable response side by side; save, regenerate, dismiss and explicitly confirm sending.
- Local Ollama inference for classification, reply drafting and verification. No cloud inference fallback. Install/start controls and model download progress.
- A 16 GiB GPU target with conservative context and an Ollama-reported full-GPU-residency gate. Model download size alone is not qualification.

## Architecture

Native egui/eframe UI -> bounded command channel -> one blocking worker -> encrypted SQLite + Gmail REST + loopback-only Ollama. A Rust library and optional authenticated, read-only loopback API allow later integration with a separate job-seeker application. OAuth uses the system browser, S256 PKCE, random state and a temporary loopback listener. Credentials and mail content are encrypted at rest; Windows Credential Manager holds the encryption key. Linux development can use an explicit Argon2-derived passphrase.

## Incremental synchronization

Take a Gmail history baseline before the initial bounded-date message listing. Persist unique account/message IDs and a durable processing queue before advancing the history cursor. Later polls consume all history pages, inserting only missing IDs. Expired history requires a safe full reconciliation; changing lookback forces reconciliation. Existing content is not fetched or classified again on every poll. A failure must never silently skip pages or advance an incomplete cursor. Retention removes old completed message content but preserves deduplication and delivery tombstones.

## Reply safety and operational contract

Incoming messages are untrusted data, never executable instructions. Use structured model output, exact evidence checks, bounded inputs and a separate verification pass by the same local model. This reduces errors but is not an independent-model guarantee or calibrated confidence estimate. Automatic mode requires explicit consent, a cooldown, a rolling send-attempt limit and current verified model/draft/context identities. Ambiguity, truncated messages, no-reply addresses, reply loops, changed threads and failed verification must not auto-send. A pause control is checked immediately before dispatch; an already-dispatched message cannot be recalled.

Before a Gmail send, reserve the conversation durably in SQLite. Never blindly retry a possibly delivered message. Interrupted or ambiguous deliveries become Uncertain and can be reconciled against Sent mail. Editing a draft invalidates its previous verification. UI actions carry record revisions so stale approvals cannot send updated content.

## Implementation workstreams

1. Configuration, typed records, authenticated encryption, migrations and persistent queue.
2. Gmail OAuth, MIME parsing, incremental synchronization and threaded replies.
3. Ollama provisioning, digest pinning, VRAM checks, classification/drafting/verification.
4. Worker scheduler and guarded delivery state machine.
5. Windows-oriented native desktop GUI, review flow, activity and settings.
6. Headless CLI, read-only integration API and synthetic offline demo.
7. Automated tests, Windows/Linux CI, packaging and operating documentation.

## Acceptance and evidence

Test exact setting presets, encryption/tampering, deduplication, restart recovery, stale revisions, rate limits, MIME/header injection, reply-loop protection, model-response validation and API authentication. Build GUI and CLI on Windows; build/test core on Linux. Use synthetic fixtures only. A local model evaluation command must report its actual results rather than inventing an accuracy score. Live Gmail authorization/sending and physical 16 GiB GPU qualification require the owner's environment and are not implied by successful CI.

## Scope boundaries

One Gmail account per running data directory in v0.1. No IMAP/Outlook provider, hosted inference, multi-agent model ensemble, automatic forwarding, attachment execution, silent OS installation, automatic model switching, or guarantees of perfect classification. User OAuth setup, runtime installation approval and model download are explicit. The app must be running for scheduled checks; Windows scheduled startup can be documented without pretending a closed desktop app keeps running.
