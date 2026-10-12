# Architecture

Rejection Rejector is a native desktop application: a Rust GUI (egui/eframe) and the
`rr` command-line tool both submit work to **one worker process** that owns the
workspace. That worker talks to exactly two external systems: the Gmail REST API
(Google's HTTP interface for mailbox access) and a local Ollama server (the local
model runtime, reached only over the loopback network address `127.0.0.1`). An
optional read-only HTTP API exposes the same worker state to other local tools.

There is no browser wrapper, no server database and no hosted component. Network,
model and database work never runs on the UI thread; the UI posts typed commands over
a bounded channel and renders typed results. Atomic Pause/Stop flags gate dispatch.
The worker keeps its thread handle for **bounded graceful shutdown**: operations that
touch the outside world (send, backup, restore) are surfaced as typed operation state
so the GUI can warn before closing without ever waiting indefinitely.

## Component map

| Path | Role |
|---|---|
| `src/gui/`, `src/gui.rs`, `src/tui.rs`, `src/web.rs` | Native GUI, terminal UI and embedded local web page |
| `src/engine.rs`, `src/background.rs`, `src/session.rs` | Worker loop, scheduling, command channel |
| `src/sync.rs`, `src/gmail.rs` | Incremental Gmail synchronization and provider calls |
| `src/ollama.rs`, `src/evaluation.rs` | Local model inference and task evaluation |
| `src/store.rs`, `src/storage.rs`, `src/vault.rs` | Delivery state machine, encrypted SQLite storage, cryptography |
| `src/decision.rs`, `src/language.rs` | Deterministic rejection gate and reply-language checks |
| `src/policy.rs`, `src/audit_anchor.rs`, `src/emergency.rs` | Enterprise policy, rollback anchors, emergency stop |
| `src/api.rs`, `src/api_auth.rs`, `src/contracts.rs` | Loopback API, bearer-token verification, OpenAPI contract |
| `src/recovery.rs`, `src/recovery/` | Backup verification and restore |
| `src/mail.rs`, `src/oauth.rs`, `src/oauth/`, `src/gmail.rs` | MIME parsing/threading and Gmail OAuth + REST access |
| `src/config.rs`, `src/types.rs`, `src/readiness.rs`, `src/diagnostics.rs`, `src/metrics.rs`, `src/retry.rs` | Settings and shared types, readiness gates, privacy-minimal diagnostics/metrics, retry policy |

## Incremental sync

Synchronization is **incremental**: only new or changed mail is fetched after the
first run. The worker takes a Gmail history baseline before the initial date-bounded
listing, then inserts each missing account/message identity with an encrypted durable
queue record. The history cursor is saved only after every page succeeds, so an
interrupted poll replays safely; replayed pages are deduplicated by provider identity.
Expired history (Gmail answers 404) or a changed lookback window triggers a
reconciliation pass. Taking the baseline before listing catches messages that arrive
while the listing is running.

Actual message dates and folders are checked by the worker. Out-of-window messages
become **Deferred** and their bodies are discarded; expanding the window requeues
them. Previously processed mail is not refetched or reclassified on each poll.
Non-rejections keep their identity records, not full bodies. Gmail label-change
subscriptions and Google Pub/Sub push are outside the current release line (0.3).
Each synchronization operation has a hard resource ceiling of 512 provider pages and
250,000 observed message identities. Exceeding either budget fails closed without
advancing the durable Gmail cursor; already inserted identities are replay-safe
because provider IDs are deduplicated.

## State and delivery

Message states: **Queued → Ready / Attention / Other / Deferred**. Editing a
reviewable reply invalidates its verification and moves it to Attention. Regeneration
requeues it. Dismissal records **Dismissed**. Confirmed human sends or eligible
automatic replies transition through **Sending → Sent / Uncertain**. Positive Sent
reconciliation (matching the outgoing message in Gmail's Sent mail) resolves
Uncertain.

### Failure isolation

Per-message local-analysis failures are bulkheaded (isolated) from runtime-wide
failures. A healthy Ollama/model preflight happens before a message is dequeued;
failures discovered after dequeue are recorded under a stable typed processing-failure
code and retried with a per-item delay. After three attempts the item moves to
**Attention**. The worker treats that recorded item failure as handled and stays
available for other due messages, so one poison message cannot open the global
analysis circuit breaker or starve the queue. Only failures established before dequeue
remain runtime-wide circuit-breaker failures. Stable failure metadata lives in a
dedicated authenticated table; the clear code/exhaustion fields are non-sensitive
operational indexes and are checked against the encrypted record during deep integrity
verification.

### Send authorization

A send must match the current revision and the exact persisted draft hash. The
account, the source message and newer conversation activity are rechecked. An
IMMEDIATE SQLite transaction enforces the global rolling attempt cap and creates one
permanent delivery record for that specific rejection message **before** the HTTP
dispatch. Automatic mode additionally enforces a hard rolling 24-hour ceiling of two
attempts to the same normalized recipient mailbox; that recipient guard is rechecked
inside the same reservation transaction. No new recipient index is persisted — the
bounded recent delivery set is decrypted locally — and Human Review remains the
explicit operator override path. A thread may have only one **reserved or uncertain**
delivery at a time; a completed Sent record does not prevent a later, distinct
rejection in the same Gmail thread from receiving its own reply. The same rejection
message can never obtain a second delivery record. Crashed Sending records recover as
Uncertain.

Known pre-dispatch cancellation or a definite provider-side rejection releases the
unsent reservation and returns the message to Human Review. Ambiguous network/server
outcomes retain an Uncertain record and block further replies in that thread until
reconciliation. This deliberately prioritizes avoiding duplicate delivery over
guaranteed delivery. It is at-most-once **per rejection message at the application
level**, not a distributed exactly-once guarantee. The deterministic outgoing
Message-ID supports reconciliation.

## Trust boundary

Email is inert untrusted data, never tools or instructions. Attachments are not
executed; HTML becomes text. Structured outputs and exact evidence checks reject
malformed or unsupported classifications. Model/prompt/context/source/draft hashes
bind a verification to its inputs. The same model performs the second pass, so its
errors are correlated; Automatic mode therefore also requires a deterministic
affirmative rejection phrase in the current de-quoted message (the message with quoted
history removed), in addition to rejecting conflicting opportunity or prompt-injection
language. Human review remains the recommended initial mode.

Integrity is protected by SQLite running in WAL mode (write-ahead logging: changes
are recorded in a log before being applied) with FULL synchronization, authenticated
encrypted payloads, optimistic revisions and an exclusive directory lock. Payload
encryption is AEAD: it detects tampering as well as hiding content. Metadata indexes
are not encrypted. The database layout is private; use the library or the loopback API
as the integration contract (see [INTEGRATION.md](INTEGRATION.md)).

Backups bind checksums to the authenticated audit-chain head. A non-destructive
recovery drill restores a selected backup through the production restore path into an
isolated temporary workspace, reopens it under the current vault and deeply verifies
encrypted metadata/items/events/deliveries before reporting success. The integration
API publishes the SHA-256 fingerprint of its exact OpenAPI bytes so downstream tools
can detect contract drift without reading SQLite internals.

## Where behavior is enforced and proven

The safety-critical behaviors above are release invariants with dedicated tests: the
delivery state machine (`src/store.rs`, exercised by `tests/state_invariants.rs` and
`tests/send_concurrency.rs`), the deterministic rejection gate
(`tests/decision_protocol.rs`), sync recovery (`tests/sync_recovery.rs`), HTTP/API
boundaries (`tests/http_boundaries.rs`, `tests/openapi_compatibility.rs`) and the
recovery path (`tests/release/`). See [TESTING.md](TESTING.md) for the evidence rules
that govern these runs.

## Sources (checked 2026-10-12)

- SQLite, "Write-Ahead Logging" (WAL semantics used above):
  https://sqlite.org/wal.html
- Google, Gmail API (provider history/list/send semantics):
  https://developers.google.com/gmail/api
- IETF RFC 8252 / RFC 7636 (loopback OAuth + PKCE used for Gmail authorization):
  https://www.rfc-editor.org/rfc/rfc8252 and https://www.rfc-editor.org/rfc/rfc7636
- OpenAPI Initiative, OpenAPI Specification (the served contract is version 3.1.0):
  https://spec.openapis.org/oas/latest.html
