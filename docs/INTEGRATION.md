# Integration with the separate job-seeker application

This page is for developers who want to consume Rejection Rejector's state from
another local program. There are two integration surfaces: the Rust library (in-process)
and an authenticated **loopback HTTP API** — a small web API that listens only on
`127.0.0.1`, the machine's own network address ("loopback"), so it is never reachable
from the network.

## Rust library

The crate exposes typed configuration/messages, encrypted storage, Gmail
synchronization, Ollama analysis, the guarded engine and the worker. Prefer these
interfaces to duplicating delivery logic — the delivery state machine carries the
safety invariants described in [ARCHITECTURE.md](ARCHITECTURE.md). Only one GUI or
headless worker may own a data directory; close the GUI before running `rr.exe run`.
The public Rust surface follows the Rust API Guidelines and is SemVer-checked in CI.

## Read-only loopback API

Enable the API in Settings, save and restart the app or worker. The default origin is
`http://127.0.0.1:8734`.

Access control uses a **bearer token** (RFC 6750): a random 256-bit credential sent in
the `Authorization: Bearer …` header on every request. Rejection Rejector persists only
a **domain-separated SHA-256 verifier** of that token — a one-way hash (FIPS 180-4)
mixed with a fixed application label, so the stored value cannot be replayed as a
credential and cannot be reversed to the token. The plaintext is displayed only when
first generated or explicitly rotated, disappears after 60 seconds and cannot be
recovered. Existing legacy plaintext tokens are migrated to verifier-only storage
without changing the credential. If a token is lost, rotate it in Settings or, with the
GUI/worker closed, run `rr.exe rotate-api-token`. Store the plaintext credential in the
consuming application's OS-protected secret store. It grants access to private email
content; never commit it or embed it in a public frontend.

For machine integrations the read surface accepts **GET only**, an exact literal-loopback
`Host` header and the valid bearer token. Browser `Origin` headers are refused and no
CORS permissions are emitted. Call from the trusted Rust backend of the future desktop
application, not arbitrary web content.

```powershell
$headers = @{ Authorization = "Bearer " + (Read-Host 'Local API token') }
Invoke-RestMethod 'http://127.0.0.1:8734/v1/capabilities' -Headers $headers
Invoke-RestMethod 'http://127.0.0.1:8734/v1/status' -Headers $headers
Invoke-RestMethod 'http://127.0.0.1:8734/v1/metrics' -Headers $headers
$feed = Invoke-RestMethod 'http://127.0.0.1:8734/v1/item-feed?limit=25' -Headers $headers
if ($feed.next_cursor) {
    Invoke-RestMethod ("http://127.0.0.1:8734/v1/item-feed?limit=25&cursor=" + [uri]::EscapeDataString($feed.next_cursor)) -Headers $headers
}
Invoke-RestMethod 'http://127.0.0.1:8734/v1/items?page=0' -Headers $headers
Invoke-RestMethod 'http://127.0.0.1:8734/v1/events?after=0' -Headers $headers
```

### Endpoint reference

| Endpoint | Result |
|---|---|
| /v1/capabilities | API/application versions, read-only contract, provider, modes, supported features and schedule presets |
| /v1/health | Canonical readiness/integrity state plus filesystem headroom, typed worker operation, enterprise policy, privacy-minimal runtime-journal health and privacy-safe emergency-stop status |
| /v1/status | Version, account, mode, pause/send settings, counts and last successful sync |
| /v1/metrics | Privacy-safe aggregate operational snapshot: queue/review/sent/uncertain counts, send attempts, sync freshness, database/storage headroom, scheduled-backup freshness, audit sequence, qualification state and enterprise-policy revision; no mailbox identity/content |
| /v1/settings | Non-secret presentation settings for the web interface: mode, tone (including Insane), reply-language policy, sending toggle, Automatic-arm state and the arm-cooldown length |
| /v1/item-feed?limit=N&cursor=TOKEN | Preferred integration feed. Opaque cursor traverses a fixed high-water-mark snapshot, so new mail cannot shift pages during synchronization |
| /v1/items?page=N | Legacy offset pagination used by the current UI; suitable for browsing, not durable synchronization |
| /v1/items/ID | One account-owned job |
| /v1/events?after=SEQ | Up to 100 tamper-evident encrypted-journal events after decryption, including stable `kind`, typed `domain` and `severity`; persist the highest returned sequence |
| /v1/audit/anchor | Current verified SHA-256 audit point. Preserves the v1 top-level `head` and adds sequence, workspace fingerprint, and a versioned nested anchor for durable external rollback detection |
| /v1/audit/contains?head=HASH | Check whether a previously exported audit head is present in the authenticated current chain |

### Response conventions

Responses use `Cache-Control: no-store` and every response carries an `X-Request-ID`
UUID (a locally generated correlation identifier) plus `X-RR-API-Contract-SHA256`, the
SHA-256 fingerprint of the exact OpenAPI document served by `/v1/openapi.json`.
Integrations may cache that fingerprint to detect byte-level contract drift, while
semantic compatibility remains governed by the versioned `/v1` contract and
`api_version`. Errors use a stable envelope: `api_version`, `request_id`, and
`error { code, message, retryable }`. Worker operation failures use the same stable
`code`/`retryable` semantics:

- `retryable_*` — a bounded retry is safe;
- `review_required_*` — an operator/user action is required;
- `reconcile_required_*` — an external delivery may have crossed the write boundary
  and **must not be retried** until reconciliation.

Capability, health and status responses expose the application settings-format version
so integrations can detect incompatible future configuration schemas. Enterprise-policy
status includes whether independently provisioned SHA-256 and Ed25519
policy-authentication controls are enforced/verified, plus the non-secret signer
public-key fingerprint when signature enforcement is active. HTTP 503 codes such as
`worker_busy` or `worker_timeout` are retryable with bounded backoff; do not bypass the
worker and open SQLite directly. `/v1/health` and `/v1/status` also expose typed worker
operation state so clients can distinguish sync, model evaluation, backup, delivery and
other operations without scraping UI strings. Each operation lifecycle carries a locally
generated `operation_id` UUID; the same UUID is written to privacy-minimal runtime-journal
records so local support tooling can correlate start/result events without logging
mailbox content. SQLite internals are not a stable integration contract.

### Write routes: web interface only

Version 0.3 keeps the read-only contract for integrations: there are no write/send
routes for machine consumers, no automatic webhook uploads and no cross-service
synchronization. The reserved `api_allow_writes` setting rejects `true`. The embedded
local web interface (`rr web`) is the single exception: it issues state-changing
commands through the same bearer token over `POST /v1/commands/*` (edit-draft,
regenerate, dismiss, send, update-settings, automatic-arm). Those routes enforce the
desktop/terminal gates server-side — the shared `send_gate_eligible` composition, the
confirm-exact-reply payload matched byte for byte against the persisted draft, the
editor `(id, revision)` binding, and the `AutomaticArmGate` 30-second cooldown for
Automatic arming — under a fixed request-body cap, a strict Content-Security-Policy on
every response, and plain-text-only rendering of email content. Enabling, disabling or
changing the API listener requires a restart. Enterprise policy can prohibit the
integration API entirely; effective policy identity and constraints are visible through
authenticated health/status diagnostics.

The served contract is an OpenAPI 3.1.0 document (the latest published specification
is 3.2.0, September 2025; this project deliberately pins 3.1.0 as its compatibility
boundary and validates compatibility in CI).

## Fleet monitoring contract

For enterprise monitoring, prefer `/v1/metrics` or `rr.exe metrics` over scraping UI
labels. The metrics schema is explicitly privacy-safe and versioned independently with
`schema_version`. It contains aggregate state only and performs no external upload.
Treat metric names/fields as a contract and gate consumers on `schema_version`; do not
infer private mailbox identity from counts or timing.

## Cursor synchronization

For application-to-application synchronization, use `/v1/item-feed` rather than offset
pages. Start without a cursor. Persist the returned `next_cursor` only after
successfully processing that page, then request the next page with the token unchanged.
The cursor is opaque: do not parse, construct, truncate, or compare it.

The first request captures the account's current SQLite row high-water mark. Every
continuation remains bounded by that snapshot. Mail inserted after traversal starts
appears only in a later fresh traversal, preventing offset-shift duplicates or
omissions. Cursors are local implementation tokens, not durable cross-version
identifiers; restart a feed from page one after an API contract/version change.

## Sources (checked 2026-10-12)

- IETF RFC 6750, "The OAuth 2.0 Authorization Framework: Bearer Token Usage":
  <https://www.rfc-editor.org/rfc/rfc6750>
- NIST FIPS 180-4, Secure Hash Standard (SHA-256):
  <https://csrc.nist.gov/pubs/fips/180/4/final>
- OpenAPI Initiative, OpenAPI Specification (3.1.0 in this contract; 3.2.0 latest):
  <https://spec.openapis.org/oas/latest.html>
- Rust API Guidelines (public Rust surface conventions):
  <https://rust-lang.github.io/api-guidelines/>
