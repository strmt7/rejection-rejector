# Integration with the separate job-seeker application

## Rust library

The crate exposes typed configuration/messages, encrypted storage, Gmail synchronization, Ollama analysis, the guarded engine and the worker. Prefer these interfaces to duplicating delivery logic. Only one GUI or headless worker may own a data directory; close the GUI before running rr.exe run.

## Read-only loopback API

Enable the API in Settings, save and restart the app or worker. The default origin is http://127.0.0.1:8734. Rejection Rejector persists only a domain-separated SHA-256 verifier for the random 256-bit bearer credential; the plaintext is displayed only when first generated or explicitly rotated, then disappears after 60 seconds and cannot be recovered. Existing legacy tokens are migrated to verifier-only storage without changing the credential. If a token is lost, rotate it in Settings or, with the GUI/worker closed, run `rr.exe rotate-api-token`. Store the plaintext credential in the consuming application's OS-protected secret store. It grants access to private email content; never commit it or embed it in a public frontend.

The server accepts GET only, an exact literal-loopback Host header and the valid bearer token. Browser Origin headers are refused and no CORS permissions are emitted. Call from the trusted Rust backend of the future desktop application, not arbitrary web content.

```powershell
$token = Read-Host 'Local API token'
$headers = @{ Authorization = "Bearer $token" }
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

| Endpoint | Result |
|---|---|
| /v1/capabilities | API/application versions, read-only contract, provider, modes, supported features and schedule presets |
| /v1/health | Canonical readiness/integrity state plus filesystem headroom, typed worker operation, enterprise policy and privacy-minimal runtime-journal health |
| /v1/status | Version, account, mode, pause/send settings, counts and last successful sync |
| /v1/metrics | Privacy-safe aggregate operational snapshot: queue/review/sent/uncertain counts, send attempts, sync freshness, database/storage headroom, scheduled-backup freshness, audit sequence, qualification state and enterprise-policy revision; no mailbox identity/content |
| /v1/item-feed?limit=N&cursor=TOKEN | Preferred integration feed. Opaque cursor traverses a fixed high-water-mark snapshot, so new mail cannot shift pages during synchronization |
| /v1/items?page=N | Legacy offset pagination used by the current UI; suitable for browsing, not durable synchronization |
| /v1/items/ID | One account-owned job |
| /v1/events?after=SEQ | Up to 100 tamper-evident encrypted-journal events after decryption, including stable `kind`, typed `domain` and `severity`; persist the highest returned sequence |
| /v1/audit/anchor | Current verified SHA-256 audit point. Preserves the v1 top-level `head` and adds sequence, workspace fingerprint, and a versioned nested anchor for durable external rollback detection |
| /v1/audit/contains?head=HASH | Check whether a previously exported audit head is present in the authenticated current chain |

Responses use `Cache-Control: no-store` and every response carries an `X-Request-ID` UUID for local correlation plus `X-RR-API-Contract-SHA256`, the SHA-256 fingerprint of the exact OpenAPI document served by `/v1/openapi.json`. Integrations may cache that fingerprint to detect byte-level contract drift, while semantic compatibility remains governed by the versioned `/v1` contract and `api_version`. Errors use a stable envelope: `api_version`, `request_id`, and `error { code, message, retryable }`. Capability, health and status responses expose the application settings-format version so integrations can detect incompatible future configuration schemas. Enterprise-policy status includes whether independently provisioned SHA-256 and Ed25519 policy-authentication controls are enforced/verified, plus the non-secret signer public-key fingerprint when signature enforcement is active. HTTP 503 codes such as `worker_busy` or `worker_timeout` are retryable with bounded backoff; do not bypass the worker and open SQLite directly. `/v1/health` and `/v1/status` also expose typed worker operation state so clients can distinguish sync, model evaluation, backup, delivery and other operations without scraping UI strings. Each operation lifecycle carries a locally generated `operation_id` UUID; the same UUID is written to privacy-minimal runtime-journal records so local support tooling can correlate start/result events without logging mailbox content. SQLite internals are not a stable integration contract.

Version 0.2 retains the read-only HTTP contract: there are no write/send HTTP routes, automatic webhook uploads or cross-service synchronization. The reserved `api_allow_writes` setting rejects true. Enabling, disabling or changing the API listener requires a restart. Enterprise policy can prohibit the integration API entirely; effective policy identity and constraints are visible through authenticated health/status diagnostics.


## Fleet monitoring contract

For enterprise monitoring, prefer `/v1/metrics` or `rr.exe metrics` over scraping UI labels. The metrics schema is explicitly privacy-safe and versioned independently with `schema_version`. It contains aggregate state only and performs no external upload. Treat metric names/fields as a contract and gate consumers on `schema_version`; do not infer private mailbox identity from counts or timing.


## Cursor synchronization

For application-to-application synchronization, use `/v1/item-feed` rather than offset pages. Start without a cursor. Persist the returned `next_cursor` only after successfully processing that page, then request the next page with the token unchanged. The cursor is opaque: do not parse, construct, truncate, or compare it.

The first request captures the account's current SQLite row high-water mark. Every continuation remains bounded by that snapshot. Mail inserted after traversal starts appears only in a later fresh traversal, preventing offset-shift duplicates or omissions. Cursors are local implementation tokens, not durable cross-version identifiers; restart a feed from page one after an API contract/version change.
