# Integration with the separate job-seeker application

## Rust library

The crate exposes typed configuration/messages, encrypted storage, Gmail synchronization, Ollama analysis, the guarded engine and the worker. Prefer these interfaces to duplicating delivery logic. Only one GUI or headless worker may own a data directory; close the GUI before running rr.exe run.

## Read-only loopback API

Enable the API in Settings, save and restart the app or worker. The default origin is http://127.0.0.1:8734. Reveal its random bearer token in Settings. The token is stored encrypted and grants access to private email content; never commit it or embed it in a public frontend.

The server accepts GET only, an exact literal-loopback Host header and the valid bearer token. Browser Origin headers are refused and no CORS permissions are emitted. Call from the trusted Rust backend of the future desktop application, not arbitrary web content.

```powershell
$token = Read-Host 'Local API token'
$headers = @{ Authorization = "Bearer $token" }
Invoke-RestMethod 'http://127.0.0.1:8734/v1/capabilities' -Headers $headers
Invoke-RestMethod 'http://127.0.0.1:8734/v1/status' -Headers $headers
Invoke-RestMethod 'http://127.0.0.1:8734/v1/metrics' -Headers $headers
Invoke-RestMethod 'http://127.0.0.1:8734/v1/items?page=0' -Headers $headers
Invoke-RestMethod 'http://127.0.0.1:8734/v1/events?after=0' -Headers $headers
```

| Endpoint | Result |
|---|---|
| /v1/capabilities | API/application versions, read-only contract, provider, modes, supported features and schedule presets |
| /v1/status | Version, account, mode, pause/send settings, counts and last successful sync |
| /v1/metrics | Privacy-safe aggregate operational snapshot: queue/review/sent/uncertain counts, send attempts, sync freshness, database size/schema, audit sequence, qualification state and enterprise-policy revision; no mailbox identity/content |
| /v1/items?page=N | Page of 25 account-owned jobs with retained original/draft content |
| /v1/items/ID | One account-owned job |
| /v1/events?after=SEQ | Up to 100 tamper-evident encrypted-journal events after decryption, including stable `kind`, typed `domain` and `severity`; persist the highest returned sequence |
| /v1/audit/anchor | Current verified SHA-256 audit-chain head for external anchoring |
| /v1/audit/contains?head=HASH | Check whether a previously exported audit head is present in the current chain |

Responses use `Cache-Control: no-store` and every response carries an `X-Request-ID` UUID for local correlation. Errors use a stable envelope: `api_version`, `request_id`, and `error { code, message, retryable }`. Capability, health and status responses expose the application settings-format version so integrations can detect incompatible future configuration schemas. Enterprise-policy status includes whether an independently provisioned policy digest pin is enforced and matched. HTTP 503 codes such as `worker_busy` or `worker_timeout` are retryable with bounded backoff; do not bypass the worker and open SQLite directly. `/v1/health` and `/v1/status` also expose typed worker operation state so clients can distinguish sync, model evaluation, backup, delivery and other operations without scraping UI strings. SQLite internals are not a stable integration contract.

Version 0.1 has no write/send HTTP routes, automatic webhook uploads or cross-service synchronization. The reserved `api_allow_writes` setting rejects true. Enabling, disabling or changing the API listener requires a restart. Enterprise policy can prohibit the integration API entirely; effective policy identity and constraints are visible through authenticated health/status diagnostics.


## Fleet monitoring contract

For enterprise monitoring, prefer `/v1/metrics` or `rr.exe metrics` over scraping UI labels. The metrics schema is explicitly privacy-safe and versioned independently with `schema_version`. It contains aggregate state only and performs no external upload. Treat metric names/fields as a contract and gate consumers on `schema_version`; do not infer private mailbox identity from counts or timing.
