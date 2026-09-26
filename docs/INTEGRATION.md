# Integrating the separate job-seeker app

Use the Rust library or the read-only HTTP API, not SQLite internals. Only one process can open a data directory.

Enable the API in Settings, save and restart. Default origin: http://127.0.0.1:8734. Reveal its random bearer token in Settings. It is stored encrypted and grants access to private email data; keep it out of repositories/frontend constants.

Only GET with an exact loopback Host and valid bearer is accepted. Browser Origin headers are refused; no CORS permission is emitted. There are no write/send endpoints in v0.1. The future Rust desktop backend can call it directly.

```powershell
$token = Read-Host 'Local API token'
$headers = @{ Authorization = "Bearer $token" }
Invoke-RestMethod 'http://127.0.0.1:8734/v1/status' -Headers $headers
Invoke-RestMethod 'http://127.0.0.1:8734/v1/items?page=0' -Headers $headers
Invoke-RestMethod 'http://127.0.0.1:8734/v1/events?after=0' -Headers $headers
```

/v1/status returns aggregate status; /v1/items?page=N returns 25 account-owned jobs; /v1/items/ID returns one job; /v1/events?after=SEQ returns up to100 audit events. Persist the largest sequence for incremental consumption. Responses use no-store. A503 means the single worker is busy: retry with bounded backoff. Enabling/disabling/changing the listener requires restart. api_allow_writes=true is rejected; no webhook upload exists.
