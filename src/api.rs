use crate::{
    api_auth::ApiTokenVerifier,
    worker::{Command, WorkerPulse},
};
use anyhow::Result;
use chrono::Utc;
use crossbeam_channel::{Sender, bounded};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tiny_http::{Header, Method, Response, Server};

pub const API_VERSION: u32 = 1;
pub const OPENAPI_DOCUMENT: &str = include_str!("../docs/openapi-v1.json");
pub const JSON_CONTENT_TYPE: &str = "application/json; charset=utf-8";
pub const OPENMETRICS_CONTENT_TYPE: &str =
    "application/openmetrics-text; version=1.0.0; charset=utf-8";
pub const API_RATE_LIMIT_BURST: u32 = 30;
pub const API_RATE_LIMIT_PER_SECOND: f64 = 2.0;
/// Deadline for one state-changing write to finish on the worker.
///
/// Sends recheck Gmail and can take far longer than a read query; the
/// bounded deadline still keeps a wedged worker from pinning the listener.
pub const WRITE_REPLY_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Debug)]
struct RateLimiter {
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    /// Create a token-bucket rate limiter starting full.
    ///
    /// Inputs: `now` — the instant the bucket clock starts from. Output: `Self`
    /// with `tokens` at `API_RATE_LIMIT_BURST` and `last` set to `now`.
    fn new(now: Instant) -> Self {
        Self {
            tokens: f64::from(API_RATE_LIMIT_BURST),
            last: now,
        }
    }

    /// Spend one token if the replenished bucket has one.
    ///
    /// Inputs: `now` — instant of the current request, used to refill the bucket.
    /// Output: `true` when a token was available and consumed; `false` when the
    /// request must be rate-limited.
    fn allow(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * API_RATE_LIMIT_PER_SECOND)
            .min(f64::from(API_RATE_LIMIT_BURST));
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

/// Fingerprint the bundled OpenAPI contract document.
///
/// Inputs: none. Output: `String` of lowercase hex — the SHA-256 digest of [`OPENAPI_DOCUMENT`].
pub fn openapi_sha256() -> String {
    crate::hex_lower(Sha256::digest(OPENAPI_DOCUMENT.as_bytes()))
}

/// Build the stable API error envelope.
///
/// Inputs: `code` — machine-readable error code; `message` — operator-facing
/// description; `retryable` — whether the client may retry the request;
/// `request_id` — per-request correlation identifier. Output:
/// `serde_json::Value` envelope carrying `api_version`, `request_id`, and the
/// typed error object.
fn error_body(code: &str, message: &str, retryable: bool, request_id: &str) -> serde_json::Value {
    json!({
        "api_version": API_VERSION,
        "request_id": request_id,
        "error": {
            "code": code,
            "message": message,
            "retryable": retryable
        }
    })
}

/// Answer the direct read routes from a worker liveness snapshot.
///
/// Inputs: `path` — request path; `pulse` — worker liveness source backing the
/// snapshot. Output: `Some` JSON body for a known read route (`/v1/live`,
/// `/v1/openapi.json`); `None` for any other path, which falls through to the
/// routed handlers.
fn direct_get(path: &str, pulse: &WorkerPulse) -> Option<serde_json::Value> {
    match path {
        "/v1/live" => {
            let worker = pulse.snapshot(Utc::now());
            Some(json!({
                "live": true,
                "api_thread_live": true,
                "worker_responsive": worker.worker_responsive,
                "worker": worker,
                "api_version": API_VERSION,
                "api_contract_sha256": openapi_sha256(),
                "application_version": env!("CARGO_PKG_VERSION"),
                "build": crate::build_info::current()
            }))
        }
        "/v1/openapi.json" => serde_json::from_str(OPENAPI_DOCUMENT).ok(),
        _ => None,
    }
}

/// Read one strictly-unique request header value.
///
/// Inputs: `headers` — request header list; `name` — header name, matched ASCII
/// case-insensitively. Output: `Some(&str)` with the value only when exactly
/// one matching header exists; `None` when it is missing or repeated, so
/// ambiguous input fails closed.
fn unique_header<'a>(headers: &'a [tiny_http::Header], name: &str) -> Option<&'a str> {
    let mut values = headers
        .iter()
        .filter(|header| header.field.to_string().eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str());
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

/// Check one request's bearer header against the verifier.
///
/// Inputs: `value` — raw `Authorization` header value, if present; `verifier` —
/// API token verifier. Output: `true` only when the header authorizes the
/// request.
fn authorized(value: Option<&str>, verifier: &ApiTokenVerifier) -> bool {
    verifier.authorize_header(value)
}

/// Whether the request is a navigation for the embedded web page.
///
/// Inputs: `method` — request method; `route` — request path. Output: `true`
/// only for `GET /`, the static shell served without a bearer token because
/// it contains no data; every data route stays authenticated.
fn is_web_page(method: &Method, route: &str) -> bool {
    method == &Method::Get && route == "/"
}

/// Whether a request may carry a browser `Origin` header at all.
///
/// Inputs: `method` — request method; `route` — request path; `origin` —
/// unique `Origin` header value; `origin_present` — whether any `Origin`
/// header exists; `port` — configured loopback port. Output: `true` only for
/// a POST to an exact write route whose `Origin` is exactly this server's
/// loopback origin (same-origin browser writes from the embedded page).
/// Every other request — all reads included — refuses any `Origin` header,
/// preserving the existing cross-site request forgery posture.
fn origin_policy_allows(
    method: &Method,
    route: &str,
    origin: Option<&str>,
    origin_present: bool,
    port: u16,
) -> bool {
    if !origin_present {
        return true;
    }
    let loopback_origin = format!("http://127.0.0.1:{port}");
    method == &Method::Post
        && crate::web::is_write_route(route)
        && origin == Some(loopback_origin.as_str())
}

/// The typed rejection for a body over the fixed write cap.
///
/// Inputs: none. Output: a [`crate::web::WriteError`] with status 413 and
/// code [`crate::web::CODE_REQUEST_BODY_TOO_LARGE`], shared by the declared
/// and streamed length checks so both yield the identical contract.
fn body_too_large() -> crate::web::WriteError {
    crate::web::WriteError {
        status: 413,
        code: crate::web::CODE_REQUEST_BODY_TOO_LARGE.into(),
        message: "The request body exceeds the fixed local write limit".into(),
        retryable: false,
    }
}

/// Read one request body stream under the fixed size cap.
///
/// Inputs: `reader` — unconsumed body source. Output: the raw body bytes, or
/// a typed [`crate::web::WriteError`]: a mid-body transport failure (e.g. a
/// TCP reset) is a non-retryable [`crate::web::CODE_INVALID_REQUEST`] that
/// never echoes the underlying I/O error, and a body past
/// [`crate::web::MAX_WRITE_BODY_BYTES`] fails with
/// [`crate::web::CODE_REQUEST_BODY_TOO_LARGE`] without buffering the excess.
/// Generic over [`std::io::Read`] so the failure mapping is testable with a
/// faulting reader instead of a real socket reset.
fn read_capped_body<R: Read>(reader: R) -> Result<Vec<u8>, crate::web::WriteError> {
    let mut raw = Vec::new();
    reader
        .take(crate::web::MAX_WRITE_BODY_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| crate::web::WriteError {
            status: 400,
            code: crate::web::CODE_INVALID_REQUEST.into(),
            message: "The request body could not be read".into(),
            retryable: false,
        })?;
    if raw.len() > crate::web::MAX_WRITE_BODY_BYTES {
        return Err(body_too_large());
    }
    Ok(raw)
}

/// Read one state-changing request body under the fixed size cap.
///
/// Inputs: `request` — in-flight request whose body has not been consumed.
/// Output: the raw body bytes, or a typed [`crate::web::WriteError`]: a
/// declared `Content-Length` over [`crate::web::MAX_WRITE_BODY_BYTES`] fails
/// with [`crate::web::CODE_REQUEST_BODY_TOO_LARGE`] before any read, and
/// transport or size failures while streaming map exactly as
/// [`read_capped_body`] documents.
fn read_write_body(request: &mut tiny_http::Request) -> Result<Vec<u8>, crate::web::WriteError> {
    let declared = unique_header(request.headers(), "Content-Length")
        .map(str::trim)
        .and_then(|value| value.parse::<usize>().ok());
    if declared.is_some_and(|length| length > crate::web::MAX_WRITE_BODY_BYTES) {
        return Err(body_too_large());
    }
    read_capped_body(request.as_reader())
}

/// Handle one state-changing request: parse, dispatch to the worker, wrap the
/// outcome in the stable response envelope.
///
/// Inputs: `request` — in-flight request with an unconsumed body;
/// `request_id` — per-request correlation UUID; `commands` — worker command
/// channel. Output: `(status, body)` for the response — typed write
/// rejections keep their stable code, accepted writes carry the typed
/// operation status, and a busy or wedged worker yields the existing
/// `worker_busy`/`worker_timeout` envelope.
fn handle_write(
    request: &mut tiny_http::Request,
    request_id: &str,
    commands: &Sender<Command>,
) -> (u16, String) {
    let error_outcome = |error: &crate::web::WriteError| {
        (
            error.status,
            crate::web::response_envelope(request_id, &crate::web::WriteOutcome::error(error))
                .to_string(),
        )
    };
    // The write contract is `application/json` (see the OpenAPI document and
    // the embedded page's fetch wrapper); a body announced as any other type
    // is refused before it is read or dispatched. A missing header is left to
    // the body parser, which requires valid JSON regardless.
    if let Some(value) = unique_header(request.headers(), "Content-Type") {
        let essence = value.split(';').next().unwrap_or_default().trim();
        if !essence.eq_ignore_ascii_case("application/json") {
            return error_outcome(&crate::web::WriteError::reject(
                400,
                crate::web::CODE_INVALID_REQUEST,
                "State-changing requests must carry an application/json body",
            ));
        }
    }
    let raw = match read_write_body(request) {
        Ok(raw) => raw,
        Err(error) => return error_outcome(&error),
    };
    let write = match crate::web::parse_write_request(request.url(), &raw) {
        Ok(write) => write,
        Err(error) => return error_outcome(&error),
    };
    let (tx, rx) = bounded(1);
    if commands
        .try_send(Command::ApiWrite {
            request: write,
            reply: tx,
        })
        .is_err()
    {
        return (
            503,
            error_body(
                "worker_busy",
                "The worker command queue is busy",
                true,
                request_id,
            )
            .to_string(),
        );
    }
    match rx.recv_timeout(WRITE_REPLY_TIMEOUT) {
        Ok(outcome) => (
            outcome.status,
            crate::web::response_envelope(request_id, &outcome).to_string(),
        ),
        Err(_) => (
            503,
            error_body(
                "worker_timeout",
                "The worker did not answer before the local API deadline",
                true,
                request_id,
            )
            .to_string(),
        ),
    }
}

/// Build the fixed response header set attached to every API response.
///
/// Inputs: `request_id` — per-request correlation identifier;
/// `contract_sha256` — hex digest of the pinned OpenAPI contract;
/// `build_identity_sha256` — hex digest of the build identity;
/// `content_type` — response body media type. Output: the seven headers in
/// application order as fallible constructions. Every name is an ASCII
/// literal and every value is a constant or generated ASCII (UUID/hex
/// digests), so production inputs always construct; the fallibility is kept
/// and guarded by [`finalize_response`] so the failure path is injectable
/// and tested instead of a dead 500 arm.
fn response_headers(
    request_id: &str,
    contract_sha256: &str,
    build_identity_sha256: &str,
    content_type: &str,
) -> [Result<Header, ()>; 7] {
    [
        Header::from_bytes("Content-Type", content_type),
        Header::from_bytes("Cache-Control", "no-store"),
        Header::from_bytes("X-Content-Type-Options", "nosniff"),
        Header::from_bytes(
            "Content-Security-Policy",
            crate::web::WEB_CONTENT_SECURITY_POLICY,
        ),
        Header::from_bytes("X-Request-ID", request_id),
        Header::from_bytes("X-RR-API-Contract-SHA256", contract_sha256),
        Header::from_bytes("X-RR-Build-Identity-SHA256", build_identity_sha256),
    ]
}

/// Assemble the response to send from one body plus fallible headers.
///
/// Inputs: `body` — response body; `status` — response status;
/// `headers` — constructed headers in application order. Output: the normal
/// response carrying every header when all constructions succeed, or the
/// fixed bare 500 "Internal response construction failure" response when any
/// header cannot be built (guards against malformed header input ever
/// reaching a client half-formed).
fn finalize_response(
    body: String,
    status: u16,
    headers: impl IntoIterator<Item = Result<Header, ()>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let headers: Vec<Header> = match headers.into_iter().collect() {
        Ok(headers) => headers,
        Err(()) => {
            return Response::from_string("Internal response construction failure")
                .with_status_code(500);
        }
    };
    let mut response = Response::from_string(body).with_status_code(status);
    for header in headers {
        response = response.with_header(header);
    }
    response
}

/// Local loopback HTTP surface: read API, embedded web page, gated writes.
///
/// No CORS, literal loopback Host, bearer token on every data route, and no
/// browser `Origin` except same-origin writes from the embedded page. The
/// static page at `GET /` contains no data and needs no token; read endpoints
/// stay read-only, and state-changing endpoints accept only authenticated
/// POST requests under the fixed body cap.
///
/// Inputs: `port` — loopback TCP port to bind (`0` picks an ephemeral one); `verifier`
/// — bearer-token verifier applied to every data route; `commands` — channel
/// to the worker for write commands; `stop` — flag that shuts the accept loop
/// down; `disabled` — flag that stops the accept loop while the API is
/// disabled; `pulse` — worker liveness source for read snapshots. Output: `Result<u16>`
/// with the port actually bound; errors when the listener cannot bind.
pub fn start_with_verifier(
    port: u16,
    verifier: ApiTokenVerifier,
    commands: Sender<Command>,
    stop: Arc<AtomicBool>,
    disabled: Arc<AtomicBool>,
    pulse: WorkerPulse,
) -> Result<u16> {
    let contract_sha256 = openapi_sha256();
    let build_identity_sha256 = crate::build_info::identity_sha256();
    let listener = std::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .map_err(|e| anyhow::anyhow!("Cannot bind loopback API: {e}"))?;
    // Bind exactly once and work from the port the socket actually holds:
    // `port` may be 0 (ephemeral, required by parallel tests), and the Host
    // and Origin policies must check the real endpoint.
    let port = listener
        .local_addr()
        .map_err(|e| anyhow::anyhow!("Cannot inspect loopback API listener: {e}"))?
        .port();
    let server = Server::from_listener(listener, None)
        .map_err(|e| anyhow::anyhow!("Cannot bind loopback API: {e}"))?;
    std::thread::spawn(move || {
        let mut rate_limiter = RateLimiter::new(Instant::now());
        while !stop.load(Ordering::SeqCst) && !disabled.load(Ordering::SeqCst) {
            let mut request = match server.recv_timeout(Duration::from_millis(250)) {
                Ok(Some(r)) => r,
                Ok(None) => continue,
                Err(_) => break,
            };
            let request_id = uuid::Uuid::new_v4().to_string();
            let auth = unique_header(request.headers(), "Authorization");
            let host = unique_header(request.headers(), "Host");
            let origin_present = request.headers().iter().any(|h| h.field.equiv("Origin"));
            let origin = unique_header(request.headers(), "Origin");
            let page = is_web_page(request.method(), request.url());
            let write_route = crate::web::is_write_route(request.url());
            let (status, body, content_type) = if !rate_limiter.allow(Instant::now()) {
                (
                    429,
                    error_body(
                        "rate_limited",
                        "The local integration API request rate exceeded its bounded burst",
                        true,
                        &request_id,
                    )
                    .to_string(),
                    JSON_CONTENT_TYPE,
                )
            } else if host != Some(format!("127.0.0.1:{port}").as_str())
                || !origin_policy_allows(
                    request.method(),
                    request.url(),
                    origin,
                    origin_present,
                    port,
                )
                || (!page && !authorized(auth, &verifier))
            {
                (
                    401,
                    error_body(
                        "unauthorized",
                        "Authentication, Host or Origin policy rejected the request",
                        false,
                        &request_id,
                    )
                    .to_string(),
                    JSON_CONTENT_TYPE,
                )
            } else if page {
                (
                    200,
                    crate::web::WEB_PAGE_HTML.to_string(),
                    crate::web::WEB_PAGE_CONTENT_TYPE,
                )
            } else if write_route {
                if request.method() == &Method::Post {
                    let (status, body) = handle_write(&mut request, &request_id, &commands);
                    (status, body, JSON_CONTENT_TYPE)
                } else {
                    (
                        405,
                        error_body(
                            "method_not_allowed",
                            "This state-changing endpoint accepts POST only",
                            false,
                            &request_id,
                        )
                        .to_string(),
                        JSON_CONTENT_TYPE,
                    )
                }
            } else if request.method() != &Method::Get {
                (
                    405,
                    error_body(
                        "method_not_allowed",
                        "The integration API is read-only",
                        false,
                        &request_id,
                    )
                    .to_string(),
                    JSON_CONTENT_TYPE,
                )
            } else if request.url().len() > 2000 || !request.url().starts_with("/v1/") {
                (
                    404,
                    error_body("route_not_found", "Unknown API route", false, &request_id)
                        .to_string(),
                    JSON_CONTENT_TYPE,
                )
            } else if request.url() == "/v1/metrics/openmetrics" {
                let (tx, rx) = bounded(1);
                if commands
                    .try_send(Command::OpenMetrics { reply: tx })
                    .is_err()
                {
                    (
                        503,
                        error_body(
                            "worker_busy",
                            "The worker command queue is busy",
                            true,
                            &request_id,
                        )
                        .to_string(),
                        JSON_CONTENT_TYPE,
                    )
                } else {
                    match rx.recv_timeout(Duration::from_secs(3)) {
                        Ok(text) => (200, text, OPENMETRICS_CONTENT_TYPE),
                        Err(_) => (
                            503,
                            error_body(
                                "worker_timeout",
                                "The worker did not answer before the local API deadline",
                                true,
                                &request_id,
                            )
                            .to_string(),
                            JSON_CONTENT_TYPE,
                        ),
                    }
                }
            } else if let Some(body) = direct_get(request.url(), &pulse) {
                (200, body.to_string(), JSON_CONTENT_TYPE)
            } else {
                let (tx, rx) = bounded(1);
                if commands
                    .try_send(Command::Api {
                        path: request.url().into(),
                        reply: tx,
                    })
                    .is_err()
                {
                    (
                        503,
                        error_body(
                            "worker_busy",
                            "The worker command queue is busy",
                            true,
                            &request_id,
                        )
                        .to_string(),
                        JSON_CONTENT_TYPE,
                    )
                } else {
                    match rx.recv_timeout(Duration::from_secs(3)) {
                        Ok(data) if data.get("error").is_some() => (
                            400,
                            error_body(
                                "invalid_request",
                                "The request was invalid or the requested resource is unavailable",
                                false,
                                &request_id,
                            )
                            .to_string(),
                            JSON_CONTENT_TYPE,
                        ),
                        Ok(data) => (200, data.to_string(), JSON_CONTENT_TYPE),
                        Err(_) => (
                            503,
                            error_body(
                                "worker_timeout",
                                "The worker did not answer before the local API deadline",
                                true,
                                &request_id,
                            )
                            .to_string(),
                            JSON_CONTENT_TYPE,
                        ),
                    }
                }
            };
            let response = finalize_response(
                body,
                status,
                response_headers(
                    request_id.as_str(),
                    contract_sha256.as_str(),
                    build_identity_sha256.as_str(),
                    content_type,
                ),
            );
            let _ = request.respond(response);
        }
    });
    Ok(port)
}

/// Backwards-compatible library entry point. The supplied plaintext token is
/// immediately reduced to an in-memory verifier; application persistence uses
/// only verifier material.
///
/// Inputs: `port` — loopback TCP port to bind; `token` — plaintext bearer
/// token, reduced to a verifier before use; `commands` — channel to the
/// worker; `stop` — flag that shuts the accept loop down; `disabled` — flag
/// that stops the accept loop while the API is disabled; `pulse` — worker
/// liveness source. Output: `Result<u16>` with the bound port, as [`start_with_verifier`].
pub fn start(
    port: u16,
    token: String,
    commands: Sender<Command>,
    stop: Arc<AtomicBool>,
    disabled: Arc<AtomicBool>,
    pulse: WorkerPulse,
) -> Result<u16> {
    let verifier = ApiTokenVerifier::from_token(&token)?;
    start_with_verifier(port, verifier, commands, stop, disabled, pulse)
}
#[cfg(test)]
mod tests {
    // Uncovered-by-design lines here carry no product signal: the
    // `_ => panic!(...)` arms of the scripted worker dispatchers fire only
    // when the code under test sends a command the scenario does not
    // expect (which is exactly what they pin), so they never run green.
    use super::*;
    use crate::web::{CODE_CONFIRM_REPLY_MISMATCH, CODE_METHOD_NOT_ALLOWED, WriteOutcome};
    use crossbeam_channel::Receiver;

    /// Bind a free loopback port and start the real API server for one test.
    ///
    /// Inputs: `token` — bearer credential the client will present. Output:
    /// `(port, receiver, stop)` where `receiver` plays the worker role (the
    /// test answers dispatched commands itself) and `stop` shuts the
    /// listener down.
    fn serve(token: &str) -> (u16, Receiver<Command>, Arc<AtomicBool>) {
        let (commands, receiver) = bounded(4);
        let stop = Arc::new(AtomicBool::new(false));
        let port = start(
            0,
            token.into(),
            commands,
            stop.clone(),
            Arc::new(AtomicBool::new(false)),
            WorkerPulse::new(),
        )
        .unwrap();
        (port, receiver, stop)
    }

    /// Assert a response carries the strict Content-Security-Policy header.
    ///
    /// Inputs: `response` — HTTP response. Output: none; panics when the
    /// header is missing or does not deny everything by default.
    fn assert_csp(response: &reqwest::blocking::Response) {
        let policy = response
            .headers()
            .get("Content-Security-Policy")
            .expect("every response must carry a Content-Security-Policy")
            .to_str()
            .unwrap();
        assert!(policy.contains("default-src 'none'"));
        assert!(policy.contains("connect-src 'self'"));
    }

    /// Body source that yields a short prefix and then fails, simulating a
    /// mid-body transport reset without needing real socket options.
    struct FailingReader {
        delivered: bool,
    }

    impl Read for FailingReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.delivered {
                self.delivered = true;
                buf[..4].copy_from_slice(b"part");
                return Ok(4);
            }
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "SECRET-IO-DETAIL",
            ))
        }
    }

    // why: the read-failure mapping is the only stable answer to a transport
    // reset mid-body; it must stay a non-retryable 400 `invalid_request` with
    // a fixed message and must never echo the I/O error text, which can carry
    // local path or socket details. A regression to 500/retryable, a changed
    // code, or a message that leaks the source error fails this test.
    #[test]
    fn mid_body_read_failures_map_to_non_retryable_invalid_request() {
        let error = read_capped_body(FailingReader { delivered: false }).unwrap_err();
        assert_eq!(error.status, 400);
        assert_eq!(error.code, crate::web::CODE_INVALID_REQUEST);
        assert!(!error.retryable);
        assert_eq!(error.message, "The request body could not be read");
        assert!(!error.message.contains("SECRET-IO-DETAIL"));
    }

    // why: every response must carry exactly the pinned security and provenance
    // headers (no-store, nosniff, strict CSP, request id, contract and build
    // identity digests); dropping, reordering or corrupting any of them is a
    // silent contract break this pins.
    #[test]
    fn response_headers_pin_the_security_and_provenance_contract() {
        let headers = response_headers("req-1", "ca", "bi", "text/plain; charset=utf-8");
        let rendered: Vec<(String, String)> = headers
            .iter()
            .map(|header| {
                let header = header.as_ref().unwrap();
                (
                    header.field.as_str().to_string(),
                    header.value.as_str().to_string(),
                )
            })
            .collect();
        assert_eq!(
            rendered,
            vec![
                (
                    "Content-Type".to_string(),
                    "text/plain; charset=utf-8".to_string()
                ),
                ("Cache-Control".to_string(), "no-store".to_string()),
                ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
                (
                    "Content-Security-Policy".to_string(),
                    crate::web::WEB_CONTENT_SECURITY_POLICY.to_string(),
                ),
                ("X-Request-ID".to_string(), "req-1".to_string()),
                ("X-RR-API-Contract-SHA256".to_string(), "ca".to_string()),
                ("X-RR-Build-Identity-SHA256".to_string(), "bi".to_string()),
            ]
        );
    }

    // why: the response assembler must attach every header plus the exact
    // body and status on the normal path, and must fall back to the bare 500
    // "Internal response construction failure" carrying no half-built
    // headers when any header cannot be constructed — malformed header input
    // must never reach a client half-formed. This is the injectable form of
    // the former dead 500 arm in the server loop.
    #[test]
    fn finalize_response_applies_headers_or_falls_back_to_the_bare_500() {
        let ok = finalize_response(
            "{\"ok\":true}".to_string(),
            200,
            response_headers("req-1", "ca", "bi", "application/json"),
        );
        assert_eq!(ok.status_code().0, 200);
        assert_eq!(ok.headers().len(), 7);
        assert_eq!(ok.into_reader().into_inner(), b"{\"ok\":true}".to_vec());

        let broken = Header::from_bytes("X-Broken", "caf\u{e9}");
        assert!(broken.is_err(), "the probe header must be unbuildable");
        let fallback = finalize_response(
            "ignored".to_string(),
            200,
            vec![Header::from_bytes("X-Ok", "1"), broken],
        );
        assert_eq!(fallback.status_code().0, 500);
        assert!(
            !fallback
                .headers()
                .iter()
                .any(|header| header.field.equiv("X-Ok")),
            "the 500 fallback must carry no half-built headers"
        );
        assert_eq!(
            fallback.into_reader().into_inner(),
            b"Internal response construction failure".to_vec()
        );
    }

    // why: the embedded shell is what a browser navigates to; it must load
    // without the bearer token yet hold no data and stay behind the strict
    // CSP, while every data route keeps refusing token-less requests.
    #[test]
    fn web_page_is_an_unauthenticated_text_html_shell_but_data_stays_protected() {
        let (port, _receiver, stop) = serve(&"T".repeat(48));
        let client = crate::net::client(5, true).unwrap();
        let page = client
            .get(format!("http://127.0.0.1:{port}/"))
            .send()
            .unwrap();
        assert_eq!(page.status().as_u16(), 200);
        assert!(
            page.headers()
                .get(reqwest::header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        assert_csp(&page);
        let html = page.text().unwrap();
        assert!(html.contains("Rejection Rejector"));
        let data = client
            .get(format!("http://127.0.0.1:{port}/v1/status"))
            .send()
            .unwrap();
        assert_eq!(data.status().as_u16(), 401);
        stop.store(true, Ordering::SeqCst);
    }

    // why: a write without the exact bearer credential must be refused at
    // the wire; reaching the worker would mutate state from an
    // unauthenticated request.
    #[test]
    fn unauthorized_write_is_rejected_before_reaching_the_worker() {
        let (port, receiver, stop) = serve(&"T".repeat(48));
        let client = crate::net::client(5, true).unwrap();
        for auth in [
            None,
            Some("Bearer wrongwrongwrongwrongwrongwrongwrongwrongwrong"),
        ] {
            let mut request = client
                .post(format!("http://127.0.0.1:{port}/v1/commands/send"))
                .json(&serde_json::json!({
                    "id": "a".repeat(64),
                    "revision": 1,
                    "confirm_reply": "x"
                }));
            if let Some(value) = auth {
                request = request.header(reqwest::header::AUTHORIZATION, value);
            }
            let response = request.send().unwrap();
            assert_eq!(response.status().as_u16(), 401);
            assert_csp(&response);
            let body: serde_json::Value = response.json().unwrap();
            assert_eq!(body["error"]["code"], "unauthorized");
            assert_eq!(body["error"]["retryable"], false);
        }
        // why: the worker channel must still be empty — nothing was dispatched.
        assert!(receiver.try_recv().is_err());
        stop.store(true, Ordering::SeqCst);
    }

    // why: the body cap is the loopback listener's memory bound; an
    // oversized body must be refused on the wire before parsing or dispatch.
    #[test]
    fn oversized_write_body_is_rejected_at_the_wire_without_dispatch() {
        let (port, receiver, stop) = serve(&"T".repeat(48));
        let oversized = "x".repeat(crate::web::MAX_WRITE_BODY_BYTES + 1);
        let response = crate::net::client(5, true)
            .unwrap()
            .post(format!("http://127.0.0.1:{port}/v1/commands/edit-draft"))
            .bearer_auth("T".repeat(48))
            .body(oversized)
            .send()
            .unwrap();
        assert_eq!(response.status().as_u16(), 413);
        assert_csp(&response);
        let body: serde_json::Value = response.json().unwrap();
        assert_eq!(
            body["error"]["code"],
            crate::web::CODE_REQUEST_BODY_TOO_LARGE
        );
        assert!(receiver.try_recv().is_err());
        stop.store(true, Ordering::SeqCst);
    }

    // why: the write channel must dispatch exactly the mirrored worker
    // command and answer with the stable envelope (api_version, request_id,
    // typed operation status), never a bare ad-hoc body.
    #[test]
    fn write_round_trip_dispatches_the_mirrored_worker_command() {
        let (port, receiver, stop) = serve(&"T".repeat(48));
        let handle = std::thread::spawn(move || {
            match receiver.recv_timeout(Duration::from_secs(5)).unwrap() {
                Command::ApiWrite { request, reply } => {
                    assert_eq!(
                        request,
                        crate::web::WriteRequest::EditDraft {
                            id: "a".repeat(64),
                            revision: 2,
                            body: "Please reconsider this rejection.".into()
                        }
                    );
                    reply
                        .send(WriteOutcome::accepted_with(
                            serde_json::json!({"operation": {"kind": "edit_draft"}}),
                        ))
                        .unwrap();
                }
                _ => panic!("unexpected command for the write round-trip test"),
            }
        });
        let response = crate::net::client(5, true)
            .unwrap()
            .post(format!("http://127.0.0.1:{port}/v1/commands/edit-draft"))
            .bearer_auth("T".repeat(48))
            .json(&serde_json::json!({
                "id": "a".repeat(64),
                "revision": 2,
                "body": "Please reconsider this rejection."
            }))
            .send()
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        let body: serde_json::Value = response.json().unwrap();
        assert_eq!(body["api_version"], API_VERSION);
        assert_eq!(
            body["request_id"].as_str().unwrap().len(),
            "550e8400-e29b-41d4-a716-446655440000".len()
        );
        assert_eq!(body["accepted"], true);
        assert_eq!(body["operation"]["kind"], "edit_draft");
        handle.join().unwrap();
        stop.store(true, Ordering::SeqCst);
    }

    // why: gate rejections must reach the wire with their stable code so
    // clients can branch on it; a confirm-reply mismatch is never an opaque
    // 400.
    #[test]
    fn gate_rejections_keep_their_stable_codes_on_the_wire() {
        let (port, receiver, stop) = serve(&"T".repeat(48));
        let handle = std::thread::spawn(move || {
            match receiver.recv_timeout(Duration::from_secs(5)).unwrap() {
                Command::ApiWrite { reply, .. } => {
                    reply
                        .send(WriteOutcome::error(&crate::web::WriteError::reject(
                            409,
                            CODE_CONFIRM_REPLY_MISMATCH,
                            "The confirmed reply does not match the persisted draft byte for byte",
                        )))
                        .unwrap();
                }
                _ => panic!("unexpected command for the gate-rejection test"),
            }
        });
        let response = crate::net::client(5, true)
            .unwrap()
            .post(format!("http://127.0.0.1:{port}/v1/commands/send"))
            .bearer_auth("T".repeat(48))
            .json(&serde_json::json!({
                "id": "a".repeat(64),
                "revision": 1,
                "confirm_reply": "not the persisted draft"
            }))
            .send()
            .unwrap();
        assert_eq!(response.status().as_u16(), 409);
        assert_csp(&response);
        let body: serde_json::Value = response.json().unwrap();
        assert_eq!(body["error"]["code"], "confirm_reply_mismatch");
        assert_eq!(body["error"]["retryable"], false);
        handle.join().unwrap();
        stop.store(true, Ordering::SeqCst);
    }

    // why: CSP is contractual on every response class (page, error, method
    // rejection, size rejection, read success) — one missing header would
    // reopen inline/remote content loading for the embedded page.
    #[test]
    fn content_security_policy_is_present_on_every_response() {
        let (port, receiver, stop) = serve(&"T".repeat(48));
        let client = crate::net::client(5, true).unwrap();
        let token = "T".repeat(48);
        let probes = [
            client
                .get(format!("http://127.0.0.1:{port}/"))
                .send()
                .unwrap(),
            client
                .get(format!("http://127.0.0.1:{port}/v1/status"))
                .send()
                .unwrap(),
            client
                .get(format!("http://127.0.0.1:{port}/v1/live"))
                .bearer_auth(&token)
                .send()
                .unwrap(),
            client
                .post(format!("http://127.0.0.1:{port}/v1/status"))
                .bearer_auth(&token)
                .send()
                .unwrap(),
            client
                .get(format!("http://127.0.0.1:{port}/v1/commands/send"))
                .bearer_auth(&token)
                .send()
                .unwrap(),
            client
                .get(format!("http://127.0.0.1:{port}/unknown"))
                .bearer_auth(&token)
                .send()
                .unwrap(),
        ];
        for response in &probes {
            assert_csp(response);
        }
        assert_eq!(probes[0].status().as_u16(), 200);
        assert_eq!(probes[1].status().as_u16(), 401);
        assert_eq!(probes[2].status().as_u16(), 200);
        assert_eq!(probes[3].status().as_u16(), 405);
        assert_eq!(probes[4].status().as_u16(), 405);
        assert_eq!(probes[5].status().as_u16(), 404);
        assert!(receiver.try_recv().is_err());
        stop.store(true, Ordering::SeqCst);
    }

    // why: the Origin policy is the CSRF boundary. A cross-site write must
    // die at the wire even with a stolen-looking token, the embedded page's
    // own same-origin writes must pass, and reads keep refusing every Origin.
    #[test]
    fn origin_policy_refuses_cross_site_writes_but_allows_same_origin_page_writes() {
        let (port, receiver, stop) = serve(&"T".repeat(48));
        let client = crate::net::client(5, true).unwrap();
        let token = "T".repeat(48);
        let cross = client
            .post(format!("http://127.0.0.1:{port}/v1/commands/dismiss"))
            .bearer_auth(&token)
            .header("Origin", "http://evil.example")
            .json(&serde_json::json!({"id": "a".repeat(64), "revision": 1}))
            .send()
            .unwrap();
        assert_eq!(cross.status().as_u16(), 401);
        assert!(receiver.try_recv().is_err());
        let read_with_origin = client
            .get(format!("http://127.0.0.1:{port}/v1/status"))
            .bearer_auth(&token)
            .header("Origin", "http://evil.example")
            .send()
            .unwrap();
        assert_eq!(read_with_origin.status().as_u16(), 401);
        // The responder must run concurrently: the server waits for the
        // worker reply before it answers the same-origin write.
        let handle = std::thread::spawn(move || {
            match receiver.recv_timeout(Duration::from_secs(5)).unwrap() {
                Command::ApiWrite {
                    request: crate::web::WriteRequest::Dismiss { revision, .. },
                    reply,
                } => {
                    assert_eq!(revision, 1);
                    reply
                        .send(WriteOutcome::accepted_with(serde_json::json!({})))
                        .unwrap();
                }
                _ => panic!("unexpected command for the origin-policy test"),
            }
        });
        let same_origin = client
            .post(format!("http://127.0.0.1:{port}/v1/commands/dismiss"))
            .bearer_auth(&token)
            .header("Origin", format!("http://127.0.0.1:{port}"))
            .json(&serde_json::json!({"id": "a".repeat(64), "revision": 1}))
            .send()
            .unwrap();
        assert_eq!(same_origin.status().as_u16(), 200);
        handle.join().unwrap();
        stop.store(true, Ordering::SeqCst);
    }

    // why: reads stay read-only and write routes stay POST-only; a method
    // mix-up must fail loudly instead of half-working.
    #[test]
    fn method_polarity_is_enforced_for_reads_and_writes() {
        let (port, receiver, stop) = serve(&"T".repeat(48));
        let client = crate::net::client(5, true).unwrap();
        let token = "T".repeat(48);
        let post_read = client
            .post(format!("http://127.0.0.1:{port}/v1/status"))
            .bearer_auth(&token)
            .send()
            .unwrap();
        assert_eq!(post_read.status().as_u16(), 405);
        let body: serde_json::Value = post_read.json().unwrap();
        assert_eq!(body["error"]["code"], CODE_METHOD_NOT_ALLOWED);
        let get_write = client
            .get(format!("http://127.0.0.1:{port}/v1/commands/send"))
            .bearer_auth(&token)
            .send()
            .unwrap();
        assert_eq!(get_write.status().as_u16(), 405);
        let body: serde_json::Value = get_write.json().unwrap();
        assert_eq!(body["error"]["code"], CODE_METHOD_NOT_ALLOWED);
        assert!(receiver.try_recv().is_err());
        stop.store(true, Ordering::SeqCst);
    }
    #[test]
    fn rate_limiter_bounds_bursts_and_refills_deterministically() {
        let start = Instant::now();
        let mut limiter = RateLimiter::new(start);
        for _ in 0..API_RATE_LIMIT_BURST {
            assert!(limiter.allow(start));
        }
        assert!(!limiter.allow(start));
        assert!(!limiter.allow(start + Duration::from_millis(499)));
        assert!(limiter.allow(start + Duration::from_millis(500)));
        assert!(!limiter.allow(start + Duration::from_millis(500)));
        assert!(limiter.allow(start + Duration::from_secs(1)));
    }

    #[test]
    fn duplicate_sensitive_headers_are_not_unique() {
        let headers = vec![
            Header::from_bytes("Authorization", "Bearer one").unwrap(),
            Header::from_bytes("Authorization", "Bearer two").unwrap(),
            Header::from_bytes("Host", "127.0.0.1:8734").unwrap(),
        ];
        assert!(unique_header(&headers, "Authorization").is_none());
        assert_eq!(unique_header(&headers, "Host"), Some("127.0.0.1:8734"));
    }

    #[test]
    fn direct_liveness_and_openapi_routes_are_self_contained() {
        let pulse = WorkerPulse::new();
        let live = direct_get("/v1/live", &pulse).unwrap();
        assert_eq!(live["live"], true);
        assert_eq!(live["api_thread_live"], true);
        assert_eq!(live["worker_responsive"], true);
        assert_eq!(live["worker"]["schema_version"], 1);
        assert_eq!(live["api_version"], API_VERSION);
        assert_eq!(live["api_contract_sha256"].as_str().unwrap().len(), 64);
        assert_eq!(live["build"]["identity_sha256"].as_str().unwrap().len(), 64);
        assert_eq!(openapi_sha256().len(), 64);
        assert!(
            openapi_sha256()
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );

        let spec = direct_get("/v1/openapi.json", &pulse).unwrap();
        assert_eq!(spec["openapi"], "3.1.0");
        assert!(spec["paths"]["/v1/health"].is_object());
        assert!(spec["paths"]["/v1/audit/anchor"].is_object());
        assert!(spec["components"]["schemas"]["OperationStatus"].is_object());
        assert!(
            spec["components"]["schemas"]["OperationStatus"]["properties"]["operation_id"]
                .is_object()
        );
        assert!(direct_get("/v1/unknown", &pulse).is_none());
    }

    #[test]
    fn openmetrics_route_uses_real_authenticated_wire_contract() {
        let token = "T".repeat(48);
        let (commands, receiver) = bounded(4);
        let stop = Arc::new(AtomicBool::new(false));
        let disabled = Arc::new(AtomicBool::new(false));
        let responder = std::thread::spawn(move || {
            let command = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
            match command {
                Command::OpenMetrics { reply } => {
                    reply
                        .send(
                            "# TYPE rejection_rejector_up gauge\nrejection_rejector_up 1\n# EOF\n"
                                .into(),
                        )
                        .unwrap();
                }
                _ => panic!("unexpected command for OpenMetrics test"),
            }
        });

        let port = start(
            0,
            token.clone(),
            commands,
            stop.clone(),
            disabled,
            WorkerPulse::new(),
        )
        .unwrap();

        let response = crate::net::client(5, true)
            .unwrap()
            .get(format!("http://127.0.0.1:{port}/v1/metrics/openmetrics"))
            .bearer_auth(&token)
            .send()
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(
            response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            OPENMETRICS_CONTENT_TYPE
        );
        let body = response.text().unwrap();
        assert!(body.ends_with("# EOF\n"));
        assert!(body.contains("rejection_rejector_up 1\n"));

        stop.store(true, Ordering::SeqCst);
        responder.join().unwrap();
    }

    #[test]
    fn metric_content_types_are_explicit_and_prometheus_compatible() {
        assert_eq!(JSON_CONTENT_TYPE, "application/json; charset=utf-8");
        assert_eq!(
            OPENMETRICS_CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0; charset=utf-8"
        );
    }

    #[test]
    fn error_envelope_has_stable_machine_readable_fields() {
        let body = error_body("worker_busy", "Synthetic", true, "request-123");
        assert_eq!(body["api_version"], API_VERSION);
        assert_eq!(body["request_id"], "request-123");
        assert_eq!(body["error"]["code"], "worker_busy");
        assert_eq!(body["error"]["retryable"], true);
        assert_eq!(body["error"]["message"], "Synthetic");
    }

    #[test]
    fn exact_bearer_required() {
        let verifier = ApiTokenVerifier::from_token(&"correct".repeat(8)).unwrap();
        let token = "correct".repeat(8);
        assert!(authorized(Some(&format!("Bearer {token}")), &verifier));
        for value in [
            None,
            Some(token.as_str()),
            Some("Bearer wrongwrongwrongwrongwrongwrongwrongwrongwrong"),
            Some("Bearer correctcorrectcorrectcorrectcorrectcorrectcorrectcorrect "),
        ] {
            assert!(!authorized(value, &verifier));
        }
    }

    /// Bind the real API server with an explicit worker-channel capacity so
    /// queue-full (`worker_busy`) paths are reachable with an unanswered
    /// worker role.
    ///
    /// Inputs: `token` — bearer credential; `capacity` — command-queue slots.
    /// Output: `(port, receiver, stop)` like [`serve`].
    fn serve_cap(token: &str, capacity: usize) -> (u16, Receiver<Command>, Arc<AtomicBool>) {
        let (commands, receiver) = bounded(capacity);
        let stop = Arc::new(AtomicBool::new(false));
        let port = start(
            0,
            token.into(),
            commands,
            stop.clone(),
            Arc::new(AtomicBool::new(false)),
            WorkerPulse::new(),
        )
        .unwrap();
        (port, receiver, stop)
    }

    /// Perform one raw HTTP/1.1 exchange against the loopback API.
    ///
    /// Inputs: `port` — bound API port; `request` — full raw request bytes.
    /// Output: the raw response text (headers included).
    fn raw_exchange(port: u16, request: &str) -> String {
        use std::io::{Read, Write};
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        response
    }

    // why: the bearer credential is the only gate between the loopback port
    // and the worker; malformed authorization headers (wrong scheme case,
    // missing token, scheme-less values, duplicated headers that become
    // ambiguous) must all land in the same 401 envelope instead of some
    // silently matching prefix.
    #[test]
    fn malformed_bearer_headers_are_refused_on_the_wire() {
        let token = "T".repeat(48);
        let (port, receiver, stop) = serve(&token);
        let client = crate::net::client(5, true).unwrap();
        for value in [
            format!("bearer {token}"),
            "Bearer".to_string(),
            "Bearer ".to_string(),
            format!("Bearer\t{token}"),
            format!("Bearer  {token}"),
            format!("Basic {token}"),
            token.clone(),
        ] {
            let response = client
                .get(format!("http://127.0.0.1:{port}/v1/status"))
                .header(reqwest::header::AUTHORIZATION, value.as_str())
                .send()
                .unwrap();
            assert_eq!(response.status().as_u16(), 401, "{value:?}");
        }
        // Two Authorization headers are ambiguous and must authenticate nobody.
        let response = client
            .get(format!("http://127.0.0.1:{port}/v1/status"))
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
            .send()
            .unwrap();
        assert_eq!(response.status().as_u16(), 401);
        assert!(receiver.try_recv().is_err());
        stop.store(true, Ordering::SeqCst);
    }

    // why: the accept loop polls in 250 ms slices; if a quiet period made it
    // exit instead of continue, the API would die a quarter second after the
    // last request and every later request would hang on a closed listener.
    #[test]
    fn idle_accept_loop_survives_quiet_periods() {
        let (port, receiver, stop) = serve(&"T".repeat(48));
        std::thread::sleep(Duration::from_millis(700));
        let response = crate::net::client(5, true)
            .unwrap()
            .get(format!("http://127.0.0.1:{port}/v1/live"))
            .bearer_auth("T".repeat(48))
            .send()
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        assert!(receiver.try_recv().is_err());
        stop.store(true, Ordering::SeqCst);
    }

    // why: the rate limiter is the only backstop against a runaway local
    // client; the bounded burst must surface as a stable `rate_limited`
    // envelope on the wire, not as silently dropped or queued requests.
    #[test]
    fn wire_requests_over_the_burst_are_rate_limited() {
        let (port, _receiver, stop) = serve(&"T".repeat(48));
        let client = crate::net::client(10, true).unwrap();
        let mut limited = None;
        for _ in 0..(API_RATE_LIMIT_BURST + 2) {
            let response = client
                .get(format!("http://127.0.0.1:{port}/v1/live"))
                .bearer_auth("T".repeat(48))
                .send()
                .unwrap();
            if response.status().as_u16() == 429 {
                limited = Some(response);
                break;
            }
        }
        let response = limited.expect("the burst ceiling must trigger 429 on the wire");
        assert_csp(&response);
        let body: serde_json::Value = response.json().unwrap();
        assert_eq!(body["error"]["code"], "rate_limited");
        assert_eq!(body["error"]["retryable"], true);
        stop.store(true, Ordering::SeqCst);
    }

    // why: with a wedged (never-answering) worker the API must stay
    // fail-closed and bounded: an unanswered read times out into
    // `worker_timeout`, and once the command queue is full every further
    // dispatch attempt (write or metrics) must fail fast as `worker_busy`
    // instead of buffering unbounded work or hanging the HTTP client.
    #[test]
    fn wedged_worker_yields_busy_and_timeout_envelopes() {
        let (port, _receiver, stop) = serve_cap(&"T".repeat(48), 1);
        let client = crate::net::client(10, true).unwrap();
        let token = "T".repeat(48);
        // Fills the single command slot and waits out the read deadline.
        let late = client
            .get(format!("http://127.0.0.1:{port}/v1/status"))
            .bearer_auth(&token)
            .send()
            .unwrap();
        assert_eq!(late.status().as_u16(), 503);
        let body: serde_json::Value = late.json().unwrap();
        assert_eq!(body["error"]["code"], "worker_timeout");
        assert_eq!(body["error"]["retryable"], true);
        // Queue full: writes must fail fast without waiting the write deadline.
        let write = client
            .post(format!("http://127.0.0.1:{port}/v1/commands/dismiss"))
            .bearer_auth(&token)
            .json(&serde_json::json!({"id": "a".repeat(64), "revision": 1}))
            .send()
            .unwrap();
        assert_eq!(write.status().as_u16(), 503);
        let body: serde_json::Value = write.json().unwrap();
        assert_eq!(body["error"]["code"], "worker_busy");
        assert_eq!(body["error"]["retryable"], true);
        // Metrics dispatches are bounded the same way.
        let metrics = client
            .get(format!("http://127.0.0.1:{port}/v1/metrics/openmetrics"))
            .bearer_auth(&token)
            .send()
            .unwrap();
        assert_eq!(metrics.status().as_u16(), 503);
        let body: serde_json::Value = metrics.json().unwrap();
        assert_eq!(body["error"]["code"], "worker_busy");
        // Read dispatches fail fast against the full queue too — they must
        // never block waiting for a slot behind wedged work.
        let read = client
            .get(format!("http://127.0.0.1:{port}/v1/status"))
            .bearer_auth(&token)
            .send()
            .unwrap();
        assert_eq!(read.status().as_u16(), 503);
        let body: serde_json::Value = read.json().unwrap();
        assert_eq!(body["error"]["code"], "worker_busy");
        stop.store(true, Ordering::SeqCst);
    }

    // why: a worker reply carrying an `error` field is an application-level
    // rejection and must surface as the stable 400 `invalid_request` envelope,
    // while a data reply is forwarded verbatim — swapping these would either
    // hide real errors behind 200s or break valid reads.
    #[test]
    fn worker_replies_shape_read_outcomes() {
        let token = "T".repeat(48);
        // Error payload -> 400.
        let (port, receiver, stop) = serve(&token);
        let handle =
            std::thread::spawn(
                move || match receiver.recv_timeout(Duration::from_secs(5)) {
                    Ok(Command::Api { reply, .. }) => {
                        reply
                            .send(serde_json::json!({"error": "unknown item"}))
                            .unwrap();
                    }
                    _ => panic!("unexpected command"),
                },
            );
        let response = crate::net::client(5, true)
            .unwrap()
            .get(format!("http://127.0.0.1:{port}/v1/status"))
            .bearer_auth(&token)
            .send()
            .unwrap();
        assert_eq!(response.status().as_u16(), 400);
        let body: serde_json::Value = response.json().unwrap();
        assert_eq!(body["error"]["code"], "invalid_request");
        assert_eq!(body["error"]["retryable"], false);
        handle.join().unwrap();
        stop.store(true, Ordering::SeqCst);

        // Data payload -> 200 verbatim.
        let (port, receiver, stop) = serve(&token);
        let handle =
            std::thread::spawn(
                move || match receiver.recv_timeout(Duration::from_secs(5)) {
                    Ok(Command::Api { reply, path }) => {
                        assert_eq!(path, "/v1/status");
                        reply.send(serde_json::json!({"items": [1, 2]})).unwrap();
                    }
                    _ => panic!("unexpected command"),
                },
            );
        let response = crate::net::client(5, true)
            .unwrap()
            .get(format!("http://127.0.0.1:{port}/v1/status"))
            .bearer_auth(&token)
            .send()
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        let body: serde_json::Value = response.json().unwrap();
        assert_eq!(body["items"], serde_json::json!([1, 2]));
        handle.join().unwrap();
        stop.store(true, Ordering::SeqCst);
    }

    // why: openmetrics output must carry the Prometheus content type (a
    // scraper refuses other types) and must answer with the worker's text.
    #[test]
    fn openmetrics_replies_use_the_prometheus_content_type() {
        let token = "T".repeat(48);
        let (port, receiver, stop) = serve(&token);
        let handle =
            std::thread::spawn(
                move || match receiver.recv_timeout(Duration::from_secs(5)) {
                    Ok(Command::OpenMetrics { reply }) => {
                        reply.send("# TYPE rr_up gauge\nrr_up 1\n".into()).unwrap();
                    }
                    _ => panic!("unexpected command"),
                },
            );
        let response = crate::net::client(5, true)
            .unwrap()
            .get(format!("http://127.0.0.1:{port}/v1/metrics/openmetrics"))
            .bearer_auth(&token)
            .send()
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(
            response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            OPENMETRICS_CONTENT_TYPE
        );
        assert!(response.text().unwrap().contains("rr_up 1"));
        handle.join().unwrap();
        stop.store(true, Ordering::SeqCst);
    }

    // why: an unanswered metrics dispatch must degrade to the stable
    // `worker_timeout` envelope within the read deadline instead of hanging
    // the scraper forever.
    #[test]
    fn unanswered_openmetrics_times_out_with_a_stable_envelope() {
        let (port, _receiver, stop) = serve_cap(&"T".repeat(48), 1);
        let response = crate::net::client(10, true)
            .unwrap()
            .get(format!("http://127.0.0.1:{port}/v1/metrics/openmetrics"))
            .bearer_auth("T".repeat(48))
            .send()
            .unwrap();
        assert_eq!(response.status().as_u16(), 503);
        let body: serde_json::Value = response.json().unwrap();
        assert_eq!(body["error"]["code"], "worker_timeout");
        stop.store(true, Ordering::SeqCst);
    }

    // why: the stream cap is what bounds listener memory when a client lies
    // about (or omits) Content-Length; a chunked body over the cap must stop
    // at `MAX_WRITE_BODY_BYTES + 1` and answer 413, while a body of exactly
    // the cap must reach the parser (and fail there on its own merits).
    #[test]
    fn chunked_bodies_are_capped_by_the_stream_limit() {
        let token = "T".repeat(48);
        let (port, receiver, stop) = serve_cap(&token, 1);
        let header = format!(
            "POST /v1/commands/edit-draft HTTP/1.1\r\n\
             Host: 127.0.0.1:{port}\r\n\
             Authorization: Bearer {token}\r\n\
             Content-Type: application/json\r\n\
             Transfer-Encoding: chunked\r\n\r\n"
        );
        let chunk_of = |size: usize| format!("{:x}\r\n{}\r\n", size, "x".repeat(size));
        // Exactly the cap: the parser sees it (garbage JSON -> invalid_request).
        let exact = format!(
            "{header}{}0\r\n\r\n",
            chunk_of(crate::web::MAX_WRITE_BODY_BYTES)
        );
        let response = raw_exchange(port, &exact);
        assert!(
            response.contains(" 400 ") && response.contains("invalid_request"),
            "exact-cap body must reach the parser"
        );
        assert!(!response.contains("request_body_too_large"));
        // One byte over the cap: stopped at the stream limit, never dispatched.
        let over = format!(
            "{header}{}0\r\n\r\n",
            chunk_of(crate::web::MAX_WRITE_BODY_BYTES + 1)
        );
        let response = raw_exchange(port, &over);
        assert!(
            response.contains(" 413 ") && response.contains("request_body_too_large"),
            "over-cap body must be refused"
        );
        assert!(receiver.try_recv().is_err());
        stop.store(true, Ordering::SeqCst);
    }

    // why: the write contract is application/json; a body announced as any
    // other type must be refused before parsing or dispatch, while the same
    // body under the JSON content type (including parameters and case
    // variations) proceeds to the worker gates.
    #[test]
    fn writes_reject_non_json_content_types() {
        let token = "T".repeat(48);
        let (port, receiver, stop) = serve_cap(&token, 1);
        let client = crate::net::client(5, true).unwrap();
        let payload = serde_json::json!({"id": "a".repeat(64), "revision": 1});
        for wrong in ["text/plain", "application/x-www-form-urlencoded", ""] {
            let response = client
                .post(format!("http://127.0.0.1:{port}/v1/commands/dismiss"))
                .bearer_auth(&token)
                .header(reqwest::header::CONTENT_TYPE, wrong)
                .body(payload.to_string())
                .send()
                .unwrap();
            assert_eq!(response.status().as_u16(), 400, "{wrong:?}");
            let body: serde_json::Value = response.json().unwrap();
            assert_eq!(body["error"]["code"], "invalid_request");
        }
        assert!(receiver.try_recv().is_err());
        stop.store(true, Ordering::SeqCst);

        // Accepted variants reach the worker (queue-full proves dispatch).
        for good in [
            "application/json",
            "application/json; charset=utf-8",
            "APPLICATION/JSON",
        ] {
            let (port, receiver, stop) = serve_cap(&token, 1);
            let client = crate::net::client(5, true).unwrap();
            // Occupy the queue so the accepted write fails as busy, not 400.
            let _late = client
                .get(format!("http://127.0.0.1:{port}/v1/status"))
                .bearer_auth(&token)
                .send()
                .unwrap();
            let response = client
                .post(format!("http://127.0.0.1:{port}/v1/commands/dismiss"))
                .bearer_auth(&token)
                .header(reqwest::header::CONTENT_TYPE, good)
                .body(payload.to_string())
                .send()
                .unwrap();
            assert_eq!(response.status().as_u16(), 503, "{good:?}");
            let body: serde_json::Value = response.json().unwrap();
            assert_eq!(body["error"]["code"], "worker_busy");
            drop(receiver);
            stop.store(true, Ordering::SeqCst);
        }
    }

    // why: a write dispatched to a worker that never answers must release the
    // request at the fixed local deadline with the stable `worker_timeout`
    // envelope — the write CAS outcome stays with the worker, but the HTTP
    // surface must never hold the connection open indefinitely.
    #[test]
    fn unanswered_writes_time_out_with_a_stable_envelope() {
        let (port, _receiver, stop) = serve_cap(&"T".repeat(48), 1);
        let response = crate::net::client(WRITE_REPLY_TIMEOUT.as_secs() + 10, true)
            .unwrap()
            .post(format!("http://127.0.0.1:{port}/v1/commands/dismiss"))
            .bearer_auth("T".repeat(48))
            .json(&serde_json::json!({"id": "a".repeat(64), "revision": 1}))
            .send()
            .unwrap();
        assert_eq!(response.status().as_u16(), 503);
        let body: serde_json::Value = response.json().unwrap();
        assert_eq!(body["error"]["code"], "worker_timeout");
        assert_eq!(body["error"]["retryable"], true);
        stop.store(true, Ordering::SeqCst);
    }
}
