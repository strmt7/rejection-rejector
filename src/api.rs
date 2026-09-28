use crate::worker::{Command, WorkerPulse};
use anyhow::{Result, ensure};
use chrono::Utc;
use crossbeam_channel::{Sender, bounded};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tiny_http::{Header, Method, Response, Server};
use zeroize::Zeroizing;

pub const API_VERSION: u32 = 1;
pub const OPENAPI_DOCUMENT: &str = include_str!("../docs/openapi-v1.json");
pub const JSON_CONTENT_TYPE: &str = "application/json; charset=utf-8";
pub const OPENMETRICS_CONTENT_TYPE: &str =
    "application/openmetrics-text; version=1.0.0; charset=utf-8";
pub const API_RATE_LIMIT_BURST: u32 = 30;
pub const API_RATE_LIMIT_PER_SECOND: f64 = 2.0;

#[derive(Clone, Debug)]
struct RateLimiter {
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    fn new(now: Instant) -> Self {
        Self {
            tokens: f64::from(API_RATE_LIMIT_BURST),
            last: now,
        }
    }

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

pub fn openapi_sha256() -> String {
    format!("{:x}", Sha256::digest(OPENAPI_DOCUMENT.as_bytes()))
}

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

fn authorized(value: Option<&str>, token: &str) -> bool {
    let expected = format!("Bearer {token}");
    value
        .unwrap_or("")
        .as_bytes()
        .ct_eq(expected.as_bytes())
        .unwrap_u8()
        == 1
}
/// Explicitly read-only. No CORS, literal loopback Host, bearer token, no browser Origin.
pub fn start(
    port: u16,
    token: String,
    commands: Sender<Command>,
    stop: Arc<AtomicBool>,
    disabled: Arc<AtomicBool>,
    pulse: WorkerPulse,
) -> Result<()> {
    ensure!(token.len() >= 40, "API token lacks required entropy");
    let token = Zeroizing::new(token);
    let contract_sha256 = openapi_sha256();
    let build_identity_sha256 = crate::build_info::identity_sha256();
    let server = Server::http(format!("127.0.0.1:{port}"))
        .map_err(|e| anyhow::anyhow!("Cannot bind loopback API: {e}"))?;
    std::thread::spawn(move || {
        let mut rate_limiter = RateLimiter::new(Instant::now());
        while !stop.load(Ordering::SeqCst) && !disabled.load(Ordering::SeqCst) {
            let request = match server.recv_timeout(Duration::from_millis(250)) {
                Ok(Some(r)) => r,
                Ok(None) => continue,
                Err(_) => break,
            };
            let request_id = uuid::Uuid::new_v4().to_string();
            let auth = unique_header(request.headers(), "Authorization");
            let host = unique_header(request.headers(), "Host");
            let origin = request.headers().iter().any(|h| h.field.equiv("Origin"));
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
            } else if !authorized(auth, token.as_str())
                || host != Some(format!("127.0.0.1:{port}").as_str())
                || origin
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
            let response = Response::from_string(body)
                .with_status_code(status)
                .with_header(
                    Header::from_bytes("Content-Type", content_type).expect("constant header"),
                )
                .with_header(
                    Header::from_bytes("Cache-Control", "no-store").expect("constant header"),
                )
                .with_header(
                    Header::from_bytes("X-Content-Type-Options", "nosniff")
                        .expect("constant header"),
                )
                .with_header(
                    Header::from_bytes("X-Request-ID", request_id.as_bytes())
                        .expect("UUID request ID is valid header content"),
                )
                .with_header(
                    Header::from_bytes("X-RR-API-Contract-SHA256", contract_sha256.as_bytes())
                        .expect("SHA-256 contract fingerprint is valid header content"),
                )
                .with_header(
                    Header::from_bytes(
                        "X-RR-Build-Identity-SHA256",
                        build_identity_sha256.as_bytes(),
                    )
                    .expect("SHA-256 build fingerprint is valid header content"),
                );
            let _ = request.respond(response);
        }
    });
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
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
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

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

        start(
            port,
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
        assert!(authorized(Some("Bearer correct"), "correct"));
        for v in [
            None,
            Some("correct"),
            Some("Bearer wrong"),
            Some("Bearer correct "),
        ] {
            assert!(!authorized(v, "correct"));
        }
    }
}
