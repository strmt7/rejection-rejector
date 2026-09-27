use crate::worker::Command;
use anyhow::{Result, ensure};
use crossbeam_channel::{Sender, bounded};
use serde_json::json;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use subtle::ConstantTimeEq;
use tiny_http::{Header, Method, Response, Server};
use zeroize::Zeroizing;

pub const API_VERSION: u32 = 1;
pub const OPENAPI_DOCUMENT: &str = include_str!("../docs/openapi-v1.json");

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

fn direct_get(path: &str) -> Option<serde_json::Value> {
    match path {
        "/v1/live" => Some(json!({
            "live": true,
            "api_version": API_VERSION,
            "application_version": env!("CARGO_PKG_VERSION")
        })),
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
) -> Result<()> {
    ensure!(token.len() >= 40, "API token lacks required entropy");
    let token = Zeroizing::new(token);
    let server = Server::http(format!("127.0.0.1:{port}"))
        .map_err(|e| anyhow::anyhow!("Cannot bind loopback API: {e}"))?;
    std::thread::spawn(move || {
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
            let (status, body) = if !authorized(auth, token.as_str())
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
                    ),
                )
            } else if request.method() != &Method::Get {
                (
                    405,
                    error_body(
                        "method_not_allowed",
                        "The integration API is read-only",
                        false,
                        &request_id,
                    ),
                )
            } else if request.url().len() > 2000 || !request.url().starts_with("/v1/") {
                (
                    404,
                    error_body("route_not_found", "Unknown API route", false, &request_id),
                )
            } else if let Some(body) = direct_get(request.url()) {
                (200, body)
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
                        ),
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
                            ),
                        ),
                        Ok(data) => (200, data),
                        Err(_) => (
                            503,
                            error_body(
                                "worker_timeout",
                                "The worker did not answer before the local API deadline",
                                true,
                                &request_id,
                            ),
                        ),
                    }
                }
            };
            let response = Response::from_string(body.to_string())
                .with_status_code(status)
                .with_header(
                    Header::from_bytes("Content-Type", "application/json; charset=utf-8")
                        .expect("constant header"),
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
        let live = direct_get("/v1/live").unwrap();
        assert_eq!(live["live"], true);
        assert_eq!(live["api_version"], API_VERSION);

        let spec = direct_get("/v1/openapi.json").unwrap();
        assert_eq!(spec["openapi"], "3.1.0");
        assert!(spec["paths"]["/v1/health"].is_object());
        assert!(spec["paths"]["/v1/audit/anchor"].is_object());
        assert!(direct_get("/v1/unknown").is_none());
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
