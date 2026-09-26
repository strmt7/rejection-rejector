//! Loopback-only HTTP fault tests. No external network or secrets.
use rejection_rejector::net;
use serde::Deserialize;
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
};

fn response(raw: String) -> reqwest::blocking::Response {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut request = [0; 4096];
        let _ = stream.read(&mut request);
        let _ = stream.write_all(raw.as_bytes());
    });
    let result = net::client(5, true)
        .unwrap()
        .get(format!("http://{addr}/fixture"))
        .send()
        .unwrap();
    server.join().unwrap();
    result
}
fn wire(status: &str, body: &str, headers: &str) -> String {
    format!("HTTP/1.1 {status}\r\nConnection: close\r\n{headers}\r\n{body}")
}
#[test]
fn bounded_valid_json_decodes() {
    let r = response(wire("200 OK", "{\"ok\":true}", "Content-Length: 11\r\n"));
    assert_eq!(net::json::<serde_json::Value>(r, 100).unwrap()["ok"], true);
}
#[test]
fn large_unknown_length_body_is_rejected() {
    let r = response(wire("200 OK", &"x".repeat(1000), ""));
    assert!(net::json::<serde_json::Value>(r, 32).is_err());
}
#[test]
fn large_declared_length_is_rejected() {
    let r = response(wire(
        "200 OK",
        &"x".repeat(1000),
        "Content-Length: 1000\r\n",
    ));
    assert!(net::json::<serde_json::Value>(r, 32).is_err());
}
#[test]
fn redirect_is_returned_not_followed() {
    let r = response(wire(
        "302 Found",
        "",
        "Location: http://127.0.0.1:1/never-connect\r\nContent-Length: 0\r\n",
    ));
    assert_eq!(r.status().as_u16(), 302);
}
#[test]
fn error_body_is_not_in_error_chain() {
    let r = response(wire(
        "403 Forbidden",
        "PRIVATE_SENTINEL",
        "Content-Length: 16\r\n",
    ));
    let err = net::json::<serde_json::Value>(r, 100).unwrap_err();
    assert!(!format!("{err:#}").contains("PRIVATE_SENTINEL"));
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Number {
    value: u32,
}
#[test]
fn json_type_error_does_not_echo_private_value() {
    let r = response(wire("200 OK", "{\"value\":\"PRIVATE_SENTINEL\"}", ""));
    let err = net::json::<Number>(r, 100).unwrap_err();
    assert!(!format!("{err:#}").contains("PRIVATE_SENTINEL"));
}
