//! Bounded, inert HTTP parsing for the temporary loopback OAuth listener.
use anyhow::{Context, Result, ensure};
use std::{
    io::{ErrorKind, Read},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};
use zeroize::Zeroizing;

const MAX_HEADER_BYTES: usize = 8192;

/// The caller must bound each blocking read (the TCP caller uses 250 ms).
/// A per-connection absolute deadline prevents a slow stream from renewing a
/// per-read timeout indefinitely. Never accept an incomplete header block.
pub(super) fn read_headers(
    reader: &mut impl Read,
    cancelled: &AtomicBool,
    deadline: Instant,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new([0u8; 1024]);
    loop {
        ensure!(!cancelled.load(Ordering::SeqCst), "Authorization cancelled");
        ensure!(Instant::now() < deadline, "OAuth callback deadline exceeded");
        ensure!(
            bytes.len() < MAX_HEADER_BYTES,
            "OAuth callback headers are too large"
        );
        let remaining = (MAX_HEADER_BYTES - bytes.len()).min(chunk.len());
        match reader.read(&mut chunk[..remaining]) {
            Ok(0) => anyhow::bail!("Incomplete OAuth callback request"),
            Ok(count) => bytes.extend_from_slice(&chunk[..count]),
            Err(error) => ensure!(
                matches!(
                    error.kind(),
                    ErrorKind::Interrupted | ErrorKind::TimedOut | ErrorKind::WouldBlock
                ),
                "Cannot read OAuth callback request"
            ),
        }
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            bytes.truncate(end + 4);
            return Ok(bytes);
        }
    }
}

/// Parse only a GET with a unique literal-loopback Host and no request body.
pub(super) fn request_target(headers: &[u8], port: u16) -> Result<&str> {
    ensure!(
        headers.len() <= MAX_HEADER_BYTES && headers.ends_with(b"\r\n\r\n"),
        "Invalid OAuth callback header block"
    );
    let text = std::str::from_utf8(headers).context("Invalid OAuth callback encoding")?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    let first = lines
        .next()
        .context("OAuth callback request line is missing")?;
    let parts: Vec<_> = first.split(' ').collect();
    ensure!(
        parts.len() == 3
            && parts[0] == "GET"
            && matches!(parts[2], "HTTP/1.1" | "HTTP/1.0")
            && parts[1].starts_with('/')
            && !parts[1].starts_with("//")
            && !parts[1].contains('#')
            && !parts[1].chars().any(char::is_control),
        "Invalid OAuth callback request line"
    );
    let expected_host = format!("127.0.0.1:{port}");
    let mut hosts = 0;
    let mut lengths = 0;
    for line in lines {
        ensure!(
            !line.starts_with([' ', '\t']) && !line.contains(['\r', '\n']),
            "Invalid OAuth callback header"
        );
        let (name, value) = line
            .split_once(':')
            .context("Invalid OAuth callback header")?;
        ensure!(
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "Invalid OAuth callback header name"
        );
        let value = value.trim();
        if name.eq_ignore_ascii_case("Host") {
            hosts += 1;
            ensure!(value == expected_host, "Invalid OAuth callback Host");
        }
        if name.eq_ignore_ascii_case("Content-Length") {
            lengths += 1;
            ensure!(value == "0", "OAuth callback request bodies are forbidden");
        }
        ensure!(
            !name.eq_ignore_ascii_case("Transfer-Encoding"),
            "OAuth callback transfer encodings are forbidden"
        );
    }
    ensure!(
        hosts == 1 && lengths <= 1,
        "Ambiguous OAuth callback headers"
    );
    Ok(parts[1])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Cursor, time::Duration};

    fn parse(extra: &str) -> bool {
        let text = format!("GET /callback?code=x&state=s HTTP/1.1\r\nHost: 127.0.0.1:1234\r\n{extra}\r\n");
        request_target(text.as_bytes(), 1234).is_ok()
    }

    #[test]
    fn exact_loopback_get_and_empty_body_are_supported() {
        assert!(parse(""));
        assert!(parse("Content-Length: 0\r\n"));
        assert!(parse("Sec-Fetch-Mode: navigate\r\n"));
    }

    #[test]
    fn ambiguous_headers_and_bodies_are_rejected() {
        for extra in [
            "Host: 127.0.0.1:1234\r\n",
            "Content-Length: 1\r\n",
            "Content-Length: 0\r\nContent-Length: 0\r\n",
            "Transfer-Encoding: chunked\r\n",
            " Host: attacker.invalid\r\n",
            "Invalid Header: value\r\n",
        ] {
            assert!(!parse(extra), "{extra}");
        }
    }

    #[test]
    fn wrong_hosts_methods_fragments_and_versions_are_rejected() {
        for text in [
            "GET /callback HTTP/1.1\r\nHost: localhost:1234\r\n\r\n",
            "GET /callback HTTP/1.1\r\nHost: 127.0.0.1:1235\r\n\r\n",
            "GET /callback HTTP/1.1\r\n\r\n",
            "POST /callback HTTP/1.1\r\nHost: 127.0.0.1:1234\r\n\r\n",
            "GET /callback#x HTTP/1.1\r\nHost: 127.0.0.1:1234\r\n\r\n",
            "GET /callback HTTP/2\r\nHost: 127.0.0.1:1234\r\n\r\n",
            "GET /callback HTTP/1.1 extra\r\nHost: 127.0.0.1:1234\r\n\r\n",
        ] {
            assert!(request_target(text.as_bytes(), 1234).is_err(), "{text}");
        }
    }

    #[test]
    fn incomplete_and_oversized_streams_never_yield_a_code() {
        let cancelled = AtomicBool::new(false);
        for bytes in [
            b"GET /callback?code=x HTTP/1.1\r\n".to_vec(),
            vec![b'x'; 8193],
        ] {
            let deadline = Instant::now() + Duration::from_secs(1);
            assert!(read_headers(&mut Cursor::new(bytes), &cancelled, deadline).is_err());
        }
    }

    #[test]
    fn cancellation_and_expiry_are_checked_before_reading() {
        let mut reader = Cursor::new(b"GET /callback HTTP/1.1\r\n\r\n");
        let cancelled = AtomicBool::new(true);
        let deadline = Instant::now() + Duration::from_secs(1);
        assert!(read_headers(&mut reader, &cancelled, deadline).is_err());
        assert_eq!(reader.position(), 0);
        cancelled.store(false, Ordering::SeqCst);
        assert!(read_headers(&mut reader, &cancelled, Instant::now()).is_err());
        assert_eq!(reader.position(), 0);
    }

    #[test]
    fn valid_stream_ends_at_header_boundary() {
        let mut reader = Cursor::new(b"GET /callback HTTP/1.1\r\n\r\nextra");
        let deadline = Instant::now() + Duration::from_secs(1);
        let bytes = read_headers(&mut reader, &AtomicBool::new(false), deadline).unwrap();
        assert_eq!(bytes.as_slice(), b"GET /callback HTTP/1.1\r\n\r\n");
    }
}
