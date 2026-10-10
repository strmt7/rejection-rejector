use crate::net;
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

mod callback;

pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
pub const READ_SCOPE: &str = "https://www.googleapis.com/auth/gmail.readonly";
pub const SEND_SCOPE: &str = "https://www.googleapis.com/auth/gmail.send";

// Credentials intentionally do not implement Debug to prevent accidental logging of secrets.
// The struct implements Drop to zeroize sensitive fields on destruction.
// Handle the return value of oauth::login() carefully as it contains sensitive credential material.
#[derive(Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub client_id: String,
    pub client_secret: String,
    pub refresh_token: String,
    pub can_send: bool,
}
impl Drop for Credentials {
    fn drop(&mut self) {
        self.client_secret.zeroize();
        self.refresh_token.zeroize();
    }
}
#[derive(Deserialize)]
struct ClientFile {
    installed: Installed,
}
#[derive(Deserialize)]
struct Installed {
    client_id: String,
    client_secret: String,
}
impl Drop for Installed {
    fn drop(&mut self) {
        self.client_secret.zeroize();
    }
}
#[derive(Deserialize)]
pub struct Tokens {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}
impl Zeroize for Tokens {
    fn zeroize(&mut self) {
        self.access_token.zeroize();
        if let Some(token) = &mut self.refresh_token {
            token.zeroize();
        }
    }
}
pub fn secret() -> String {
    let b = rand::random::<[u8; 32]>();
    URL_SAFE_NO_PAD.encode(b)
}

/// RFC 7636 S256 code challenge: BASE64URL-ENCODE(SHA256(ASCII(verifier))).
///
/// Split out of `login()` so the exact challenge construction is pinned by the
/// RFC test vector; a subtly wrong digest encoding would break authorization
/// only at the Google redirect, far from any test.
fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn callback_code(target: &str, state: &str) -> Result<Option<String>> {
    ensure!(
        target.starts_with('/')
            && !target.starts_with("//")
            && !target.contains('#')
            && !target.chars().any(char::is_control),
        "Invalid OAuth callback target"
    );
    let u = url::Url::parse(&format!("http://127.0.0.1{target}"))?;
    if u.path() != "/callback" {
        return Ok(None);
    }
    let pairs: Vec<_> = u.query_pairs().collect();
    ensure!(
        pairs.iter().filter(|(k, _)| k == "state").count() == 1,
        "Invalid OAuth state count"
    );
    ensure!(
        pairs.iter().filter(|(k, _)| k == "code").count() == 1,
        "Exactly one OAuth authorization code is required"
    );
    let q: HashMap<_, _> = pairs.into_iter().collect();
    let actual = q.get("state").map(|v| v.as_ref()).unwrap_or("");
    ensure!(
        actual.as_bytes().ct_eq(state.as_bytes()).unwrap_u8() == 1,
        "Invalid OAuth state"
    );
    ensure!(
        !q.contains_key("error"),
        "Google authorization was declined"
    );
    let code = q.get("code").context("Authorization code missing")?;
    ensure!(
        !code.is_empty() && code.len() < 4096,
        "Invalid authorization code"
    );
    Ok(Some(code.to_string()))
}

/// Desktop-app OAuth: S256 PKCE, random state, random loopback port, five-minute expiry.
pub fn login(path: &Path, send: bool, cancelled: &AtomicBool) -> Result<Credentials> {
    login_with(
        path,
        send,
        cancelled,
        Duration::from_secs(300),
        |url| {
            webbrowser::open(url)
                .map(|_| ())
                .context("Cannot open the system browser for Google sign-in")
        },
        TOKEN_URL,
    )
}

/// Parameterized core of [`login`].
///
/// Inputs: `path` — Google Desktop-app OAuth JSON; `send` — whether the send
/// scope is required; `cancelled` — cooperative cancellation flag;
/// `timeout` — consent deadline; `open_browser` — consent-URL launcher;
/// `token_url` — OAuth token endpoint. Output: the obtained
/// [`Credentials`]. The browser launcher and token endpoint are injectable so
/// the whole consent loop (state, PKCE binding, decline handling, exchange
/// failure modes) can be exercised deterministically without a real browser
/// or Google; [`login`] wires in the real ones.
fn login_with(
    path: &Path,
    send: bool,
    cancelled: &AtomicBool,
    timeout: Duration,
    open_browser: impl Fn(&str) -> Result<()>,
    token_url: &str,
) -> Result<Credentials> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "OAuth client file must be a regular file, not a symlink"
    );
    ensure!(metadata.len() <= 32768, "OAuth client file is too large");
    let mut config_bytes = Zeroizing::new(Vec::new());
    fs::File::open(path)?
        .take(32769)
        .read_to_end(&mut config_bytes)?;
    ensure!(
        config_bytes.len() <= 32768,
        "OAuth client file is too large"
    );
    let mut config: ClientFile = serde_json::from_slice(&config_bytes).map_err(|_| {
        anyhow::anyhow!(
            "Choose a Google Desktop app OAuth JSON file containing an installed object"
        )
    })?;
    drop(config_bytes);
    ensure!(
        !config.installed.client_id.is_empty() && !config.installed.client_secret.is_empty(),
        "Incomplete OAuth client file"
    );
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let redirect = format!(
        "http://127.0.0.1:{}/callback",
        listener.local_addr()?.port()
    );
    let state = secret();
    let verifier = Zeroizing::new(secret());
    let challenge = pkce_challenge(verifier.as_str());
    let scope = if send {
        format!("{READ_SCOPE} {SEND_SCOPE}")
    } else {
        READ_SCOPE.into()
    };
    let mut url = url::Url::parse("https://accounts.google.com/o/oauth2/v2/auth")?;
    url.query_pairs_mut().extend_pairs([
        ("client_id", config.installed.client_id.as_str()),
        ("redirect_uri", redirect.as_str()),
        ("response_type", "code"),
        ("scope", scope.as_str()),
        ("access_type", "offline"),
        ("prompt", "consent"),
        ("state", state.as_str()),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ]);
    open_browser(url.as_str())?;
    let start = Instant::now();
    let login_deadline = start + timeout;
    let local_port = listener.local_addr()?.port();
    let code = Zeroizing::new(loop {
        ensure!(!cancelled.load(Ordering::SeqCst), "Authorization cancelled");
        ensure!(
            start.elapsed() < timeout,
            "Authorization timed out; no credentials saved"
        );
        match listener.accept() {
            Ok((mut stream, peer)) => {
                if !peer.ip().is_loopback() {
                    continue;
                }
                stream.set_read_timeout(Some(Duration::from_millis(250)))?;
                stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                let deadline = (Instant::now() + Duration::from_secs(2)).min(login_deadline);
                let result =
                    callback::read_headers(&mut stream, cancelled, deadline).and_then(|headers| {
                        let target = callback::request_target(&headers, local_port)?;
                        callback_code(target, &state)
                    });
                let (status, text) = if matches!(&result, Ok(Some(_))) {
                    (
                        "200 OK",
                        "Authorization received. Return to Rejection Rejector.",
                    )
                } else {
                    (
                        "400 Bad Request",
                        "Authorization not accepted. Retry from the application.",
                    )
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{text}",
                    text.len()
                );
                let _ = stream.write_all(response.as_bytes());
                if let Ok(Some(code)) = result {
                    break code;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50))
            }
            Err(e) => return Err(e.into()),
        }
    });
    // Do not exchange an authorization code after cancellation or expiry.
    ensure!(!cancelled.load(Ordering::SeqCst), "Authorization cancelled");
    ensure!(Instant::now() < login_deadline, "Authorization expired");
    drop(listener);
    let response = net::client(30, false)?
        .post(token_url)
        .form(&[
            ("client_id", config.installed.client_id.as_str()),
            ("client_secret", config.installed.client_secret.as_str()),
            ("code", code.as_str()),
            ("code_verifier", verifier.as_str()),
            ("redirect_uri", redirect.as_str()),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .context("OAuth exchange failed")?;
    let mut tokens: Zeroizing<Tokens> = Zeroizing::new(net::json(response, 32768)?);
    let granted = tokens.scope.as_deref().unwrap_or("");
    ensure!(
        granted.split_whitespace().any(|s| s == READ_SCOPE),
        "Gmail read permission was not granted"
    );
    let can_send = granted.split_whitespace().any(|s| s == SEND_SCOPE);
    ensure!(!send || can_send, "Gmail send permission was not granted");
    let Some(refresh_token) = tokens.refresh_token.take() else {
        tokens.access_token.zeroize();
        bail!(
            "No refresh token returned. Revoke this app's old consent in your Google account and reconnect"
        );
    };
    tokens.access_token.zeroize();
    Ok(Credentials {
        client_id: std::mem::take(&mut config.installed.client_id),
        client_secret: std::mem::take(&mut config.installed.client_secret),
        refresh_token,
        can_send,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn state_required_and_constant() {
        assert!(callback_code("/callback?code=x&state=wrong", "correct").is_err());
        assert_eq!(
            callback_code("/callback?code=x&state=correct", "correct").unwrap(),
            Some("x".into())
        );
    }
    #[test]
    fn duplicate_state_rejected() {
        assert!(callback_code("/callback?code=x&state=a&state=a", "a").is_err());
    }
    #[test]
    fn unknown_path_ignored() {
        assert_eq!(callback_code("/favicon.ico", "a").unwrap(), None);
    }
    #[test]
    fn token_wiping_clears_both_secrets() {
        let mut tokens = Tokens {
            access_token: "private-access-token".into(),
            expires_in: 3600,
            refresh_token: Some("private-refresh-token".into()),
            scope: None,
        };
        tokens.zeroize();
        assert!(tokens.access_token.is_empty());
        assert_eq!(tokens.refresh_token.as_deref(), Some(""));
    }

    #[test]
    fn fragments_and_non_origin_targets_are_rejected() {
        for target in [
            "//attacker.invalid/callback?state=s&code=x",
            "/callback?state=s&code=x#fragment",
            "/callback?state=s&code=x\r\nInjected: value",
        ] {
            assert!(callback_code(target, "s").is_err());
        }
    }

    #[test]
    fn pkce_entropy() {
        assert_eq!(secret().len(), 43);
        assert_ne!(secret(), secret());
    }

    /// Guards PKCE S256 correctness against the RFC 7636 appendix B vector:
    /// a wrong digest encoding, padding, or alphabet would break authorization
    /// only at Google's redirect and pass every local smoke check.
    #[test]
    fn pkce_challenge_matches_the_rfc_7636_test_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            pkce_challenge(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    /// Guards challenge construction hygiene: the challenge must be unpadded
    /// base64url of the SHA-256 digest (43 chars), never the verifier itself.
    #[test]
    fn pkce_challenge_is_unpadded_base64url_and_distinct_from_verifier() {
        let verifier = secret();
        let challenge = pkce_challenge(&verifier);
        assert_eq!(challenge.len(), 43);
        assert!(
            challenge
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        assert_ne!(challenge, verifier);
    }

    /// Guards consent-declines: a Google error response must fail even when it
    /// carries a well-formed state and code, so no token exchange is attempted.
    #[test]
    fn google_decline_is_rejected_despite_valid_state_and_code() {
        let error = callback_code("/callback?state=s&code=x&error=access_denied", "s")
            .unwrap_err()
            .to_string();
        assert!(error.contains("declined"), "{error}");
    }

    /// Guards authorization-code validation at its exact length boundary:
    /// 4095 bytes pass, 4096 and empty codes are rejected (off-by-one).
    #[test]
    fn authorization_code_length_is_an_exact_boundary() {
        let code_4095 = "c".repeat(4095);
        assert_eq!(
            callback_code(&format!("/callback?state=s&code={code_4095}"), "s").unwrap(),
            Some(code_4095)
        );
        let code_4096 = "c".repeat(4096);
        assert!(callback_code(&format!("/callback?state=s&code={code_4096}"), "s").is_err());
        assert!(callback_code("/callback?state=s&code=", "s").is_err());
    }

    /// Guards state comparison semantics: the state parameter must be compared
    /// after URL-decoding and byte-for-byte (length included); raw comparison
    /// or truncation would accept tampered callbacks.
    #[test]
    fn state_is_url_decoded_and_compared_byte_exact() {
        assert_eq!(
            callback_code("/callback?state=a%2Fb&code=x", "a/b").unwrap(),
            Some("x".into())
        );
        assert!(callback_code("/callback?state=a%2Fb&code=x", "a%2Fb").is_err());
        assert!(callback_code("/callback?state=abc&code=x", "abcd").is_err());
        assert!(callback_code("/callback?state=abcd&code=x", "abc").is_err());
        assert!(callback_code("/callback?state=ABC&code=x", "abc").is_err());
        assert!(callback_code("/callback?state=abc&code=x", "abc ").is_err());
    }

    /// Guards callback path matching: only the exact /callback path extracts a
    /// code; lookalike paths (trailing slash, different case) are ignored as
    /// ordinary browser noise rather than erroring the login loop.
    #[test]
    fn only_the_exact_callback_path_extracts_a_code() {
        assert_eq!(
            callback_code("/callback/?state=s&code=x", "s").unwrap(),
            None
        );
        assert_eq!(
            callback_code("/Callback?state=s&code=x", "s").unwrap(),
            None
        );
        assert_eq!(
            callback_code("/callback/extra?state=s&code=x", "s").unwrap(),
            None
        );
    }

    fn client_file(contents: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.json");
        std::fs::write(&path, contents).unwrap();
        (dir, path)
    }

    /// Guards the client-file size cap before any secret parsing: an oversized
    /// file must be refused outright (both by metadata and by the bounded read).
    #[test]
    fn oversized_oauth_client_file_is_rejected_before_parsing() {
        let (_dir, path) = client_file(&vec![b' '; 32_769]);
        let error = login(&path, false, &AtomicBool::new(false))
            .err()
            .expect("login must fail")
            .to_string();
        assert!(error.contains("too large"), "{error}");
    }

    /// Guards OAuth client-file shape validation: only a Google "installed"
    /// desktop-app JSON is accepted; web-app shapes, garbage and directories
    /// fail with the guidance error before any listener or browser is started.
    #[test]
    fn malformed_oauth_client_files_are_rejected_before_any_network() {
        let (_dir, garbage) = client_file(b"not json at all");
        assert!(
            login(&garbage, false, &AtomicBool::new(false))
                .err()
                .expect("login must fail")
                .to_string()
                .contains("Choose a Google Desktop app OAuth JSON")
        );
        let (_dir, web) = client_file(br#"{"web":{"client_id":"x","client_secret":"y"}}"#);
        assert!(
            login(&web, false, &AtomicBool::new(false))
                .err()
                .expect("login must fail")
                .to_string()
                .contains("Choose a Google Desktop app OAuth JSON")
        );
        let (_dir, missing) = client_file(br#"{"installed":{}}"#);
        assert!(
            login(&missing, false, &AtomicBool::new(false))
                .err()
                .expect("login must fail")
                .to_string()
                .contains("Choose a Google Desktop app OAuth JSON")
        );
        let dir = tempfile::tempdir().unwrap();
        assert!(login(dir.path(), false, &AtomicBool::new(false)).is_err());
    }

    /// Guards incomplete credential rejection: empty client_id or client_secret
    /// must fail before the loopback listener starts, so a half-configured file
    /// can never begin an authorization dance.
    #[test]
    fn incomplete_oauth_client_credentials_are_rejected() {
        for body in [
            br#"{"installed":{"client_id":"","client_secret":"s"}}"# as &[u8],
            br#"{"installed":{"client_id":"i","secret":"","client_secret":""}}"#,
        ] {
            let (_dir, path) = client_file(body);
            assert!(
                login(&path, false, &AtomicBool::new(false))
                    .err()
                    .expect("login must fail")
                    .to_string()
                    .contains("Incomplete OAuth client file"),
                "{body:?} must fail as incomplete"
            );
        }
    }

    /// Guards PKCE verifier bounds: the generated verifier must sit inside the
    /// RFC 7636 unreserved alphabet and length window at both ends, because
    /// Google rejects anything else at the redirect, far from any local check.
    #[test]
    fn pkce_verifiers_stay_inside_rfc_7636_bounds() {
        for _ in 0..32 {
            let verifier = secret();
            assert!(verifier.len() >= 43 && verifier.len() <= 128, "{verifier}");
            assert!(
                verifier
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                "verifier leaves the unreserved alphabet: {verifier}"
            );
        }
    }

    /// Guards the missing-parameter branches of callback parsing: a callback
    /// without exactly one `code` or exactly one `state` is an error, never a
    /// silent success or a wrong-branch parse.
    #[test]
    fn callbacks_missing_state_or_code_are_errors() {
        assert!(callback_code("/callback?code=x", "s").is_err());
        assert!(callback_code("/callback?state=s", "s").is_err());
        assert!(callback_code("/callback?state=s&code=x&code=y", "s").is_err());
        assert!(callback_code("/callback?state=s&state=s", "s").is_err());
    }

    use std::net::TcpStream;
    use std::sync::{Arc, mpsc};

    /// Serve exactly one token exchange on a loopback socket.
    ///
    /// Inputs: `status` — HTTP status of the exchange response; `body` —
    /// response body. Output: `(token_url, request)` where `request` resolves
    /// to the raw request the exchange sent.
    fn token_server(status: u16, body: &str) -> (String, std::thread::JoinHandle<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/token", listener.local_addr().unwrap());
        let body = body.to_owned();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => request.extend_from_slice(&chunk[..n]),
                    Err(_) => break,
                }
            }
            let response = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            String::from_utf8_lossy(&request).to_string()
        });
        (url, handle)
    }

    /// Parse the consent URL the browser launcher received.
    ///
    /// Inputs: `url` — consent URL. Output: query pairs; panics unless the
    /// URL targets the real Google consent endpoint over HTTPS.
    fn consent_query(url: &str) -> HashMap<String, String> {
        let parsed = url::Url::parse(url).unwrap();
        assert_eq!(parsed.scheme(), "https");
        assert_eq!(parsed.host_str(), Some("accounts.google.com"));
        parsed
            .query_pairs()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    /// Drive one callback request against the loopback listener behind the
    /// consent URL's `redirect_uri`.
    ///
    /// Inputs: `redirect_uri` — exact redirect from the consent URL;
    /// `target` — request target to send. Output: the raw HTTP response.
    fn drive(redirect_uri: &str, target: &str) -> String {
        let addr = redirect_uri
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap()
            .to_owned();
        let mut stream = TcpStream::connect(&addr).unwrap();
        stream
            .write_all(
                format!("GET {target} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .unwrap();
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        response
    }

    /// Look up one form-encoded field in a raw HTTP request.
    ///
    /// Inputs: `request` — raw request text; `name` — field name. Output: the
    /// decoded value, or `None` when absent.
    fn form_value(request: &str, name: &str) -> Option<String> {
        let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
        url::form_urlencoded::parse(body.as_bytes())
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.to_string())
    }

    /// Start the consent-callback driver behind the injected browser launcher.
    ///
    /// Inputs: `script` — runs on its own thread once the consent URL is
    /// issued; it may drive any number of callback requests sequentially.
    /// Output: `(launcher, join)` for `login_with`; `join` yields the script's
    /// return value. The script must live on its own thread because the
    /// callback listener only starts answering after the launcher returns.
    fn driver<T: Send + 'static>(
        script: impl FnOnce(String) -> T + Send + 'static,
    ) -> (
        impl Fn(&str) -> Result<()> + Send + 'static,
        std::thread::JoinHandle<T>,
    ) {
        let (tx, rx) = mpsc::channel::<String>();
        let handle = std::thread::spawn(move || script(rx.recv().unwrap()));
        let launcher = move |url: &str| -> Result<()> {
            tx.send(url.to_owned())
                .map_err(|_| anyhow::anyhow!("consent URL receiver dropped"))?;
            Ok(())
        };
        (launcher, handle)
    }

    fn client_json() -> (tempfile::TempDir, std::path::PathBuf) {
        client_file(br#"{"installed":{"client_id":"cid","client_secret":"cs"}}"#)
    }

    fn token_body(scope: &str, refresh: bool) -> String {
        let rt = if refresh { r#""rt-secret""# } else { "null" };
        format!(
            r#"{{"access_token":"at-secret","expires_in":3600,"refresh_token":{rt},"scope":"{scope}"}}"#
        )
    }

    /// Guards the full consent loop end to end: the consent URL must pin the
    /// fixed policy parameters and the S256 challenge against the real Google
    /// endpoint, the exchange must post exactly the verifier whose digest is
    /// that challenge plus the same redirect_uri and code, and only the
    /// refresh credential may land in the result.
    #[test]
    fn login_flow_binds_pkce_and_returns_only_the_refresh_credential() {
        let (_root, path) = client_json();
        let (token_url, request) = token_server(200, &token_body(READ_SCOPE, true));
        let (launcher, driver) = driver(|url| {
            let query = consent_query(&url);
            assert_eq!(query.get("response_type").map(String::as_str), Some("code"));
            assert_eq!(
                query.get("code_challenge_method").map(String::as_str),
                Some("S256")
            );
            assert_eq!(
                query.get("access_type").map(String::as_str),
                Some("offline")
            );
            assert_eq!(query.get("prompt").map(String::as_str), Some("consent"));
            assert_eq!(query.get("scope").map(String::as_str), Some(READ_SCOPE));
            let response = drive(
                query.get("redirect_uri").unwrap(),
                &format!(
                    "/callback?state={}&code=code-1",
                    query.get("state").unwrap()
                ),
            );
            assert!(response.contains("200 OK"), "{response}");
            query
        });
        let creds = login_with(
            &path,
            false,
            &AtomicBool::new(false),
            Duration::from_secs(30),
            launcher,
            &token_url,
        )
        .unwrap();
        let query = driver.join().unwrap();
        assert_eq!(creds.client_id, "cid");
        assert_eq!(creds.client_secret, "cs");
        assert_eq!(creds.refresh_token, "rt-secret");
        assert!(!creds.can_send);

        let request = request.join().unwrap();
        assert!(
            request.contains("grant_type=authorization_code"),
            "{request}"
        );
        assert!(request.contains("code=code-1"), "{request}");
        assert_eq!(
            form_value(&request, "redirect_uri").as_deref(),
            query.get("redirect_uri").map(String::as_str),
            "the exchange must reuse the exact redirect the consent URL advertised"
        );
        assert_eq!(
            pkce_challenge(form_value(&request, "code_verifier").unwrap().as_str()),
            *query.get("code_challenge").unwrap(),
            "the posted verifier must hash to the advertised challenge"
        );
    }

    /// Guards scope enforcement at the exchange boundary: read permission is
    /// mandatory, the send grant is honored only when requested, and a token
    /// response without a refresh token is refused instead of storing a
    /// credential that dies together with the access token.
    #[test]
    fn token_exchange_enforces_scopes_and_the_refresh_token() {
        let (_root, path) = client_json();
        type ExchangeCase = (bool, String, bool, Option<bool>, Option<String>);
        let cases: Vec<ExchangeCase> = vec![
            (
                true,
                format!("{READ_SCOPE} {SEND_SCOPE}"),
                true,
                Some(true),
                None,
            ),
            (
                true,
                READ_SCOPE.into(),
                true,
                None,
                Some("send permission".into()),
            ),
            (false, READ_SCOPE.into(), true, Some(false), None),
            (
                false,
                "other-scope".into(),
                true,
                None,
                Some("read permission".into()),
            ),
            (
                false,
                READ_SCOPE.into(),
                false,
                None,
                Some("No refresh token".into()),
            ),
        ];
        for (send, scope, refresh, expect_send, error_phrase) in cases {
            let (token_url, _request) = token_server(200, &token_body(&scope, refresh));
            let (launcher, done) = driver(move |url| {
                let query = consent_query(&url);
                if send {
                    assert_eq!(
                        query.get("scope").map(String::as_str),
                        Some(format!("{READ_SCOPE} {SEND_SCOPE}").as_str()),
                        "send=true must widen the consent scope"
                    );
                }
                let response = drive(
                    query.get("redirect_uri").unwrap(),
                    &format!("/callback?state={}&code=c1", query.get("state").unwrap()),
                );
                assert!(response.contains("200 OK"), "{response}");
            });
            let result = login_with(
                &path,
                send,
                &AtomicBool::new(false),
                Duration::from_secs(30),
                launcher,
                &token_url,
            );
            done.join().unwrap();
            match (error_phrase, expect_send) {
                (Some(phrase), _) => {
                    let error = result.err().expect("login must fail").to_string();
                    assert!(error.contains(&phrase), "{scope}: {error}");
                }
                (None, Some(can_send)) => {
                    let creds = result.unwrap();
                    assert_eq!(creds.can_send, can_send, "{scope}");
                    assert_eq!(creds.refresh_token, "rt-secret");
                }
                _ => unreachable!("every case pins an outcome"),
            }
        }
    }

    /// Guards the callback loop against hostile first contacts: a tampered
    /// state and a Google decline are both refused on the wire with 400 and
    /// the loop keeps listening, so one forged request cannot burn the login.
    #[test]
    fn tampered_and_declined_callbacks_do_not_stop_the_flow() {
        let (_root, path) = client_json();
        let (token_url, _request) = token_server(
            200,
            &token_body(&format!("{READ_SCOPE} {SEND_SCOPE}"), true),
        );
        let (launcher, driver) = driver(|url| {
            let query = consent_query(&url);
            assert_eq!(
                query.get("scope").map(String::as_str),
                Some(format!("{READ_SCOPE} {SEND_SCOPE}").as_str()),
                "send=true must widen the consent scope"
            );
            let redirect = query.get("redirect_uri").unwrap().clone();
            let state = query.get("state").unwrap().clone();
            let forged = drive(&redirect, "/callback?state=attacker&code=x");
            assert!(forged.contains("400 Bad Request"), "{forged}");
            let declined = drive(
                &redirect,
                &format!("/callback?state={state}&code=ok&error=access_denied"),
            );
            assert!(declined.contains("400 Bad Request"), "{declined}");
            let valid = drive(&redirect, &format!("/callback?state={state}&code=ok-code"));
            assert!(valid.contains("200 OK"), "{valid}");
        });
        let creds = login_with(
            &path,
            true,
            &AtomicBool::new(false),
            Duration::from_secs(30),
            launcher,
            &token_url,
        )
        .unwrap();
        driver.join().unwrap();
        assert!(creds.can_send);
        assert_eq!(creds.refresh_token, "rt-secret");
    }

    /// Guards cooperative cancellation: once the flag is raised no code is
    /// exchanged, even though a valid consent URL was already issued.
    #[test]
    fn cancellation_stops_the_flow_before_any_exchange() {
        let (_root, path) = client_json();
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = cancelled.clone();
        let (launcher, driver) = driver(move |_url| {
            flag.store(true, Ordering::SeqCst);
        });
        let error = login_with(
            &path,
            false,
            &cancelled,
            Duration::from_secs(30),
            launcher,
            "http://127.0.0.1:1/token",
        )
        .err()
        .expect("login must fail")
        .to_string();
        driver.join().unwrap();
        assert!(error.contains("cancelled"), "{error}");
    }

    /// Guards the consent deadline: an expired window fails closed with no
    /// credentials even while the browser launcher is happy.
    #[test]
    fn an_expired_consent_window_fails_closed() {
        let (_root, path) = client_json();
        let (launcher, driver) = driver(|_url| ());
        let error = login_with(
            &path,
            false,
            &AtomicBool::new(false),
            Duration::ZERO,
            launcher,
            "http://127.0.0.1:1/token",
        )
        .err()
        .expect("login must fail")
        .to_string();
        driver.join().unwrap();
        assert!(error.contains("timed out"), "{error}");
    }

    /// Guards launcher failure propagation: if no browser can be opened the
    /// login aborts immediately instead of waiting out the consent deadline.
    #[test]
    fn browser_launcher_failures_abort_the_login() {
        let (_root, path) = client_json();
        let error = login_with(
            &path,
            false,
            &AtomicBool::new(false),
            Duration::from_secs(30),
            |_| Err(anyhow::anyhow!("no browser")),
            "http://127.0.0.1:1/token",
        )
        .err()
        .expect("login must fail")
        .to_string();
        assert!(error.contains("no browser"), "{error}");
    }
}

#[cfg(test)]
mod callback_regressions {
    #[test]
    fn duplicated_authorization_codes_are_rejected() {
        assert!(super::callback_code("/callback?state=s&code=a&code=b", "s").is_err());
    }
}
