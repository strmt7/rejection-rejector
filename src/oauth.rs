use crate::net;
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
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

pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
pub const READ_SCOPE: &str = "https://www.googleapis.com/auth/gmail.readonly";
pub const SEND_SCOPE: &str = "https://www.googleapis.com/auth/gmail.send";

// Credentials intentionally do not implement Debug.
#[derive(Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub client_id: String,
    pub client_secret: String,
    pub refresh_token: String,
    pub can_send: bool,
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
#[derive(Deserialize)]
pub struct Tokens {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}
pub fn secret() -> String {
    let mut b = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

fn callback_code(target: &str, state: &str) -> Result<Option<String>> {
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
    ensure!(
        fs::metadata(path)?.len() <= 32768,
        "OAuth client file is too large"
    );
    let config: ClientFile = serde_json::from_slice(&fs::read(path)?)
        .context("Choose a Google Desktop app OAuth JSON file containing an installed object")?;
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
    let verifier = secret();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
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
    webbrowser::open(url.as_str()).context("Cannot open the system browser for Google sign-in")?;
    let start = Instant::now();
    let code = loop {
        ensure!(!cancelled.load(Ordering::SeqCst), "Authorization cancelled");
        ensure!(
            start.elapsed() < Duration::from_secs(300),
            "Authorization timed out; no credentials saved"
        );
        match listener.accept() {
            Ok((mut stream, peer)) => {
                if !peer.ip().is_loopback() {
                    continue;
                }
                stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                let mut bytes = Vec::new();
                let mut chunk = [0; 1024];
                while bytes.len() < 8192 && !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => bytes.extend_from_slice(&chunk[..n]),
                        Err(_) => break,
                    }
                }
                let input = String::from_utf8_lossy(&bytes);
                let mut first = input.lines().next().unwrap_or("").split_whitespace();
                let method = first.next().unwrap_or("");
                let target = first.next().unwrap_or("");
                let result = if method == "GET" && target.starts_with('/') {
                    callback_code(target, &state)
                } else {
                    Ok(None)
                };
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
                let response=format!("HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{text}",text.len());
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
    };
    let response = net::client(30, false)?
        .post(TOKEN_URL)
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
    let tokens: Tokens = net::json(response, 32768)?;
    let granted = tokens.scope.as_deref().unwrap_or("");
    ensure!(
        granted.split_whitespace().any(|s| s == READ_SCOPE),
        "Gmail read permission was not granted"
    );
    let can_send = granted.split_whitespace().any(|s| s == SEND_SCOPE);
    ensure!(!send || can_send, "Gmail send permission was not granted");
    let Some(refresh_token) = tokens.refresh_token else {
        bail!("No refresh token returned. Revoke this app's old consent in your Google account and reconnect");
    };
    Ok(Credentials {
        client_id: config.installed.client_id,
        client_secret: config.installed.client_secret,
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
    fn pkce_entropy() {
        assert_eq!(secret().len(), 43);
        assert_ne!(secret(), secret());
    }
}

#[cfg(test)]
mod callback_regressions {
    #[test]
    fn duplicated_authorization_codes_are_rejected() {
        assert!(super::callback_code("/callback?state=s&code=a&code=b", "s").is_err());
    }
}
