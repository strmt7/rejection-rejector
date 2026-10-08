use crate::net;
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
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
    let mut b = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
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
    let login_deadline = start + Duration::from_secs(300);
    let local_port = listener.local_addr()?.port();
    let code = Zeroizing::new(loop {
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
}

#[cfg(test)]
mod callback_regressions {
    #[test]
    fn duplicated_authorization_codes_are_rejected() {
        assert!(super::callback_code("/callback?state=s&code=a&code=b", "s").is_err());
    }
}
