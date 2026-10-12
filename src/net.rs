use anyhow::{Context, Result, ensure};
use reqwest::blocking::{Client, Response};
use serde::de::DeserializeOwned;
use std::{io::Read, time::Duration};
use zeroize::Zeroizing;

/// Build the hardened HTTP client used for upstream calls.
///
/// Inputs: `timeout` — total request timeout in seconds; `local` — whether the
/// client bypasses any configured proxy for local targets. Output: `Result<Client>`;
/// errors when the client cannot be constructed.
pub fn client(timeout: u64, local: bool) -> Result<Client> {
    let mut builder = Client::builder()
        .http1_only()
        // A send may have succeeded even when the response is lost. Never replay it.
        .retry(reqwest::retry::never())
        .timeout(Duration::from_secs(timeout))
        .connect_timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("RejectionRejector/", env!("CARGO_PKG_VERSION")));
    if local {
        builder = builder.no_proxy();
    }
    Ok(builder.build()?)
}

/// Do not include upstream bodies, credentials or echoed private values in errors.
///
/// Inputs: `response` — upstream HTTP response to decode; `limit` — maximum
/// accepted body size in bytes. Output: `Result<T>` — the decoded JSON value;
/// non-success statuses, oversized bodies and malformed JSON are refused.
pub fn json<T: DeserializeOwned>(response: Response, limit: usize) -> Result<T> {
    ensure!(
        response.status().is_success(),
        "Upstream HTTP {}",
        response.status().as_u16()
    );
    ensure!(
        response.content_length().is_none_or(|n| n <= limit as u64),
        "Upstream response exceeds size limit"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    response
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .context("Cannot read upstream response")?;
    ensure!(bytes.len() <= limit, "Upstream response exceeds size limit");
    // Serde type errors can contain the offending string; deliberately omit that source.
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("Upstream returned invalid JSON"))
}
