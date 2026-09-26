use anyhow::{ensure, Context, Result};
use reqwest::blocking::{Client, Response};
use serde::de::DeserializeOwned;
use std::{io::Read, time::Duration};

pub fn client(timeout: u64, local: bool) -> Result<Client> {
    let mut builder = Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(timeout))
        .connect_timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("RejectionRejector/", env!("CARGO_PKG_VERSION")));
    if local {
        builder = builder.no_proxy();
    }
    Ok(builder.build()?)
}

/// Never include upstream error bodies, OAuth tokens, or message content in errors.
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
    let mut bytes = Vec::new();
    response
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .context("Cannot read upstream response")?;
    ensure!(bytes.len() <= limit, "Upstream response exceeds size limit");
    serde_json::from_slice(&bytes).context("Upstream returned invalid JSON")
}
