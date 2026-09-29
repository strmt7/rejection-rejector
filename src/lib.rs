#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable
    )
)]
//! Native local-first core. Constructing this library never sends email.
pub mod api;
pub mod api_auth;
pub mod audit_anchor;
pub mod background;
pub mod build_info;
pub mod config;
pub mod diagnostics;
pub mod engine;
pub mod evaluation;
pub mod gmail;
#[cfg(feature = "gui")]
pub mod gui;
pub mod mail;
pub mod metrics;
pub mod net;
pub mod oauth;
pub mod ollama;
pub mod policy;
pub mod readiness;
pub mod recovery;
pub mod runtime_log;
mod session;
pub mod shadow;
pub mod storage;
pub mod store;
pub mod sync;
pub mod types;
pub mod vault;
pub mod worker;
