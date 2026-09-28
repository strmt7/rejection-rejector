#![forbid(unsafe_code)]
//! Native local-first core. Constructing this library never sends email.
pub mod api;
pub mod audit_anchor;
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
pub mod store;
pub mod sync;
pub mod types;
pub mod vault;
pub mod worker;
