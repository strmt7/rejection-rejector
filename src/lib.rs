#![forbid(unsafe_code)]
//! Native local-first core. Constructing this library never sends email.
pub mod api;
pub mod config;
pub mod engine;
pub mod evaluation;
pub mod gmail;
#[cfg(feature = "gui")]
pub mod gui;
pub mod mail;
pub mod net;
pub mod oauth;
pub mod ollama;
pub mod recovery;
pub mod store;
pub mod sync;
pub mod types;
pub mod vault;
pub mod worker;
