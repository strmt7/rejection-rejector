#![forbid(unsafe_code)]
//! Local-first, reusable core. Constructing this library never sends email.
pub mod config;
pub mod gmail;
pub mod mail;
pub mod net;
pub mod oauth;
pub mod ollama;
pub mod store;
pub mod sync;
pub mod types;
pub mod vault;
