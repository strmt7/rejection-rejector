#![forbid(unsafe_code)]
//! Local-first, reusable core. Constructing this library never sends email.
pub mod config;
pub mod mail;
pub mod net;
pub mod store;
pub mod types;
pub mod vault;
