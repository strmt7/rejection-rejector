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
//!
//! All submodules are declared `pub` except `session` (private) to enable
//! integrated testing and clean separation of concerns while maintaining
//! encapsulation where appropriate.
pub mod api;
pub mod api_auth;
pub mod audit_anchor;
pub mod background;
pub mod build_info;
pub mod config;
pub mod contracts;
pub mod decision;
pub mod diagnostics;
pub mod emergency;
pub mod engine;
pub mod evaluation;
pub mod gmail;
#[cfg(feature = "gui")]
pub mod gui;
pub mod language;
pub mod mail;
pub mod metrics;
pub mod net;
pub mod oauth;
pub mod ollama;
pub mod policy;
pub mod readiness;
pub mod recovery;
pub mod retry;
pub mod runtime_log;
mod session;
pub mod shadow;
pub mod storage;
pub mod store;
pub mod sync;
pub mod tui;
pub mod types;
pub mod vault;
pub mod worker;

/// Format bytes as lowercase hexadecimal.
///
/// Inputs: `bytes` — any byte buffer ([`AsRef`]`<`[`u8`]`>`; SHA-256 digests
/// included). Output: [`String`] of exactly `2 * bytes.len()` lowercase hex
/// characters. This is the single digest-formatting path (sha2 0.11 digests no
/// longer implement [`core::fmt::LowerHex`]).
pub fn hex_lower(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod hex_lower_tests {
    use super::hex_lower;

    #[test]
    fn hex_lower_encodes_single_and_multi_byte_buffers() {
        assert_eq!(hex_lower(b""), "");
        assert_eq!(hex_lower([0x00, 0x0f, 0xff]), "000fff");
    }

    #[test]
    fn hex_lower_accepts_sha256_digest_output() {
        use sha2::{Digest, Sha256};
        let out = hex_lower(Sha256::digest(b"abc"));
        assert_eq!(
            out,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
