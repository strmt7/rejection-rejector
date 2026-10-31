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
/// Local v1 HTTP API: routing, envelopes, rate limiting and the OpenAPI
/// contract.
///
/// Inputs: none (module). Output: the loopback request/response surface the
/// `rr api` listener serves.
pub mod api;
/// Bearer-token issuance and verification for the local API.
///
/// Inputs: none (module). Output: hashed token verification
/// ([`api_auth::ApiTokenVerifier`]) and the one-time plaintext exposure on
/// rotation.
pub mod api_auth;
/// Independent audit anchor outside the workspace database.
///
/// Inputs: none (module). Output: file- and OS-anchor reading and binding so
/// the audit head can be verified independently of the store.
pub mod audit_anchor;
/// Operating-system autostart registration for the background worker.
///
/// Inputs: none (module). Output: install, status and removal of the
/// scheduled task, summarized in [`background::AutostartStatus`].
pub mod background;
/// Build provenance embedded at compile time.
///
/// Inputs: none (module). Output: [`build_info::BuildInfo`] — application
/// version, source commit and its verification state.
pub mod build_info;
/// Settings model and shared configuration constants.
///
/// Inputs: none (module). Output: the persisted [`config::Settings`]
/// document plus the model, interval and contract-version constants every
/// surface shares.
pub mod config;
/// Machine-readable integration contract information.
///
/// Inputs: none (module). Output: [`contracts::ContractInfo`] — schema and
/// API versions with the OpenAPI contract digest.
pub mod contracts;
/// Decision-model evaluation protocol.
///
/// Inputs: none (module). Output: candidate decision-model scoring against
/// the `rr-decision-eval-v1` contract.
pub mod decision;
/// Privacy-scrubbed local diagnostics report.
///
/// Inputs: none (module). Output: the operator-facing diagnostics document,
/// with no tokens, OAuth credentials or candidate facts.
pub mod diagnostics;
/// Emergency-stop sentinel handling.
///
/// Inputs: none (module). Output: stop-file validation and status, failing
/// closed on missing, non-regular or oversized sentinels.
pub mod emergency;
/// Core orchestration engine: mail sync, analysis and controlled replies.
///
/// Inputs: none (module). Output: the state-mutating [`engine::Engine`] the
/// worker loop and every interface drive.
pub mod engine;
/// Local model evaluation suite.
///
/// Inputs: none (module). Output: per-candidate model scores against the
/// `rr-eval-contract-v5` evaluation suite.
pub mod evaluation;
/// Gmail REST API client (OAuth-authenticated).
///
/// Inputs: none (module). Output: message, profile and history fetching and
/// reply submission over the hardened HTTP client.
pub mod gmail;
/// Structural current-versus-quoted extraction for HTML mail bodies.
///
/// Inputs: none (module). Output: quote-history pruning before text
/// flattening so stale quoted language never reads as current evidence.
mod html_quote;
/// IMAP/SMTP app-password mail transport (the [`mail_transport::MailTransport`]
/// backend).
///
/// Inputs: none (module). Output: mailbox reading over IMAP and reply
/// delivery over SMTP for Gmail app-password accounts.
pub mod imap_smtp;
/// Deterministic language detection and reply-language enforcement.
///
/// Inputs: none (module). Output: the expected reply language derived from
/// the de-quoted original, independent of model output.
pub mod language;
/// Mail model: draft assembly and validation.
///
/// Inputs: none (module). Output: draft construction and validation helpers
/// over [`types::Email`] and [`types::Job`].
pub mod mail;
/// App-password (IMAP/SMTP basic-auth) mail transport.
///
/// Inputs: none (module). Output: the [`mail_transport::MailTransport`]
/// backend used when Gmail app passwords replace OAuth credentials.
pub mod mail_transport;
/// OpenMetrics exposition for the local API.
///
/// Inputs: none (module). Output: the per-workspace metrics document in
/// OpenMetrics text format.
pub mod metrics;
/// Hardened outbound HTTP client construction.
///
/// Inputs: none (module). Output: the shared client with fixed TLS, timeout
/// and redirect policy for every upstream call.
pub mod net;
/// Gmail OAuth authorization and token lifecycle.
///
/// Inputs: none (module). Output: scoped [`oauth::Tokens`] and
/// [`oauth::Credentials`], zeroized on drop, with the loopback consent flow.
pub mod oauth;
/// Local Ollama inference client.
///
/// Inputs: none (module). Output: chat/generate requests, model preflight
/// and GPU-residency checks for the private inference path.
pub mod ollama;
/// Loopback listener peer identity for the local model runtime.
///
/// Inputs: none (module). Output: OS socket-ownership inspection so the
/// model port is only ever used against an attributable runtime process.
pub mod peer_identity;
/// Enterprise policy documents and enforcement.
///
/// Inputs: none (module). Output: policy parsing and validation
/// ([`policy::EnterprisePolicy`]) and its effect on [`config::Settings`].
pub mod policy;
/// Operational readiness and send-gate indicators.
///
/// Inputs: none (module). Output: [`readiness::OperationalIndicators`]
/// summarizing connection, policy and queue state for the operator surfaces.
pub mod readiness;
/// Backup, restore and recovery-key workflows.
///
/// Inputs: none (module). Output: scheduled backups, verified pruning and
/// vault recovery-key import and export.
pub mod recovery;
/// Provider retry and circuit-breaker policy.
///
/// Inputs: none (module). Output: retry classification
/// ([`retry::CircuitTransition`]) and the backoff bounds applied to
/// provider failures.
pub mod retry;
/// Rotating runtime log of operations.
///
/// Inputs: none (module). Output: bounded current and archive log files
/// under the private workspace directory.
pub mod runtime_log;
mod session;
/// Shadow classification of send eligibility.
///
/// Inputs: none (module). Output: the per-job block reasons and queue
/// classification shown before anything is sent.
pub mod shadow;
/// Storage headroom and health checks.
///
/// Inputs: none (module). Output: [`storage::StorageHealth`] — free-space
/// headroom for runtime and backup paths.
pub mod storage;
/// Encrypted SQLite store owning the workspace connection and vault.
///
/// Inputs: none (module). Output: the persisted item surface used by the
/// engine: items, deliveries, audit events, metadata and retention.
pub mod store;
/// Provider mailbox synchronization.
///
/// Inputs: none (module). Output: the [`sync::Provider`] trait and the
/// history and message paging loop that feeds the store.
pub mod sync;
#[cfg(test)]
pub(crate) mod test_support;
/// Training monitor data model shared with the Python trainer hook.
///
/// Inputs: none (module). Output: progress parsing, duty-file handling and
/// the pacing math for the utilization ceiling.
/// Interactive terminal interface (`rr tui`).
///
/// Inputs: none (module). Output: a thin presentation shell rendering
/// [`worker::Snapshot`]s and issuing [`worker::Command`]s to the shared
/// worker.
pub mod tui;
/// Shared domain types for jobs, drafts, verdicts and operations.
///
/// Inputs: none (module). Output: the serialized data model every engine,
/// store and interface surface shares.
pub mod types;
/// Application-layer authenticated encryption for the workspace.
///
/// Inputs: none (module). Output: the [`vault::Vault`] sealing values under
/// an OS-protected or passphrase-derived key; indexes and counts stay
/// plaintext.
pub mod vault;
/// Local web interface (`rr web`) request handling and gate composition.
///
/// Inputs: none (module). Output: the pure request parsers and response
/// envelopes the embedded page is served through.
pub mod web;
/// Background worker: bounded command channel and state snapshots.
///
/// Inputs: none (module). Output: the [`worker::Worker`] handle and the
/// [`worker::Snapshot`] view every interface renders.
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
