//! App-password (IMAP/SMTP basic-auth) mail transport.
//!
//! Gmail app passwords work only over IMAP/SMTP — the Gmail REST API is
//! OAuth-only — so accepting app passwords requires a second mail transport
//! alongside the Gmail-API path. This module defines the transport seam and
//! the app-password credential type.
//!
//! Security: an app password is a *static* secret (unlike OAuth's scoped,
//! revocable tokens). It is therefore held only in memory in a zeroizing
//! container, its `Debug` output is redacted, and it must be persisted only
//! through the encrypted vault (`vault.rs`) — never in the repository,
//! settings file, or any log line.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::gmail::{FetchFailure, SendFailure, Thread};
use crate::types::{Email, Stub};

/// Credentials for app-password (IMAP/SMTP basic-auth) mail access.
///
/// Inputs at construction: `email` — the full mailbox address; `app_password` —
/// the Google app password. The password is zeroized on drop and redacted from
/// `Debug` so it can never leak through a log or error message.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct AppPasswordCredentials {
    /// Full mailbox address (e.g. `user@gmail.com`). Not secret.
    pub email: String,
    app_password: String,
}

impl AppPasswordCredentials {
    /// Construct app-password credentials.
    ///
    /// Inputs: `email` — mailbox address; `app_password` — Google app password
    /// (spaces are stripped so 16-char and 4x4 groupings both work). Output:
    /// `Self` owning the secret, zeroized on drop.
    pub fn new(email: impl Into<String>, app_password: impl Into<String>) -> Self {
        Self {
            email: email.into(),
            app_password: app_password.into().split_whitespace().collect(),
        }
    }

    /// Borrow the app password for authentication.
    ///
    /// Inputs: none (`&self`). Output: `&str` — the app password. Callers must
    /// never log, print, or persist this value outside the encrypted vault.
    pub fn password(&self) -> &str {
        &self.app_password
    }
}

impl Drop for AppPasswordCredentials {
    /// Wipe the secret in place.
    ///
    /// Inputs: none (`&mut self`). Output: none — the app password is zeroized.
    fn drop(&mut self) {
        self.app_password.zeroize();
    }
}

impl std::fmt::Debug for AppPasswordCredentials {
    /// Redacted debug: the app password is a live secret and must never appear
    /// in logs, `{:?}` output, or error messages.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppPasswordCredentials")
            .field("email", &self.email)
            .field("app_password", &"[REDACTED]")
            .finish()
    }
}

/// A mail transport: read messages and send replies.
///
/// Both the Gmail-API (OAuth) backend and the IMAP/SMTP (app-password) backend
/// implement this so the engine's safety gates (at-most-once delivery, burst
/// ceiling, deterministic rejection gate) apply identically regardless of
/// transport. `Provider` supplies `profile`/`list`/`history` for sync; this
/// trait adds the dispatch/lookup surface. Inputs/outputs mirror `Gmail`.
pub trait MailTransport: crate::sync::Provider {
    /// Whether the transport is authorized to send. Input: none (`&self`).
    /// Output: `bool`.
    fn can_send(&self) -> bool;

    /// Send one raw MIME reply. Inputs: `raw` — the full RFC-5322 message;
    /// `thread_id` — the conversation to reply within. Output:
    /// `Result<String, SendFailure>` — the provider id, or a typed failure.
    fn send(&mut self, raw: &str, thread_id: &str) -> Result<String, SendFailure>;

    /// Fetch one full message by its stub. Inputs: `stub` — queued identity.
    /// Output: `Result<Option<Email>, FetchFailure>` — the parsed message
    /// (`None` when gone), or a typed fetch failure.
    fn email(&mut self, stub: &Stub) -> Result<Option<Email>, FetchFailure>;

    /// Fetch one conversation. Inputs: `id` — thread id. Output:
    /// `anyhow::Result<Thread>` — the thread resource.
    fn thread(&mut self, id: &str) -> anyhow::Result<Thread>;

    /// Locate an already-sent message by its RFC 2822 Message-ID. Inputs:
    /// `message_id` — outgoing Message-ID. Output: `Result<Option<String>>` —
    /// the provider message id when found.
    fn find_sent(&mut self, message_id: &str) -> anyhow::Result<Option<String>>;
}

/// `Provider` for a boxed transport so generic sync (`synchronize<P: Provider>`)
/// accepts the engine's `Box<dyn MailTransport>` unchanged. Inputs: as
/// `Provider`; Output: delegates to the inner transport.
impl crate::sync::Provider for Box<dyn MailTransport> {
    fn profile(&mut self) -> anyhow::Result<crate::gmail::Profile> {
        (**self).profile()
    }
    fn list(
        &mut self,
        query: &str,
        page: Option<&str>,
    ) -> anyhow::Result<crate::gmail::MessagePage> {
        (**self).list(query, page)
    }
    fn history(
        &mut self,
        start: &str,
        page: Option<&str>,
    ) -> anyhow::Result<crate::gmail::HistoryResult> {
        (**self).history(start, page)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_exposes_the_app_password() {
        // why: a leaked app password via Debug/logs compromises the mailbox;
        // the Debug impl must redact the secret while keeping the non-secret
        // email for diagnosability.
        let creds = AppPasswordCredentials::new("user@example.com", "supersecretpassword");
        let out = format!("{creds:?}");
        assert!(
            !out.contains("supersecretpassword"),
            "Debug leaked the password: {out}"
        );
        assert!(
            out.contains("[REDACTED]"),
            "Debug must mark the secret redacted"
        );
        assert!(
            out.contains("user@example.com"),
            "Debug keeps the non-secret email"
        );
    }

    #[test]
    fn password_accessor_returns_the_real_secret() {
        // why: the transport needs the actual password to authenticate even
        // though it is hidden from Debug.
        let creds = AppPasswordCredentials::new("user@example.com", "hunter2hunter2");
        assert_eq!(creds.password(), "hunter2hunter2");
        assert_eq!(creds.email, "user@example.com");
    }

    #[test]
    fn app_password_whitespace_is_stripped() {
        // why: Google displays app passwords as four groups of four; stripping
        // whitespace lets either the grouped or continuous form authenticate.
        // NOTE: use only obviously-fake placeholders here — never a real
        // credential, since tests are committed to the repository.
        let grouped = AppPasswordCredentials::new("user@example.com", "abcd efgh ijkl mnop");
        let continuous = AppPasswordCredentials::new("user@example.com", "abcdefghijklmnop");
        assert_eq!(grouped.password(), "abcdefghijklmnop");
        assert_eq!(grouped.password(), continuous.password());
    }
}
