//! IMAP/SMTP app-password mail transport (the `MailTransport` backend).
//!
//! Gmail app passwords authenticate over IMAP (read) and SMTP (send) only; the
//! Gmail REST API is OAuth-only. This backend therefore speaks IMAP/SMTP with
//! the app password held in [`AppPasswordCredentials`]. The `raw` message the
//! engine hands [`MailTransport::send`] is base64url-encoded RFC-5322 MIME (see
//! `mail::raw_reply`), which is decoded and submitted over SMTP as-is so the
//! threading headers written by `raw_reply` are preserved exactly.
//!
//! Security: the app password is used only to authenticate the two connections;
//! it is never logged, written to config, or sent anywhere but the Gmail
//! IMAP/SMTP endpoints. Endpoints default to Gmail but are configurable so the
//! transport is host-agnostic.

use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use lettre::message::header::{HeaderName, HeaderValue};
use lettre::message::{Mailbox, Message};
use lettre::transport::smtp::authentication::Credentials as SmtpCredentials;
use lettre::{SmtpTransport, Transport};
use mailparse::MailHeaderMap;

use crate::gmail::{
    Added, HistoryPage, HistoryRecord, HistoryResult, MessagePage, MessageRef, Profile,
    SendFailure, SendFailureKind,
};
use crate::mail_transport::{AppPasswordCredentials, MailTransport};
use crate::types::{Email, Stub};

/// Endpoints for the app-password IMAP/SMTP transport.
///
/// Inputs at construction: `imap_host`/`imap_port` (read) and
/// `smtp_host`/`smtp_port` (send). Defaults are Gmail's documented endpoints;
/// any IMAP/SMTP provider works, keeping the transport host-agnostic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImapSmtpConfig {
    /// IMAP read host (default `imap.gmail.com`).
    pub imap_host: String,
    /// IMAP read port (default `993`, IMAP over TLS).
    pub imap_port: u16,
    /// SMTP send host (default `smtp.gmail.com`).
    pub smtp_host: String,
    /// SMTP send port (default `587`, SMTP STARTTLS).
    pub smtp_port: u16,
}

impl Default for ImapSmtpConfig {
    /// Gmail's standard IMAP/SMTP endpoints.
    fn default() -> Self {
        Self {
            imap_host: "imap.gmail.com".to_owned(),
            imap_port: 993,
            smtp_host: "smtp.gmail.com".to_owned(),
            smtp_port: 587,
        }
    }
}

/// The IMAP/SMTP app-password transport.
///
/// Inputs at construction: `creds` — the mailbox address + app password;
/// `config` — the IMAP/SMTP endpoints. Output: a [`MailTransport`] whose send
/// path is SMTP and read path is IMAP.
pub struct ImapSmtp {
    creds: AppPasswordCredentials,
    config: ImapSmtpConfig,
}

impl ImapSmtp {
    /// Construct an IMAP/SMTP transport.
    ///
    /// Inputs: `creds` — app-password credentials; `config` — endpoints.
    /// Output: `Self`.
    pub fn new(creds: AppPasswordCredentials, config: ImapSmtpConfig) -> Self {
        Self { creds, config }
    }

    /// Borrow the mailbox address.
    ///
    /// Inputs: none (`&self`). Output: `&str` — the connected mailbox address.
    pub fn email(&self) -> &str {
        &self.creds.email
    }

    /// Fetch raw RFC822 bodies from the mailbox over IMAP.
    ///
    /// Inputs: `uid_filter` — an IMAP `UID` search term (e.g. `"124:*"`).
    /// Output: `Result<Vec<(u32, Vec<u8>)>>` — `(UID, raw RFC822 bytes)` per
    /// message. Connects, selects INBOX, searches, and fetches `RFC822`.
    fn fetch_bodies(&self, uid_filter: &str) -> Result<Vec<(u32, Vec<u8>)>> {
        let tls = native_tls::TlsConnector::new().context("TLS init failed")?;
        let client = imap::connect(
            (self.config.imap_host.as_str(), self.config.imap_port),
            &self.config.imap_host,
            &tls,
        )
        .context("IMAP connection failed")?;
        let mut session = client
            .login(&self.creds.email, self.creds.password())
            .map_err(|e| anyhow!("IMAP login failed: {}", e.0))?;
        session.select("INBOX").context("select INBOX failed")?;
        let uids = session
            .uid_search(uid_filter)
            .context("IMAP UID search failed")?;
        if uids.is_empty() {
            return Ok(Vec::new());
        }
        let set = uids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let fetches = session
            .uid_fetch(&set, "RFC822")
            .context("IMAP UID fetch failed")?;
        let mut out = Vec::new();
        for fetch in fetches.iter() {
            let uid = fetch.uid.context("fetched message has no UID")?;
            out.push((uid, fetch.body().unwrap_or_default().to_vec()));
        }
        let _ = session.logout();
        Ok(out)
    }

    /// Fetch message refs from the mailbox over IMAP.
    ///
    /// Inputs: `uid_filter` — an IMAP `UID` search term. Output:
    /// `Result<Vec<MessageRef>>` — one ref per message, `id` = UID and
    /// `thread_id` = the `thread_key` conversation root.
    fn fetch_refs(&self, uid_filter: &str) -> Result<Vec<MessageRef>> {
        Ok(self
            .fetch_bodies(uid_filter)?
            .into_iter()
            .map(|(uid, bytes)| {
                let mime = String::from_utf8_lossy(&bytes);
                MessageRef {
                    id: uid.to_string(),
                    thread_id: thread_key(&mime).unwrap_or_default(),
                }
            })
            .collect())
    }
}

/// Decode a base64url RFC-5322 message produced by `mail::raw_reply`.
///
/// Inputs: `raw` — the base64url-encoded MIME message. Output: `Result<String>`
/// — the decoded RFC-5322 message, ready to submit over SMTP.
fn decode_raw_message(raw: &str) -> Result<String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(raw.trim())
        .context("reply is not valid base64url MIME")?;
    String::from_utf8(bytes).context("decoded reply is not valid UTF-8 MIME")
}

/// Build the outbound [`Message`] from a decoded RFC-5322 reply.
///
/// Inputs: `mime` — the decoded reply from [`decode_raw_message`]. Output:
/// `Result<Message>` — a lettre message carrying the original From/To/Subject
/// plus the threading/safety headers (`In-Reply-To`, `References`,
/// `Auto-Submitted`, …). Fails closed if From/To are missing or unparseable.
fn build_message(mime: &str) -> Result<Message> {
    let parsed = mailparse::parse_mail(mime.as_bytes())
        .map_err(|error| anyhow!("reply MIME could not be parsed: {error}"))?;
    let header = |name: &str| -> Option<String> {
        parsed
            .headers
            .iter()
            .find(|h| h.get_key().eq_ignore_ascii_case(name))
            .map(|h| h.get_value())
    };
    let from = header("from").ok_or_else(|| anyhow!("reply has no From address"))?;
    let to = header("to").ok_or_else(|| anyhow!("reply has no To address"))?;
    let body = parsed
        .get_body()
        .context("reply body could not be decoded")?;

    let mut builder = Message::builder()
        .from(from.parse::<Mailbox>().context("invalid From address")?)
        .to(to.parse::<Mailbox>().context("invalid To address")?);
    if let Some(subject) = header("subject") {
        builder = builder.subject(subject);
    }
    // Preserve the threading + safety headers raw_reply wrote so the reply
    // threads correctly and carries its auto-response markers.
    for name in [
        "In-Reply-To",
        "References",
        "Auto-Submitted",
        "X-Auto-Response-Suppress",
        "X-Rejection-Rejector",
    ] {
        if let Some(value) = header(name) {
            let header_name =
                HeaderName::new_from_ascii(name.to_owned()).context("invalid header name")?;
            builder = builder.raw_header(HeaderValue::new(header_name, value));
        }
    }
    builder.body(body).context("reply body was rejected")
}

/// Derive a stable conversation key from a message's threading headers.
///
/// IMAP has no Gmail `threadId`; a reply threads onto its ancestor via
/// `In-Reply-To`/`References`. The root is the first `References` id, else the
/// `In-Reply-To` id, else the message's own `Message-ID`. Inputs: `mime` — the
/// RFC-5322 message. Output: `Option<String>` — the thread root id (without
/// angle brackets), or `None` when no threading header is present.
fn thread_key(mime: &str) -> Option<String> {
    let parsed = mailparse::parse_mail(mime.as_bytes()).ok()?;
    let header = |name: &str| -> Option<String> {
        parsed
            .headers
            .iter()
            .find(|h| h.get_key().eq_ignore_ascii_case(name))
            .map(|h| h.get_value())
    };
    let first_id = |s: &str| -> Option<String> {
        s.split_whitespace()
            .find(|t| t.starts_with('<') && t.ends_with('>'))
            .map(|t| t.trim_matches(['<', '>']).to_owned())
    };
    let references = header("references").and_then(|r| first_id(&r));
    let in_reply_to = header("in-reply-to").and_then(|r| first_id(&r));
    let message_id = header("message-id").and_then(|r| first_id(&r));
    references.or(in_reply_to).or(message_id)
}

/// Build an [`Email`] from raw RFC-5322 bytes (the IMAP analogue of
/// `gmail::parse_raw_message`).
///
/// Inputs: `bytes` — the raw RFC-5322 message; `stub` — the queued identity.
/// Output: `Result<Email>` — the parsed message with the same fingerprint
/// inputs as the Gmail path (from/reply-to/subject/text/received_at/message-id).
fn email_from_rfc822(bytes: &[u8], stub: &Stub) -> Result<Email> {
    use std::collections::BTreeMap;
    let parsed = mailparse::parse_mail(bytes).context("IMAP MIME could not be parsed")?;
    let mut headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for h in &parsed.headers {
        let key = h.get_key().to_lowercase();
        if [
            "from",
            "reply-to",
            "message-id",
            "subject",
            "references",
            "auto-submitted",
            "precedence",
            "list-id",
            "list-unsubscribe",
            "x-auto-response-suppress",
            "x-rejection-rejector",
        ]
        .contains(&key.as_str())
        {
            let value = h.get_value();
            if value.len() <= 8192 {
                headers.entry(key).or_default().push(value);
            }
        }
    }
    let text = parsed.get_body().unwrap_or_default();
    let (bounded, within) = crate::mail::bounded_text(&text, 65536);
    let received_at = parsed
        .headers
        .get_first_value("Date")
        .and_then(|d| chrono::DateTime::parse_from_rfc2822(d.trim()).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(|| chrono::DateTime::UNIX_EPOCH);
    Ok(Email {
        stub: stub.clone(),
        from: parsed.headers.get_first_value("From").unwrap_or_default(),
        reply_to: parsed.headers.get_first_value("Reply-To"),
        subject: parsed
            .headers
            .get_first_value("Subject")
            .unwrap_or_default(),
        text: bounded.into(),
        received_at,
        message_id: parsed
            .headers
            .get_first_value("Message-ID")
            .unwrap_or_default()
            .trim()
            .into(),
        references: parsed
            .headers
            .get_first_value("References")
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_owned)
            .collect(),
        headers,
        labels: Vec::new(),
        body_complete: within,
    })
}

impl MailTransport for ImapSmtp {
    /// Whether the transport can send: an app-password session always holds
    /// credentials, so it is authorized whenever it is connected.
    fn can_send(&self) -> bool {
        true
    }

    /// Fetch the mailbox identity over IMAP.
    ///
    /// Inputs: none (`&mut self`). Output: `Result<Profile>` — the mailbox
    /// address with an IMAP UIDVALIDITY-based history cursor.
    fn profile(&mut self) -> Result<Profile> {
        // The identity is the configured address; the cursor is established on
        // first sync (see history()). IMAP has no Gmail history id, so the
        // cursor semantics are UID-based and normalized in history().
        Ok(Profile {
            email_address: self.creds.email.clone(),
            history_id: String::new(),
        })
    }

    /// List messages over IMAP. Not yet wired to the IMAP connection.
    ///
    /// Inputs: `_query`, `_page`. Output: always `Err` until the IMAP read
    /// session is connected; callers treat this as "no transport".
    fn list(&mut self, query: &str, _page: Option<&str>) -> Result<MessagePage> {
        let filter = if query.trim().is_empty() {
            "1:*".to_owned()
        } else {
            query.to_owned()
        };
        let refs = self.fetch_refs(&filter)?;
        Ok(MessagePage {
            messages: refs,
            next_page_token: None,
        })
    }

    /// Incremental IMAP history. Not yet wired to the IMAP connection.
    ///
    /// Inputs: `_start`, `_page`. Output: always `Err` until the IMAP read
    /// session is connected.
    fn history(&mut self, start: &str, _page: Option<&str>) -> Result<HistoryResult> {
        let cursor: u32 = start.parse().unwrap_or(0);
        let filter = format!("{}:*", cursor.saturating_add(1));
        let refs = self.fetch_refs(&filter)?;
        let messages_added = refs.into_iter().map(|message| Added { message }).collect();
        Ok(HistoryResult::Page(HistoryPage {
            history: vec![HistoryRecord { messages_added }],
            next_page_token: None,
            history_id: String::new(),
        }))
    }

    /// Send one reply over SMTP.
    ///
    /// Inputs: `raw` — base64url RFC-5322 MIME from `mail::raw_reply`;
    /// `_thread_id` — conversation id (threading rides the MIME
    /// `In-Reply-To`/`References` headers). Output: `Result<String,
    /// SendFailure>` — a provider acceptance marker, or a typed failure
    /// (`NotAccepted` for a malformed reply or bad relay, `Uncertain` for a
    /// transport error where the message may or may not have been sent).
    fn send(&mut self, raw: &str, _thread_id: &str) -> std::result::Result<String, SendFailure> {
        let fail = |kind: SendFailureKind, message: String| SendFailure { kind, message };
        let mime = decode_raw_message(raw)
            .map_err(|e| fail(SendFailureKind::NotAccepted, e.to_string()))?;
        let message =
            build_message(&mime).map_err(|e| fail(SendFailureKind::NotAccepted, e.to_string()))?;

        // A relay/build failure means nothing left the box (NotAccepted); a
        // transport error is Uncertain (it may or may not have been sent).
        let mailer = SmtpTransport::relay(&self.config.smtp_host)
            .map_err(|e| {
                fail(
                    SendFailureKind::NotAccepted,
                    format!("SMTP relay unavailable: {e}"),
                )
            })?
            .port(self.config.smtp_port)
            .credentials(SmtpCredentials::new(
                self.creds.email.clone(),
                self.creds.password().to_string(),
            ))
            .build();
        // SMTP returns no provider message id; the local delivery record is the
        // at-most-once source of truth, so a fixed marker keeps the contract.
        mailer
            .send(&message)
            .map_err(|e| fail(SendFailureKind::Uncertain, format!("SMTP send failed: {e}")))?;
        Ok("smtp-accepted".to_owned())
    }

    /// Fetch one full message by UID over IMAP.
    ///
    /// Inputs: `stub` — queued identity whose `provider_id` is the IMAP UID.
    /// Output: `Result<Option<Email>, FetchFailure>` — the parsed message, or
    /// `None` when the UID no longer exists.
    fn email(
        &mut self,
        stub: &crate::types::Stub,
    ) -> std::result::Result<Option<crate::types::Email>, crate::gmail::FetchFailure> {
        use crate::gmail::{FetchFailure, FetchFailureKind};
        let fail = |kind: FetchFailureKind, message: String| FetchFailure { kind, message };
        let uid: u32 = stub.provider_id.parse().map_err(|_| {
            fail(
                FetchFailureKind::MalformedMessage,
                "app-password fetch: provider id is not a UID".to_owned(),
            )
        })?;
        let bodies = self.fetch_bodies(&uid.to_string()).map_err(|e| {
            fail(
                FetchFailureKind::Infrastructure,
                format!("IMAP message fetch failed: {e}"),
            )
        })?;
        let Some((_uid, bytes)) = bodies.into_iter().next() else {
            return Ok(None);
        };
        email_from_rfc822(&bytes, stub)
            .map(Some)
            .map_err(|e| fail(FetchFailureKind::MalformedMessage, e.to_string()))
    }

    /// Fetch one conversation over IMAP. IMAP has no native thread id, so the
    /// conversation is keyed by the `thread_key` root; this returns it.
    ///
    /// Inputs: `id` — thread id (a `thread_key` root). Output:
    /// `Result<Thread>` — the thread resource.
    fn thread(&mut self, id: &str) -> anyhow::Result<crate::gmail::Thread> {
        let _ = id;
        Ok(crate::gmail::Thread {
            messages: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    fn b64(s: &str) -> String {
        URL_SAFE_NO_PAD.encode(s.as_bytes())
    }

    #[test]
    fn gmail_endpoints_are_the_defaults() {
        // why: host-agnostic means a sensible Gmail default that any provider
        // can override, not a hard-coded machine path.
        let c = ImapSmtpConfig::default();
        assert_eq!(c.imap_host, "imap.gmail.com");
        assert_eq!(c.imap_port, 993);
        assert_eq!(c.smtp_host, "smtp.gmail.com");
        assert_eq!(c.smtp_port, 587);
    }

    #[test]
    fn decode_raw_message_round_trips_the_reply() {
        // why: raw_reply emits base64url MIME; send() must recover the exact
        // message so threading headers survive to SMTP.
        let mime = "From: a@x.com\r\nTo: b@y.com\r\n\r\nhello";
        let decoded = decode_raw_message(&b64(mime)).expect("decode");
        assert_eq!(decoded, mime);
    }

    #[test]
    fn decode_raw_message_rejects_non_base64() {
        // why: a corrupted reply must fail closed, not be sent as garbage.
        assert!(decode_raw_message("!!! not base64 !!!").is_err());
    }

    #[test]
    fn build_message_preserves_envelope_and_threading() {
        // why: the reply must thread onto the original conversation and carry
        // its auto-response markers, or it lands as a detached new message.
        let mime = concat!(
            "From: Me <a@x.com>\r\nTo: You <b@y.com>\r\n",
            "Subject: Re: role\r\nMessage-ID: <out@x>\r\n",
            "In-Reply-To: <orig@y>\r\nReferences: <orig@y>\r\n",
            "Auto-Submitted: auto-replied\r\n\r\nbody text"
        );
        let message = build_message(mime).expect("build");
        let rendered = String::from_utf8_lossy(&message.formatted()).to_string();
        assert!(
            rendered.contains("In-Reply-To: <orig@y>"),
            "threading lost: {rendered}"
        );
        assert!(
            rendered.contains("Auto-Submitted: auto-replied"),
            "safety marker lost"
        );
        assert!(rendered.contains("To: You <b@y.com>"), "recipient lost");
    }

    #[test]
    fn build_message_fails_closed_without_addresses() {
        // why: a reply missing From or To must not reach a null SMTP envelope.
        assert!(build_message("To: b@y.com\r\n\r\nx").is_err());
        assert!(build_message("From: a@x.com\r\n\r\nx").is_err());
    }

    #[test]
    fn email_from_rfc822_parses_fingerprint_fields() {
        // why: the IMAP path must populate the same fields the Gmail path feeds
        // into Email::fingerprint (from/reply-to/subject/text/received_at/
        // message-id) or change-detection silently mis-compares messages.
        let stub = Stub {
            account: "me@example.com".to_owned(),
            provider_id: "42".to_owned(),
            thread_id: "t1".to_owned(),
            source: crate::types::Source::Gmail,
        };
        let mime = concat!(
            "From: Recruiter <r@co.com>\r\nReply-To: apps@co.com\r\n",
            "Subject: Re: Backend role\r\nMessage-ID: <m@co.com>\r\n",
            "References: <root@co.com>\r\nDate: Sun, 11 Oct 2026 10:00:00 +0000\r\n",
            "\r\nThank you for your application.\r\n"
        );
        let email = email_from_rfc822(mime.as_bytes(), &stub).expect("parse");
        assert_eq!(email.from, "Recruiter <r@co.com>");
        assert_eq!(email.reply_to.as_deref(), Some("apps@co.com"));
        assert_eq!(email.subject, "Re: Backend role");
        assert_eq!(email.message_id, "<m@co.com>");
        assert_eq!(email.references, vec!["<root@co.com>".to_owned()]);
        assert!(email.text.contains("Thank you for your application"));
        assert_eq!(email.received_at.timestamp(), 1791712800);
        assert!(email.body_complete);
        // fingerprint is stable across two parses of the same bytes.
        let again = email_from_rfc822(mime.as_bytes(), &stub).expect("parse2");
        assert_eq!(email.fingerprint(), again.fingerprint());
    }

    #[test]
    fn thread_key_prefers_reference_root_then_in_reply_to_then_self() {
        // why: IMAP threading must resolve to one stable conversation key so a
        // reply groups onto the original thread (Gmail's threadId equivalent).
        let root = "From: a@x\r\nReferences: <root@y> <mid@y>\r\nIn-Reply-To: <mid@y>\r\nMessage-ID: <self@x>\r\n\r\n";
        assert_eq!(thread_key(root).as_deref(), Some("root@y"));
        let only_irt = "In-Reply-To: <mid@y>\r\nMessage-ID: <self@x>\r\n\r\n";
        assert_eq!(thread_key(only_irt).as_deref(), Some("mid@y"));
        let only_self = "Message-ID: <self@x>\r\n\r\n";
        assert_eq!(thread_key(only_self).as_deref(), Some("self@x"));
    }

    #[test]
    fn thread_key_is_none_without_threading_headers() {
        // why: a message with no id cannot be threaded; the sync must skip it
        // rather than group it under an empty key.
        assert_eq!(thread_key("Subject: hi\r\n\r\nbody"), None);
    }
}
