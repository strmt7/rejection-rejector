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
use chrono::{TimeZone, Utc};
use io_imap::client::{ImapClient, ImapClientStd, ImapClientStdConnectOptions};
use io_imap::rfc3501::search::ImapMessageSearchOptions;
use io_imap::types::core::{AString, Vec1};
use io_imap::types::datetime::NaiveDate as ImapDate;
use io_imap::types::mailbox::Mailbox as ImapMailbox;
use io_imap::types::search::SearchKey;
use io_imap::types::sequence::SequenceSet;
use lettre::message::header::{HeaderName, HeaderValue};
use lettre::message::{Mailbox, Message};
use lettre::transport::smtp::authentication::Credentials as SmtpCredentials;
use lettre::{SmtpTransport, Transport};
use mailparse::MailHeaderMap;
use std::collections::BTreeMap;
use url::Url;

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
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ImapSmtpConfig {
    /// IMAP read host (default `imap.gmail.com`).
    pub imap_host: String,
    /// IMAP read port (default `993`, IMAP over TLS).
    pub imap_port: u16,
    /// Whether the IMAP read transport is implicit TLS (`imaps://`). Default
    /// `true` (Gmail). `false` selects cleartext `imap://` (RFC 2595 STARTTLS
    /// deployments and protocol-level tests against a local IMAP double).
    pub imap_secure: bool,
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
            imap_secure: true,
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
    fn fetch_bodies(&self, search: Vec1<SearchKey<'static>>) -> Result<Vec<(u32, Vec<u8>)>> {
        let scheme = if self.config.imap_secure {
            "imaps"
        } else {
            "imap"
        };
        let url = Url::parse(&format!(
            "{scheme}://{}:{}",
            self.config.imap_host, self.config.imap_port
        ))
        .context("invalid IMAP endpoint URL")?;
        let (mut client, _caps) =
            ImapClientStd::connect(&url, ImapClientStdConnectOptions::default())
                .map_err(|e| anyhow!("IMAP connection failed: {e:?}"))?;
        client
            .login(
                self.creds.email.as_str(),
                self.creds.password(),
                Default::default(),
            )
            .map_err(|e| anyhow!("IMAP login failed: {e:?}"))?;
        client
            .select(
                ImapMailbox::try_from("INBOX").map_err(|e| anyhow!("invalid mailbox: {e:?}"))?,
                Default::default(),
            )
            .map_err(|e| anyhow!("select INBOX failed: {e:?}"))?;
        // `uid: true` makes this a UID SEARCH: the returned ids are UIDs, which
        // is what the UID FETCH below and the sync cursor both require. (Plain
        // SEARCH would return sequence numbers and silently fetch wrong bodies.)
        let uids = client
            .search(search, ImapMessageSearchOptions { uid: true })
            .map_err(|e| anyhow!("IMAP search failed: {e:?}"))?;
        if uids.is_empty() {
            let _ = client.logout();
            return Ok(Vec::new());
        }
        // One batched `UID FETCH <set> (UID BODY.PEEK[])` (read-only: never
        // sets \Seen). Bodies stream into a map keyed by the server-reported
        // UID; any fetch failure is propagated, never silently dropped.
        let seq =
            SequenceSet::try_from(uids.clone()).map_err(|e| anyhow!("invalid UID set: {e:?}"))?;
        let mut bodies: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        client
            .fetch_bodies_stream(
                seq,
                true,
                |_u| -> std::io::Result<Vec<u8>> { Ok(Vec::new()) },
                |u, body: Vec<u8>| -> std::io::Result<()> {
                    bodies.insert(u, body);
                    Ok(())
                },
            )
            .map_err(|e| anyhow!("IMAP UID fetch failed: {e:?}"))?;
        let _ = client.logout();
        Ok(bodies.into_iter().collect())
    }

    /// Fetch message refs from the mailbox over IMAP.
    ///
    /// Inputs: `uid_filter` — an IMAP `UID` search term. Output:
    /// `Result<Vec<MessageRef>>` — one ref per message, `id` = UID and
    /// `thread_id` = the `thread_key` conversation root.
    fn fetch_refs(&self, search: Vec1<SearchKey<'static>>) -> Result<Vec<MessageRef>> {
        Ok(self
            .fetch_bodies(search)?
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

/// Translate a sync query into typed IMAP search keys.
///
/// The `sync` layer builds a **Gmail-style** query (`after:<unix> before:<unix>
/// -in:spam …`), but IMAP search uses `SINCE`/`BEFORE` with calendar dates and
/// has no `-in:` keys (selecting `INBOX` already excludes those folders). This
/// maps the two known shapes to typed `SearchKey`s and returns `None` (a
/// fail-closed "match nothing") on anything unrecognized.
///
/// Inputs: `query` — Gmail-style query or an IMAP UID set such as `1:*` / `124:*`.
/// Output: `Option<Vec1<SearchKey<'static>>>` — the IMAP search (a `UID` set or
/// `SINCE`+`BEFORE`), or `None` when the query is unrecognized.
fn gmail_query_to_imap_search(query: &str) -> Option<Vec1<SearchKey<'static>>> {
    let q = query.trim();
    if q.is_empty() {
        // No constraint requested: match everything.
        return Some(Vec1::from(SearchKey::All));
    }
    // A raw UID set (e.g. "1:*", "124:*", "17") is already a valid IMAP filter.
    if q.split([',', ':']).all(|part| {
        !part.is_empty() && part.bytes().all(|b| matches!(b, b'0'..=b'9' | b'*')) // `*` = IMAP wildcard (5:*)
    }) {
        return SequenceSet::try_from(q)
            .ok()
            .map(|seq| Vec1::from(SearchKey::Uid(seq)));
    }
    // Gmail-style date window: extract `after:<ts>` / `before:<ts>`.
    let ts = |key: &str| -> Option<i64> {
        q.split_whitespace()
            .find_map(|tok| tok.strip_prefix(key))
            .and_then(|v| v.parse::<i64>().ok())
    };
    let to_date = |epoch: i64| -> Option<ImapDate> {
        Utc.timestamp_opt(epoch, 0)
            .single()
            .and_then(|d| ImapDate::try_from(d.date_naive()).ok())
    };
    let mut keys: Vec<SearchKey<'static>> = Vec::new();
    if let Some(a) = ts("after:").and_then(to_date) {
        keys.push(SearchKey::Since(a));
    }
    if let Some(b) = ts("before:").and_then(to_date) {
        keys.push(SearchKey::Before(b));
    }
    if keys.is_empty() {
        return None;
    }
    Vec1::try_from(keys).ok()
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

/// Validate a Message-ID/thread token before interpolating it into an IMAP
/// SEARCH string literal.
///
/// Inputs: `id` — the raw token (Message-ID or thread root). Output:
/// `Option<&str>` — the token when it is safe to embed (no `"`, `\`, CR or LF),
/// otherwise `None`. Fail-closed so a malformed id can never inject IMAP search
/// syntax or break the literal.
fn safe_search_token(id: &str) -> Option<&str> {
    let unsafe_char = id.chars().any(|c| matches!(c, '"' | '\\' | '\r' | '\n'));
    if id.is_empty() || unsafe_char {
        None
    } else {
        Some(id)
    }
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

impl crate::sync::Provider for ImapSmtp {
    fn profile(&mut self) -> Result<Profile> {
        // The identity is the configured address; the cursor is established on
        // first sync (see history()). IMAP has no Gmail history id, so the
        // cursor semantics are UID-based and normalized in history().
        Ok(Profile {
            email_address: self.creds.email.clone(),
            // IMAP has no Gmail history id; the sync cursor is the highest UID
            // consumed. "0" is the sentinel baseline meaning "start from the
            // beginning", and it is non-empty so full_sync's baseline check
            // passes (an empty baseline is rejected as "Missing Gmail baseline").
            history_id: "0".to_owned(),
        })
    }

    /// List messages over IMAP. Not yet wired to the IMAP connection.
    ///
    /// Inputs: `_query`, `_page`. Output: always `Err` until the IMAP read
    /// session is connected; callers treat this as "no transport".
    fn list(&mut self, query: &str, _page: Option<&str>) -> Result<MessagePage> {
        let Some(search) = gmail_query_to_imap_search(query) else {
            return Ok(MessagePage {
                messages: Vec::new(),
                next_page_token: None,
            });
        };
        let refs = self.fetch_refs(search)?;
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
        let range = format!("{}:*", cursor.saturating_add(1));
        let seq = SequenceSet::try_from(range.as_str())
            .map_err(|e| anyhow!("invalid UID range: {e:?}"))?;
        let refs = self.fetch_refs(Vec1::from(SearchKey::Uid(seq)))?;
        // Advance the cursor to the highest UID consumed so the next poll only
        // fetches newer messages; an empty page keeps the previous cursor.
        let max_uid = refs
            .iter()
            .filter_map(|m| m.id.parse::<u32>().ok())
            .max()
            .unwrap_or(cursor);
        let messages_added = refs.into_iter().map(|message| Added { message }).collect();
        Ok(HistoryResult::Page(HistoryPage {
            history: vec![HistoryRecord { messages_added }],
            next_page_token: None,
            history_id: max_uid.to_string(),
        }))
    }
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
        let seq = SequenceSet::try_from(uid.to_string().as_str()).map_err(|e| {
            fail(
                FetchFailureKind::Infrastructure,
                format!("invalid UID: {e:?}"),
            )
        })?;
        let bodies = self
            .fetch_bodies(Vec1::from(SearchKey::Uid(seq)))
            .map_err(|e| {
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
        // The thread id is the conversation's root RFC 2822 Message-ID. Find the
        // messages carrying it (as their own Message-ID or in References), then
        // keep the ones whose computed thread key matches — mirroring Gmail's
        // conversation grouping without the Gmail API.
        let Some(id) = safe_search_token(id) else {
            return Ok(crate::gmail::Thread {
                messages: Vec::new(),
            });
        };
        let (Some(field_ref), Some(field_msg), Some(val_a), Some(val_b)) = (
            AString::try_from("References").ok(),
            AString::try_from("Message-ID").ok(),
            AString::try_from(id.to_string()).ok(),
            AString::try_from(id.to_string()).ok(),
        ) else {
            return Ok(crate::gmail::Thread {
                messages: Vec::new(),
            });
        };
        let key = SearchKey::Or(
            Box::new(SearchKey::Header(field_ref, val_a)),
            Box::new(SearchKey::Header(field_msg, val_b)),
        );
        let refs = self.fetch_refs(Vec1::from(key))?;
        let messages = refs
            .into_iter()
            .filter(|r| r.thread_id == id)
            .map(|r| crate::gmail::ThreadMessage {
                id: r.id,
                internal_date: String::new(),
                label_ids: Vec::new(),
            })
            .collect();
        Ok(crate::gmail::Thread { messages })
    }
    /// Locate a sent message by Message-ID via IMAP. Inputs: `message_id` —
    /// outgoing RFC 2822 Message-ID. Output: `Result<Option<String>>` — the UID
    /// when found.
    fn find_sent(&mut self, message_id: &str) -> Result<Option<String>> {
        let Some(mid) = safe_search_token(message_id) else {
            return Ok(None);
        };
        let (Some(field), Some(val)) = (
            AString::try_from("Message-ID").ok(),
            AString::try_from(mid.to_string()).ok(),
        ) else {
            return Ok(None);
        };
        let key = SearchKey::Header(field, val);
        let refs = self.fetch_refs(Vec1::from(key))?;
        Ok(refs.into_iter().next().map(|r| r.id))
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
    fn safe_search_token_rejects_imap_search_injection() {
        // why: a malformed Message-ID with a quote/backslash/newline must be
        // rejected fail-closed before it can inject IMAP SEARCH syntax or break
        // the quoted literal.
        assert_eq!(safe_search_token("<a@b.com>"), Some("<a@b.com>"));
        assert_eq!(safe_search_token(""), None);
        assert_eq!(safe_search_token("a\"b"), None);
        assert_eq!(safe_search_token("a\\\\b"), None);
        assert_eq!(safe_search_token("a\rb"), None);
        assert_eq!(safe_search_token("a\nb"), None);
    }

    // ---- Minimal plain-TCP IMAP double for protocol-level transport tests ----
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    /// Speaks just enough IMAP (greeting, LOGIN, SELECT, SEARCH, UID FETCH,
    /// LOGOUT) over plain TCP to exercise the real io-imap client stack. SEARCH
    /// filtering is faithful for the shapes the transport uses: `ALL`, `UID
    /// <spec>` and quoted-header literals. UIDs are supplied by the test and are
    /// deliberately far from sequence numbers so a seq/uid mix-up is unmistakable.
    struct FakeImap {
        port: u16,
    }

    /// Whether a UID set spec (`a`, `a:b`, `a:*`, comma-separated) covers `uid`.
    fn uid_spec_matches(spec: &str, uid: u32) -> bool {
        spec.split(',').any(|part| {
            let mut bounds = part.split(':');
            let lo: u32 = bounds.next().unwrap_or("0").parse().unwrap_or(0);
            let hi = match bounds.next() {
                Some("*") => u32::MAX,
                Some(v) => v.parse().unwrap_or(u32::MAX),
                None => lo, // a bare number is an exact uid
            };
            uid >= lo && uid <= hi
        })
    }

    /// Faithful-enough SEARCH evaluator for the criteria shapes the transport
    /// emits (`ALL`, `UID <spec>`, `HEADER <field> <value>`, `OR a b`): a
    /// message matches when any quoted/bare literal occurs in its body or any
    /// UID spec covers it. Constraints the double does not model match nothing.
    fn search_matches(command: &str, uid: u32, body: &str) -> bool {
        // Strip the command name so `UID SEARCH …` is not read as `UID` criteria.
        let args = command
            .strip_prefix("UID SEARCH")
            .or_else(|| command.strip_prefix("SEARCH"))
            .unwrap_or(command);
        let tokens: Vec<&str> = args.split_whitespace().collect();
        let mut constrained = false;
        let mut i = 0;
        while i < tokens.len() {
            let tok = tokens[i];
            if tok.eq_ignore_ascii_case("OR") || tok.eq_ignore_ascii_case("NOT") {
                i += 1;
                continue;
            }
            if tok.eq_ignore_ascii_case("ALL") {
                return true;
            }
            if tok.eq_ignore_ascii_case("HEADER") && i + 2 < tokens.len() {
                constrained = true;
                let value = tokens[i + 2].trim_matches('"');
                if !value.is_empty() && body.contains(value) {
                    return true;
                }
                i += 3;
                continue;
            }
            if tok.eq_ignore_ascii_case("UID") && i + 1 < tokens.len() {
                constrained = true;
                if uid_spec_matches(tokens[i + 1], uid) {
                    return true;
                }
                i += 2;
                continue;
            }
            i += 1;
        }
        !constrained && args.trim().is_empty()
    }

    /// Length of a trailing command literal (`... {11}`) in a line segment.
    fn trailing_literal_len(seg: &str) -> Option<usize> {
        let trimmed = seg.trim_end();
        let inner = trimmed.strip_suffix('}')?;
        let open = inner.rfind('{')?;
        inner[open + 1..].parse::<usize>().ok()
    }

    /// Read one logical command line, inlining any `{n}` literals as quoted
    /// strings so callers can treat the command as plain text.
    fn read_command(sock: &mut std::net::TcpStream, buf: &mut Vec<u8>) -> Option<String> {
        let mut out = String::new();
        let mut tmp = [0u8; 4096];
        loop {
            let segment = loop {
                if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
                    let raw: Vec<u8> = buf.drain(..pos + 2).collect();
                    break String::from_utf8_lossy(&raw[..raw.len() - 2]).to_string();
                }
                match sock.read(&mut tmp) {
                    Ok(0) | Err(_) => return None,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                }
            };
            if let Some(n) = trailing_literal_len(&segment) {
                let marker = format!("{{{n}}}");
                out.push_str(segment.trim_end().trim_end_matches(&marker));
                out.push('"');
                while buf.len() < n {
                    match sock.read(&mut tmp) {
                        Ok(0) | Err(_) => return None,
                        Ok(k) => buf.extend_from_slice(&tmp[..k]),
                    }
                }
                let content: Vec<u8> = buf.drain(..n).collect();
                out.push_str(&String::from_utf8_lossy(&content));
                out.push('"');
                continue;
            }
            out.push_str(&segment);
            return Some(out);
        }
    }

    impl FakeImap {
        fn start(messages: Vec<(u32, String)>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake imap");
            let port = listener.local_addr().expect("addr").port();
            thread::spawn(move || {
                // Every transport call opens a fresh connection, so serve them all.
                for sock in listener.incoming() {
                    let Ok(mut sock) = sock else { break };
                    let _ = sock.write_all(b"* OK [CAPABILITY IMAP4rev1] fake ready\r\n");
                    let mut buf: Vec<u8> = Vec::new();
                    while let Some(line) = read_command(&mut sock, &mut buf) {
                        let mut parts = line.splitn(2, ' ');
                        let tag = parts.next().unwrap_or("").to_string();
                        let rest = parts.next().unwrap_or("").to_string();
                        let upper = rest.to_uppercase();
                        if upper.starts_with("LOGOUT") {
                            let _ = sock
                                .write_all(format!("* BYE\r\n{tag} OK LOGOUT done\r\n").as_bytes());
                            break;
                        }
                        if upper.starts_with("LOGIN") {
                            let _ = sock.write_all(format!("{tag} OK LOGIN done\r\n").as_bytes());
                        } else if upper.starts_with("SELECT") {
                            let next = messages.last().map(|m| m.0 + 1).unwrap_or(1);
                            let _ = sock.write_all(
                                format!(
                                    "* {count} EXISTS\r\n* OK [UIDVALIDITY 1]\r\n* OK [UIDNEXT {next}]\r\n* FLAGS (\\Seen)\r\n* OK [PERMANENTFLAGS (\\Seen)]\r\n{tag} OK [READ-WRITE] SELECT done\r\n",
                                    count = messages.len(),
                                )
                                .as_bytes(),
                            );
                        } else if upper.starts_with("UID SEARCH") || upper.starts_with("SEARCH") {
                            let ids = messages
                                .iter()
                                .filter(|(u, b)| search_matches(&rest, *u, b))
                                .map(|(u, _)| u.to_string())
                                .collect::<Vec<_>>()
                                .join(" ");
                            let _ = sock.write_all(
                                format!("* SEARCH {ids}\r\n{tag} OK SEARCH done\r\n").as_bytes(),
                            );
                        } else if upper.starts_with("UID FETCH") || upper.starts_with("FETCH") {
                            let args = rest
                                .strip_prefix("UID FETCH")
                                .or_else(|| rest.strip_prefix("FETCH"))
                                .unwrap_or(&rest);
                            let spec = args.split_whitespace().next().unwrap_or("*");
                            let selected: Vec<_> = messages
                                .iter()
                                .filter(|(u, _)| uid_spec_matches(spec, *u))
                                .collect();
                            let mut out: Vec<u8> = Vec::new();
                            for (i, (uid, body)) in selected.into_iter().enumerate() {
                                out.extend_from_slice(
                                    format!(
                                        "* {} FETCH (UID {} BODY[] {{{}}}\r\n",
                                        i + 1,
                                        uid,
                                        body.len()
                                    )
                                    .as_bytes(),
                                );
                                out.extend_from_slice(body.as_bytes());
                                out.extend_from_slice(b")\r\n");
                            }
                            out.extend_from_slice(format!("{tag} OK FETCH done\r\n").as_bytes());
                            if sock.write_all(&out).is_err() {
                                break;
                            }
                        } else {
                            let _ = sock.write_all(format!("{tag} OK done\r\n").as_bytes());
                        }
                    }
                }
            });
            Self { port }
        }

        fn client(&self) -> ImapSmtp {
            ImapSmtp::new(
                AppPasswordCredentials::new("user@example.com", "abcdefghijklmnop"),
                ImapSmtpConfig {
                    imap_host: "127.0.0.1".to_owned(),
                    imap_port: self.port,
                    imap_secure: false,
                    ..ImapSmtpConfig::default()
                },
            )
        }
    }

    fn two_message_mailbox() -> (FakeImap, Vec<(u32, String)>) {
        let messages = vec![
            (
                12001u32,
                "From: a@x.com\r\nMessage-ID: <m1@x.com>\r\nSubject: One\r\n\r\nhello one"
                    .to_owned(),
            ),
            (
                12002u32,
                "From: b@x.com\r\nMessage-ID: <m2@x.com>\r\nSubject: Two\r\n\r\nhello two"
                    .to_owned(),
            ),
        ];
        (FakeImap::start(messages.clone()), messages)
    }

    #[test]
    fn imap_list_fetches_by_uid_and_keys_threads_by_message_id() {
        // Regression for three real defects: a plain SEARCH returns sequence
        // numbers (fetching wrong bodies), swallowed fetch errors, and thread
        // keys that are Message-IDs failing provider-id validation. UIDs are far
        // from the sequence numbers 1,2 so a mix-up is unmistakable.
        let (fake, _messages) = two_message_mailbox();
        let mut client = fake.client();
        let page = crate::sync::Provider::list(&mut client, "", None).expect("list");
        let ids: Vec<_> = page.messages.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, vec!["12001", "12002"], "must surface the server UIDs");
        assert_eq!(page.messages[0].thread_id, "m1@x.com");
        assert_eq!(page.messages[1].thread_id, "m2@x.com");
        // The Message-ID thread key must survive provider-id validation.
        for m in &page.messages {
            crate::gmail::stub("user@example.com", m.clone())
                .expect("Message-ID thread keys are valid provider ids");
        }
    }

    #[test]
    fn imap_history_advances_and_never_regresss_the_uid_cursor() {
        let (fake, _messages) = two_message_mailbox();
        let mut client = fake.client();
        let HistoryResult::Page(page) =
            crate::sync::Provider::history(&mut client, "0", None).expect("history")
        else {
            panic!("expected a history page");
        };
        assert_eq!(page.history_id, "12002", "cursor advances to the max UID");
        let added = &page.history[0].messages_added;
        assert_eq!(added.len(), 2);
        // A second poll from the advanced cursor sees nothing new and keeps it.
        let HistoryResult::Page(page) =
            crate::sync::Provider::history(&mut client, "12002", None).expect("history 2")
        else {
            panic!("expected a history page");
        };
        assert!(page.history[0].messages_added.is_empty());
        assert_eq!(
            page.history_id, "12002",
            "an empty page must not regress the cursor"
        );
    }

    #[test]
    fn imap_email_parses_a_fetched_message_by_provider_id() {
        let (fake, _messages) = two_message_mailbox();
        let mut client = fake.client();
        let page = crate::sync::Provider::list(&mut client, "", None).expect("list");
        let stub = crate::gmail::stub("user@example.com", page.messages[1].clone()).expect("stub");
        let email = MailTransport::email(&mut client, &stub)
            .expect("email")
            .expect("message present");
        assert_eq!(email.subject, "Two");
        assert_eq!(email.message_id, "<m2@x.com>");
    }

    #[test]
    fn imap_find_sent_locates_a_message_by_message_id() {
        let (fake, _messages) = two_message_mailbox();
        let mut client = fake.client();
        assert_eq!(
            MailTransport::find_sent(&mut client, "<m2@x.com>")
                .expect("find_sent")
                .as_deref(),
            Some("12002")
        );
        assert!(
            MailTransport::find_sent(&mut client, "<nope@x.com>")
                .expect("find_sent")
                .is_none()
        );
    }

    #[test]
    fn imap_thread_groups_by_the_reference_root() {
        let messages = vec![
            (
                12001u32,
                "From: a@x.com\r\nMessage-ID: <root@x.com>\r\n\r\nroot".to_owned(),
            ),
            (
                12002u32,
                "From: a@x.com\r\nMessage-ID: <reply@x.com>\r\nReferences: <root@x.com>\r\n\r\nreply"
                    .to_owned(),
            ),
        ];
        let fake = FakeImap::start(messages);
        let mut client = fake.client();
        let thread = MailTransport::thread(&mut client, "root@x.com").expect("thread");
        let mut ids: Vec<_> = thread.messages.iter().map(|m| m.id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(
            ids,
            vec!["12001", "12002"],
            "the root and its reply group together"
        );
    }

    #[test]
    fn imap_profile_exposes_a_non_empty_uid_baseline() {
        // Regression: full_sync rejects an empty baseline ("Missing Gmail
        // baseline"), so the app-password provider must expose a non-empty sync
        // cursor or the incremental sync can never start.
        let creds = AppPasswordCredentials::new("user@example.com", "abcdefghijklmnop");
        let mut imap = ImapSmtp::new(creds, ImapSmtpConfig::default());
        let profile = crate::sync::Provider::profile(&mut imap).unwrap();
        assert_eq!(profile.email_address, "user@example.com");
        assert!(
            !profile.history_id.is_empty(),
            "the IMAP sync baseline must be non-empty"
        );
    }

    #[test]
    fn imap_smtp_constructs_and_exposes_its_identity_and_defaults() {
        // why: the constructor, identity accessor and endpoint defaults are the
        // seam the engine relies on; regressions here break the app-password path.
        let creds = AppPasswordCredentials::new("user@example.com", "abcdefghijklmnop");
        let imap = ImapSmtp::new(creds, ImapSmtpConfig::default());
        assert_eq!(imap.email(), "user@example.com");
        let cfg = ImapSmtpConfig::default();
        assert_eq!(cfg.imap_host, "imap.gmail.com");
        assert_eq!(cfg.imap_port, 993);
        assert_eq!(cfg.smtp_host, "smtp.gmail.com");
        assert_eq!(cfg.smtp_port, 587);
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
    fn email_from_rfc822_falls_back_to_epoch_on_unparseable_date() {
        // why: an invalid/absent Date must degrade deterministically to the epoch
        // (treated as not-recent) rather than panicking or guessing — the
        // fingerprint must stay stable and the age window must fail closed.
        let stub = Stub {
            account: "me@example.com".to_owned(),
            provider_id: "7".to_owned(),
            thread_id: "t".to_owned(),
            source: crate::types::Source::Gmail,
        };
        let mime = concat!(
            "From: r@co.com\r\nSubject: S\r\nMessage-ID: <x@co.com>\r\n",
            "Date: not-a-date\r\n\r\nbody\r\n"
        );
        let email = email_from_rfc822(mime.as_bytes(), &stub).expect("parse");
        assert_eq!(
            email.received_at.timestamp(),
            0,
            "invalid Date must be the epoch"
        );
    }

    #[test]
    fn email_from_rfc822_missing_optional_headers_are_none_or_empty() {
        // why: reply_to/references are optional; a bare message must parse with
        // them absent (None / empty) rather than fabricating values that would
        // corrupt the fingerprint.
        let stub = Stub {
            account: "me@example.com".to_owned(),
            provider_id: "8".to_owned(),
            thread_id: "t".to_owned(),
            source: crate::types::Source::Gmail,
        };
        let mime = concat!(
            "From: r@co.com\r\nSubject: S\r\nMessage-ID: <y@co.com>\r\n",
            "\r\nbody\r\n"
        );
        let email = email_from_rfc822(mime.as_bytes(), &stub).expect("parse");
        assert_eq!(email.reply_to, None);
        assert!(email.references.is_empty());
        assert_eq!(email.message_id, "<y@co.com>");
    }

    #[test]
    fn gmail_query_to_imap_search_maps_the_sync_window_and_uid_sets() {
        // Empty -> match-all.
        let keys = gmail_query_to_imap_search("")
            .expect("empty is valid")
            .into_inner();
        assert_eq!(keys.len(), 1);
        assert!(matches!(keys[0], SearchKey::All), "{keys:?}");
        // Raw UID sets map to SearchKey::Uid.
        for q in ["1:*", "124:*", "17"] {
            let keys = gmail_query_to_imap_search(q)
                .expect("uid set is valid")
                .into_inner();
            assert_eq!(keys.len(), 1, "{q}");
            assert!(matches!(keys[0], SearchKey::Uid(_)), "{q}: {keys:?}");
        }
        // The sync's Gmail-style window maps to SINCE + BEFORE (typed dates).
        let keys =
            gmail_query_to_imap_search("after:1700000000 before:1700003600 -in:spam -in:trash")
                .expect("window is valid")
                .into_inner();
        assert_eq!(keys.len(), 2, "{keys:?}");
        assert!(matches!(keys[0], SearchKey::Since(_)), "{keys:?}");
        assert!(matches!(keys[1], SearchKey::Before(_)), "{keys:?}");
    }

    #[test]
    fn gmail_query_to_imap_search_fails_closed_on_unrecognized_shapes() {
        // No recognizable window or UID set -> None (the caller matches nothing),
        // never a mailbox-wide fetch and never an IMAP BAD.
        for q in ["from:foo@bar.com", "some random text", "subject:hello"] {
            assert!(gmail_query_to_imap_search(q).is_none(), "{q}");
        }
    }

    #[test]
    fn gmail_query_to_imap_search_maps_unix_timestamps_to_calendar_dates() {
        // 1700000000 == 2023-11-14 22:13:20 UTC -> Since(2023-11-14).
        let keys = gmail_query_to_imap_search("after:1700000000 before:1700003600")
            .expect("window is valid")
            .into_inner();
        match (&keys[0], &keys[1]) {
            (SearchKey::Since(d), SearchKey::Before(b)) => {
                let ds = format!("{d:?}");
                assert!(ds.contains("2023") || ds.contains("14"), "since={ds}");
                let bs = format!("{b:?}");
                assert!(bs.contains("2023") || bs.contains("14"), "before={bs}");
            }
            other => panic!("expected Since+Before, got {other:?}"),
        }
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
