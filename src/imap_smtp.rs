//! IMAP/SMTP app-password mail transport (the `MailTransport` backend).
//!
//! Gmail app passwords authenticate over IMAP (read) and SMTP (send) only; the
//! Gmail REST API is OAuth-only. This backend therefore speaks IMAP/SMTP with
//! the app password held in [`crate::mail_transport::AppPasswordCredentials`]. The `raw` message the
//! engine hands [`crate::mail_transport::MailTransport::send`] is base64url-encoded
//! RFC-5322 MIME (see
//! `mail::raw_reply`), which is decoded and submitted over SMTP as-is so the
//! threading headers written by `raw_reply` are preserved exactly.
//!
//! Security: the app password is used only to authenticate the two connections;
//! it is never logged, written to config, or sent anywhere but the Gmail
//! IMAP/SMTP endpoints. Endpoints default to Gmail but are configurable so the
//! transport is host-agnostic.

use anyhow::{Context, Result, anyhow, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{TimeZone, Utc};
use io_imap::client::{ImapClient, ImapClientStd, ImapClientStdConnectOptions};
use io_imap::rfc3501::login::ImapLoginOptions;
use io_imap::rfc3501::search::ImapMessageSearchOptions;
use io_imap::rfc3501::select::ImapMailboxSelectOptions;
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
    /// Whether the SMTP transport must negotiate TLS. Default `true`
    /// (Gmail). TLS follows the port's IANA semantics: port `465` uses
    /// implicit TLS (SMTPS, `Tls::Wrapper`), every other port negotiates
    /// STARTTLS (Gmail's default `587`). `false` selects a plaintext
    /// transport for protocol-level tests against a local SMTP double;
    /// production never sets it.
    pub smtp_secure: bool,
}

/// The TLS negotiation mode for one SMTP send transport.
///
/// Inputs: none (plain enum). Output: the pairing applied between the
/// configured port and the TLS handshake (`Wrapper` = implicit TLS).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SmtpTlsMode {
    /// Implicit TLS from the first byte (SMTPS, IANA port 465).
    Wrapper,
    /// Plaintext connect upgraded by mandatory STARTTLS (port 587 et al.).
    Starttls,
    /// No TLS at all (local protocol doubles only).
    Plaintext,
}

/// Select the SMTP TLS mode for one configured endpoint.
///
/// Inputs: `secure` — the `smtp_secure` flag; `port` — the configured send
/// port. Output: [`SmtpTlsMode`] — `Wrapper` only on 465, `Starttls` on any
/// other secure port, `Plaintext` when `secure` is `false`.
fn smtp_tls_mode(secure: bool, port: u16) -> SmtpTlsMode {
    match (secure, port) {
        (false, _) => SmtpTlsMode::Plaintext,
        (true, 465) => SmtpTlsMode::Wrapper,
        (true, _) => SmtpTlsMode::Starttls,
    }
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
            smtp_secure: true,
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

/// Hard bound on UIDs one IMAP search may return before the provider refuses
/// to fetch anything at all (security review finding 15): a hostile or broken
/// server cannot make the client materialize an unbounded result set.
///
/// Inputs: none (constant). Output: `usize` — the maximum accepted search
/// result size.
const MAX_SEARCH_UIDS: usize = 5000;
/// Hard bound on one message's raw RFC-5322 bytes while streaming.
///
/// Inputs: none (constant). Output: `usize` — the per-message retention cap.
const MAX_MESSAGE_BYTES: usize = 2 * 1024 * 1024;
/// Hard bound on the aggregate raw bytes one fetch batch may stream.
///
/// Inputs: none (constant). Output: `usize` — the batch-wide byte budget.
const MAX_AGGREGATE_BYTES: usize = 64 * 1024 * 1024;
/// Review items served per list page.
///
/// Inputs: none (constant). Output: `usize` — the page size behind the
/// continuation cursor.
const MAX_PAGE_REFS: usize = 250;
/// Header bytes retained for thread derivation. RFC-5322 headers lead the
/// message, so this window covers the full header block of any message the
/// per-message bound accepts; anything beyond it is never retained.
///
/// Inputs: none (constant). Output: `usize` — the thread-header window.
const THREAD_HEADER_WINDOW: usize = 64 * 1024;

/// What a [`BoundedSink`] does when its retention window fills.
///
/// Inputs: none (plain enum). Output: the overflow policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Overflow {
    /// Refuse further bytes: the whole-message capture must fit or fail.
    Error,
    /// Keep counting toward the aggregate budget but retain nothing beyond
    /// the window (thread-header capture).
    Truncate,
}

/// A streaming write sink bounded per message and across the batch, so
/// oversized literals are refused during streaming — before anything is
/// stored or parsed (security review finding 15).
///
/// Inputs: none (plain struct). Output: the retained bytes under the policy.
struct BoundedSink {
    /// Bytes retained so far.
    buf: Vec<u8>,
    /// Per-message retention window.
    limit: usize,
    /// Policy once the window fills.
    overflow: Overflow,
    /// Batch-wide received-byte counter shared across every sink of one
    /// fetch, enforcing the aggregate budget mid-message.
    shared: std::rc::Rc<std::cell::Cell<u64>>,
    /// Batch-wide received-byte budget enforced against `shared`.
    aggregate_limit: usize,
}

impl BoundedSink {
    /// Create one sink under the shared batch counter.
    ///
    /// Inputs: `limit` — retention window; `overflow` — window policy;
    /// `shared` — batch counter; `aggregate_limit` — batch-wide byte budget.
    /// Output: `Self`.
    fn new(
        limit: usize,
        overflow: Overflow,
        shared: std::rc::Rc<std::cell::Cell<u64>>,
        aggregate_limit: usize,
    ) -> Self {
        Self {
            buf: Vec::new(),
            limit,
            overflow,
            shared,
            aggregate_limit,
        }
    }

    /// Consume the sink, returning only the retained bytes.
    ///
    /// Inputs: none beyond the sink. Output: `Vec<u8>`.
    fn into_inner(self) -> Vec<u8> {
        self.buf
    }
}

impl std::io::Write for BoundedSink {
    /// Accept one streamed chunk under the per-message and aggregate bounds.
    ///
    /// Inputs: `data` — the next contiguous bytes of one message. Output:
    /// `Ok(data.len())` when accepted; `Err` when either budget would be
    /// exceeded under [`Overflow::Error`] (the batch aborts).
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let aggregate = self.shared.get() + data.len() as u64;
        if aggregate > self.aggregate_limit as u64 {
            return Err(std::io::Error::other(
                "IMAP fetch exceeded the aggregate byte budget; nothing further is accepted",
            ));
        }
        self.shared.set(aggregate);
        match self.overflow {
            Overflow::Error if self.buf.len() + data.len() > self.limit => {
                Err(std::io::Error::other(
                    "IMAP message exceeded the per-message byte budget; nothing further is accepted",
                ))
            }
            Overflow::Error => {
                self.buf.extend_from_slice(data);
                Ok(data.len())
            }
            Overflow::Truncate => {
                let room = self.limit.saturating_sub(self.buf.len());
                self.buf.extend_from_slice(&data[..room.min(data.len())]);
                Ok(data.len())
            }
        }
    }

    /// Flush is a no-op: bytes are retained in memory under the bounds.
    ///
    /// Inputs: none. Output: `Ok(())`.
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
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

    /// Fetch raw RFC822 bodies from the mailbox over IMAP under the fixed
    /// streaming bounds.
    ///
    /// Inputs: `search` — typed IMAP search keys. Output:
    /// `Result<Vec<(u32, Vec<u8>)>>` — `(UID, raw RFC822 bytes)` per message,
    /// each message capped at [`MAX_MESSAGE_BYTES`] and the batch at
    /// [`MAX_AGGREGATE_BYTES`] while streaming; a search above
    /// [`MAX_SEARCH_UIDS`] aborts before any fetch. Connects, selects INBOX,
    /// searches, and fetches `RFC822`.
    fn fetch_bodies(&self, search: Vec1<SearchKey<'static>>) -> Result<Vec<(u32, Vec<u8>)>> {
        self.fetch_streamed(
            search,
            MAX_MESSAGE_BYTES,
            Overflow::Error,
            MAX_AGGREGATE_BYTES,
        )
    }

    /// Fetch only the leading header window of each matching message, for
    /// thread derivation.
    ///
    /// Inputs: `search` — typed IMAP search keys. Output:
    /// `Result<Vec<(u32, Vec<u8>)>>` — `(UID, leading bytes)` per message with
    /// at most [`THREAD_HEADER_WINDOW`] bytes retained each (RFC-5322 headers
    /// lead the message); bodies beyond the window are never retained.
    fn fetch_thread_headers(
        &self,
        search: Vec1<SearchKey<'static>>,
    ) -> Result<Vec<(u32, Vec<u8>)>> {
        self.fetch_streamed(
            search,
            THREAD_HEADER_WINDOW,
            Overflow::Truncate,
            MAX_AGGREGATE_BYTES,
        )
    }

    /// Stream one bounded batch of raw RFC-5322 captures from the mailbox.
    ///
    /// The provider-level budgets run at the protocol boundary (security
    /// review finding 15): the search result is capped before any fetch, each
    /// message is streamed into a [`BoundedSink`] that refuses or truncates
    /// past its window, and a shared counter enforces the batch budget
    /// mid-message. Nothing oversized is ever stored or parsed.
    ///
    /// Inputs: `search` — typed IMAP search keys; `limit` — per-message
    /// retention window; `overflow` — window policy; `aggregate_limit` —
    /// batch-wide byte budget. Output: `Result<Vec<(u32, Vec<u8>)>>` — the
    /// captured bytes per UID in ascending UID order.
    fn fetch_streamed(
        &self,
        search: Vec1<SearchKey<'static>>,
        limit: usize,
        overflow: Overflow,
        aggregate_limit: usize,
    ) -> Result<Vec<(u32, Vec<u8>)>> {
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
                ImapLoginOptions::default(),
            )
            .map_err(|e| anyhow!("IMAP login failed: {e:?}"))?;
        client
            .select(
                ImapMailbox::try_from("INBOX").map_err(|e| anyhow!("invalid mailbox: {e:?}"))?,
                ImapMailboxSelectOptions::default(),
            )
            .map_err(|e| anyhow!("select INBOX failed: {e:?}"))?;
        // `uid: true` makes this a UID SEARCH: the returned ids are UIDs, which
        // is what the UID FETCH below and the sync cursor both require. (Plain
        // SEARCH would return sequence numbers and silently fetch wrong bodies.)
        let uids = client
            .search(search, ImapMessageSearchOptions { uid: true })
            .map_err(|e| anyhow!("IMAP search failed: {e:?}"))?;
        ensure!(
            uids.len() <= MAX_SEARCH_UIDS,
            "IMAP search returned {} UIDs, above the {}-UID safety bound; nothing was fetched (cursor retained)",
            uids.len(),
            MAX_SEARCH_UIDS
        );
        if uids.is_empty() {
            let _ = client.logout();
            return Ok(Vec::new());
        }
        // One batched `UID FETCH <set> (UID BODY.PEEK[])` (read-only: never
        // sets \Seen). Bodies stream into bounded sinks keyed by the
        // server-reported UID; any fetch failure is propagated, never silently
        // dropped.
        let seq =
            SequenceSet::try_from(uids.clone()).map_err(|e| anyhow!("invalid UID set: {e:?}"))?;
        let shared = std::rc::Rc::new(std::cell::Cell::new(0u64));
        let mut bodies: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        client
            .fetch_bodies_stream(
                seq,
                true,
                |_u| -> std::io::Result<BoundedSink> {
                    Ok(BoundedSink::new(
                        limit,
                        overflow,
                        shared.clone(),
                        aggregate_limit,
                    ))
                },
                |u, sink: BoundedSink| -> std::io::Result<()> {
                    bodies.insert(u, sink.into_inner());
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
    /// `Result<Vec<MessageRef>>` — one ref per threadable message, `id` = UID
    /// and `thread_id` = the `thread_key` conversation root. Messages without
    /// any threading header are skipped: they cannot be threaded, and an empty
    /// thread key would fail provider-id validation and abort the sync.
    fn fetch_refs(&self, search: Vec1<SearchKey<'static>>) -> Result<Vec<MessageRef>> {
        Ok(self
            .fetch_thread_headers(search)?
            .into_iter()
            .filter_map(|(uid, bytes)| {
                let mime = String::from_utf8_lossy(&bytes);
                thread_key(&mime).map(|thread_id| MessageRef {
                    id: uid.to_string(),
                    thread_id,
                })
            })
            .collect())
    }
}

/// Slice one page of review refs behind an exclusive UID-floor continuation
/// cursor.
///
/// Inputs: `refs` — threadable refs; `floor` — exclusive lower UID bound from
/// the previous page's token (0 = first page). Output:
/// `(Vec<MessageRef>, Option<String>)` — at most [`MAX_PAGE_REFS`] refs in
/// ascending UID order with UIDs at or above the floor, and the next token
/// (the last served UID plus one), or `None` when the feed is exhausted.
fn page_refs(refs: Vec<MessageRef>, floor: u32) -> (Vec<MessageRef>, Option<String>) {
    let mut eligible: Vec<MessageRef> = refs
        .into_iter()
        .filter(|r| r.id.parse::<u32>().is_ok_and(|u| u >= floor))
        .collect();
    eligible.sort_by_key(|r| r.id.parse::<u32>().unwrap_or_default());
    let next_page_token = (eligible.len() > MAX_PAGE_REFS).then(|| {
        (eligible[MAX_PAGE_REFS - 1]
            .id
            .parse::<u32>()
            .unwrap_or_default()
            + 1)
        .to_string()
    });
    eligible.truncate(MAX_PAGE_REFS);
    (eligible, next_page_token)
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
    let mut security_headers_complete = true;
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
            } else {
                // A tracked safety header over the value cap is recorded as
                // dropped without its attacker-sized value: presence-based
                // checks must not read the drop as genuine absence (security
                // review finding 5). Duplicates cannot launder the signal —
                // any oversized tracked occurrence marks the message.
                security_headers_complete = false;
            }
        }
    }
    // One shared bounded recursive extractor for both providers (security
    // review finding 3): attachments and named parts never contribute text,
    // message/rfc822 stays inert and incomplete, and multipart/alternative
    // prefers a nonblank text/plain alternative.
    let (text, mime_complete) = crate::gmail::mime_text(&parsed, 0)?;
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
        body_complete: mime_complete && within,
        security_headers_complete,
    })
}

impl crate::sync::Provider for ImapSmtp {
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
    fn list(&mut self, query: &str, page: Option<&str>) -> Result<MessagePage> {
        let Some(search) = gmail_query_to_imap_search(query) else {
            return Ok(MessagePage {
                messages: Vec::new(),
                next_page_token: None,
            });
        };
        // A continuation token is the exclusive UID floor for the next page
        // (security review finding 15). A malformed token fails closed instead
        // of silently restarting the feed.
        let floor = match page {
            None => 0,
            Some(token) => token
                .parse::<u32>()
                .map_err(|_| anyhow!("Invalid IMAP page token: {token:?}"))?,
        };
        let refs = self.fetch_refs(search)?;
        let (messages, next_page_token) = page_refs(refs, floor);
        Ok(MessagePage {
            messages,
            next_page_token,
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

    /// IMAP/SMTP relays arbitrary raw MIME, so new-message probes work.
    ///
    /// Inputs: none (`&self`). Output: `true`.
    fn supports_selftest_probe(&self) -> bool {
        true
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
        // TLS follows the port's IANA semantics (see `smtp_tls_mode`):
        // pairing implicit TLS with the STARTTLS submission port fails the
        // handshake with a TLS-record error before any bytes are sent.
        let builder = match smtp_tls_mode(self.config.smtp_secure, self.config.smtp_port) {
            SmtpTlsMode::Wrapper => SmtpTransport::relay(&self.config.smtp_host).map_err(|e| {
                fail(
                    SendFailureKind::NotAccepted,
                    format!("SMTP relay unavailable: {e}"),
                )
            })?,
            SmtpTlsMode::Starttls => SmtpTransport::starttls_relay(&self.config.smtp_host)
                .map_err(|e| {
                    fail(
                        SendFailureKind::NotAccepted,
                        format!("SMTP relay unavailable: {e}"),
                    )
                })?,
            SmtpTlsMode::Plaintext => SmtpTransport::builder_dangerous(&self.config.smtp_host),
        };
        let mailer = builder
            .port(self.config.smtp_port)
            .credentials(SmtpCredentials::new(
                self.creds.email.clone(),
                self.creds.password().to_string(),
            ))
            .build();
        // Fail-closed emergency gate at the provider boundary: the sentinel is
        // re-evaluated after all message, credential and transport preparation
        // and immediately before the relay send, so a stop engaged during
        // preparation still leaves the box untouched (security review finding
        // 4). A blocked dispatch is NotAccepted: definitely unsent.
        if let Err(error) = crate::emergency::ensure_dispatch_allowed() {
            return Err(fail(
                SendFailureKind::NotAccepted,
                format!("Emergency stop blocked the SMTP dispatch: {error}"),
            ));
        }
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
                internal_date: String::default(),
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

    // why (selftest routing + stream contract): the IMAP/SMTP relay carries
    // arbitrary raw MIME so live probes are supported (the trait default
    // refuses), and the bounded sink's flush is a no-op by contract — the
    // bytes are already retained in memory under the budgets.
    #[test]
    fn imap_smtp_supports_probes_and_flush_is_a_noop() {
        let creds = AppPasswordCredentials::new("user@example.com", "hunter2hunter2");
        let imap = ImapSmtp::new(creds, ImapSmtpConfig::default());
        assert!(imap.supports_selftest_probe());
        use std::io::Write as _;
        let mut sink = BoundedSink::new(
            8,
            Overflow::Error,
            std::rc::Rc::new(std::cell::Cell::new(0)),
            1024,
        );
        assert!(sink.flush().is_ok());
    }
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    fn b64(s: &str) -> String {
        URL_SAFE_NO_PAD.encode(s.as_bytes())
    }

    #[test]
    fn smtp_tls_mode_pairs_the_handshake_with_the_port_semantics() {
        // Port 465 is IANA implicit-TLS SMTPS; every other secure port
        // negotiates STARTTLS; insecure is test-only plaintext. The old
        // pairing (implicit TLS on 587) failed the Gmail handshake with a
        // TLS-record InvalidContentType error before any bytes were sent.
        assert_eq!(smtp_tls_mode(true, 465), SmtpTlsMode::Wrapper);
        assert_eq!(smtp_tls_mode(true, 587), SmtpTlsMode::Starttls);
        assert_eq!(smtp_tls_mode(true, 25), SmtpTlsMode::Starttls);
        assert_eq!(smtp_tls_mode(false, 465), SmtpTlsMode::Plaintext);
        assert_eq!(smtp_tls_mode(false, 587), SmtpTlsMode::Plaintext);
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

    // ---- Minimal plain-TCP SMTP double for send-path transport tests ----

    /// Captured SMTP exchange: envelope + DATA payload.
    #[derive(Default)]
    struct SmtpCapture {
        mail_from: String,
        rcpt_to: Vec<String>,
        data: String,
        dialog: Vec<String>,
    }

    /// Speaks just enough SMTP (greet, EHLO, AUTH, MAIL, RCPT, DATA, QUIT) to
    /// exercise the real lettre transport stack over plaintext. When `reject`
    /// is set it refuses the envelope with 550 so failure mapping is testable.
    struct FakeSmtp {
        port: u16,
        capture: Arc<Mutex<SmtpCapture>>,
        stop: Arc<std::sync::atomic::AtomicBool>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl Drop for FakeSmtp {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    impl FakeSmtp {
        fn start(reject: bool) -> Self {
            Self::start_with(reject, false)
        }

        /// Like [`FakeSmtp::start`], but with `login_only` the EHLO greeting
        /// advertises just `AUTH LOGIN`, forcing the client through the
        /// three-step challenge instead of single-line `AUTH PLAIN`.
        fn start_with(reject: bool, login_only: bool) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake smtp");
            let port = listener.local_addr().expect("addr").port();
            let capture: Arc<Mutex<SmtpCapture>> = Arc::new(Mutex::new(SmtpCapture::default()));
            let seen = capture.clone();
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let flag = stop.clone();
            let handle = thread::spawn(move || {
                loop {
                    if flag.load(std::sync::atomic::Ordering::SeqCst) {
                        break;
                    }
                    let Ok((mut sock, _)) = listener.accept() else {
                        break;
                    };
                    if flag.load(std::sync::atomic::Ordering::SeqCst) {
                        break;
                    }
                    let mut out = seen.lock().expect("capture");
                    *out = SmtpCapture::default();
                    if sock.write_all(b"220 fake ESMTP ready\r\n").is_err() {
                        continue;
                    }
                    let mut buf: Vec<u8> = Vec::new();
                    let mut tmp = [0u8; 4096];
                    let mut in_data = false;
                    // AUTH LOGIN challenge state: 1 = username expected next,
                    // 2 = password expected next.
                    let mut auth_step = 0u8;
                    loop {
                        let line = loop {
                            if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
                                let raw: Vec<u8> = buf.drain(..pos + 2).collect();
                                break Some(
                                    String::from_utf8_lossy(&raw[..raw.len() - 2]).to_string(),
                                );
                            }
                            match sock.read(&mut tmp) {
                                // EOF is distinct from an empty line: DATA
                                // payloads legitimately contain blank lines.
                                Ok(0) | Err(_) => break None,
                                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                            }
                        };
                        let Some(line) = line else { break };
                        out.dialog.push(format!("C: {line}"));
                        if in_data {
                            if line == "." {
                                in_data = false;
                                if !sock.write_all(b"250 2.0.0 queued\r\n").is_ok() {
                                    break;
                                }
                            } else {
                                out.data.push_str(&line);
                                out.data.push_str("\r\n");
                            }
                            continue;
                        }
                        let upper = line.to_uppercase();
                        if auth_step > 0 {
                            // LOGIN challenge continuation: a bare base64 line
                            // answers the pending username/password prompt.
                            if auth_step == 1 {
                                auth_step = 2;
                                let _ = sock.write_all(b"334 UGFzc3dvcmQ6\r\n");
                            } else {
                                auth_step = 0;
                                let _ = sock.write_all(b"235 2.7.0 ok\r\n");
                            }
                        } else if upper.starts_with("EHLO") {
                            let mechanisms = if login_only {
                                "250-fake\r\n250 AUTH LOGIN\r\n"
                            } else {
                                "250-fake\r\n250 AUTH PLAIN LOGIN\r\n"
                            };
                            let _ = sock.write_all(mechanisms.as_bytes());
                        } else if upper.starts_with("AUTH") {
                            // Single-line AUTH PLAIN, or LOGIN's first step.
                            if upper.starts_with("AUTH LOGIN") && !line.contains(' ') {
                                auth_step = 1;
                                let _ = sock.write_all(b"334 VXNlcm5hbWU6\r\n");
                            } else {
                                let _ = sock.write_all(b"235 2.7.0 ok\r\n");
                            }
                        } else if upper.starts_with("MAIL FROM") {
                            out.mail_from.clone_from(&line);
                            if reject {
                                let _ = sock.write_all(b"550 5.1.0 refused\r\n");
                            } else {
                                let _ = sock.write_all(b"250 2.1.0 ok\r\n");
                            }
                        } else if upper.starts_with("RCPT TO") {
                            out.rcpt_to.push(line.clone());
                            let _ = sock.write_all(b"250 2.1.5 ok\r\n");
                        } else if upper.starts_with("DATA") {
                            in_data = true;
                            let _ = sock.write_all(b"354 go\r\n");
                        } else if upper.starts_with("QUIT") {
                            let _ = sock.write_all(b"221 bye\r\n");
                            break;
                        } else {
                            let _ = sock.write_all(b"250 ok\r\n");
                        }
                    }
                }
            });
            Self {
                port,
                capture,
                stop,
                handle: Some(handle),
            }
        }

        fn client(&self) -> ImapSmtp {
            ImapSmtp::new(
                AppPasswordCredentials::new("user@example.com", "abcdefghijklmnop"),
                ImapSmtpConfig {
                    smtp_host: "127.0.0.1".to_owned(),
                    smtp_port: self.port,
                    smtp_secure: false,
                    ..ImapSmtpConfig::default()
                },
            )
        }

        fn captured(&self) -> SmtpCapture {
            let c = self.capture.lock().expect("capture");
            SmtpCapture {
                mail_from: c.mail_from.clone(),
                rcpt_to: c.rcpt_to.clone(),
                data: c.data.clone(),
                dialog: c.dialog.clone(),
            }
        }
    }

    fn sample_reply_mime() -> String {
        "From: user@example.com\r\nTo: recruiter@corp.com\r\nSubject: Re: Application\r\nIn-Reply-To: <orig@corp.com>\r\nReferences: <orig@corp.com>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nYour process was unfair."
            .to_owned()
    }

    #[test]
    fn smtp_send_delivers_the_exact_envelope_and_payload() {
        // The send path is the only side-effecting transport: the double must
        // observe the account as sender, the recruiter as the sole recipient,
        // and the threading headers + body intact in DATA.
        let fake = FakeSmtp::start(false);
        let mut client = fake.client();
        let raw = b64(&sample_reply_mime());
        let id = match MailTransport::send(&mut client, &raw, "orig@corp.com") {
            Ok(id) => id,
            Err(e) => panic!("send failed: {e:?} dialog={:?}", fake.captured().dialog),
        };
        assert_eq!(id, "smtp-accepted");
        let seen = fake.captured();
        assert!(
            seen.mail_from.to_lowercase().contains("user@example.com"),
            "envelope sender must be the account: {}",
            seen.mail_from
        );
        assert_eq!(seen.rcpt_to.len(), 1, "exactly one recipient");
        assert!(
            seen.rcpt_to[0]
                .to_lowercase()
                .contains("recruiter@corp.com")
        );
        assert!(
            seen.data.contains("In-Reply-To: <orig@corp.com>"),
            "threading lost"
        );
        assert!(
            seen.data.contains("References: <orig@corp.com>"),
            "threading lost"
        );
        assert!(seen.data.contains("Your process was unfair."), "body lost");
    }

    #[test]
    fn smtp_send_is_blocked_at_the_sink_by_the_emergency_gate() {
        // why (security review finding 4): the emergency gate must fire at the
        // provider boundary after all preparation — a stop engaged late still
        // means zero provider requests, and the blocked dispatch classifies as
        // NotAccepted (definitely unsent) for the at-most-once ledger. The
        // probe and the live self-test reach the relay only through this same
        // sealed send, so the gate covers every caller.
        let fake = FakeSmtp::start(false);
        let mut client = fake.client();
        let raw = b64(&sample_reply_mime());
        let outcome = crate::test_support::with_dispatch_gate(
            std::sync::Arc::new(|| Err(anyhow::anyhow!("Enterprise emergency stop is active"))),
            || MailTransport::send(&mut client, &raw, "orig@corp.com"),
        );
        let failure = outcome.expect_err("the emergency gate must block the send");
        assert_eq!(failure.kind, SendFailureKind::NotAccepted);
        let seen = fake.captured();
        assert!(
            !seen
                .dialog
                .iter()
                .any(|line| line.to_uppercase().contains("DATA")),
            "no message may reach the relay: {:?}",
            seen.dialog
        );
    }

    #[test]
    fn every_unsafe_sentinel_state_blocks_the_smtp_sink_with_zero_sends() {
        // why (security review finding 4): the report's acceptance matrix —
        // active, malformed, non-regular and uninspectable sentinel states
        // must all produce zero live-self-test/SMTP sends — is proven through
        // the real evaluation behind the real transport sink, state by state.
        let root = tempfile::tempdir().unwrap();
        let active = root.path().join("stop");
        std::fs::write(&active, b"incident").unwrap();
        let directory = root.path().join("stop-dir");
        std::fs::create_dir_all(&directory).unwrap();
        let absent = root.path().join("absent");
        let states: [(&str, std::ffi::OsString); 4] = [
            ("active", active.as_os_str().to_owned()),
            ("malformed", std::ffi::OsString::new()),
            ("non-regular", directory.as_os_str().to_owned()),
            ("uninspectable", std::ffi::OsString::from("relative.stop")),
        ];
        for (name, value) in states {
            let fake = FakeSmtp::start(false);
            let mut client = fake.client();
            let raw = b64(&sample_reply_mime());
            let gate_value = value.clone();
            let outcome = crate::test_support::with_dispatch_gate(
                std::sync::Arc::new(move || {
                    crate::emergency::ensure_dispatch_allowed_for(Some(gate_value.clone()))
                }),
                || MailTransport::send(&mut client, &raw, "orig@corp.com"),
            );
            let failure = outcome
                .map(|_| ())
                .expect_err("an unsafe sentinel state must block the provider sink");
            assert_eq!(failure.kind, SendFailureKind::NotAccepted, "{name}");
            assert!(
                !fake
                    .captured()
                    .dialog
                    .iter()
                    .any(|line| line.to_uppercase().contains("DATA")),
                "{name}: zero sends may reach the relay"
            );
        }
        // The only state that permits dispatch is an absent sentinel.
        let fake = FakeSmtp::start(false);
        let mut client = fake.client();
        let raw = b64(&sample_reply_mime());
        let allowed = crate::test_support::with_dispatch_gate(
            std::sync::Arc::new(move || {
                crate::emergency::ensure_dispatch_allowed_for(Some(absent.as_os_str().to_owned()))
            }),
            || MailTransport::send(&mut client, &raw, "orig@corp.com"),
        );
        assert!(allowed.is_ok(), "an absent sentinel permits dispatch");
    }

    #[test]
    fn smtp_send_maps_a_rejected_envelope_to_uncertain() {
        // A server-side refusal is a transport error: the message may or may
        // not have been processed, so the failure must be Uncertain (durable
        // at-most-once records) rather than NotAccepted.
        let fake = FakeSmtp::start(true);
        let mut client = fake.client();
        let raw = b64(&sample_reply_mime());
        let error = MailTransport::send(&mut client, &raw, "orig@corp.com").unwrap_err();
        assert_eq!(error.kind, SendFailureKind::Uncertain, "{error:?}");
        assert!(
            error.message.contains("SMTP send failed"),
            "{}",
            error.message
        );
    }

    // ---- Minimal plain-TCP IMAP double for protocol-level transport tests ----
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    /// Speaks just enough IMAP (greeting, LOGIN, SELECT, SEARCH, UID FETCH,
    /// LOGOUT) over plain TCP to exercise the real io-imap client stack. SEARCH
    /// filtering is faithful for the shapes the transport uses: `ALL`, `UID
    /// <spec>` and quoted-header literals. UIDs are supplied by the test and are
    /// deliberately far from sequence numbers so a seq/uid mix-up is unmistakable.
    /// Protocol failure the double serves in place of the happy path, so the
    /// transport's error mapping can be asserted against tagged rejections.
    #[derive(Clone, Copy, Debug)]
    enum ImapFault {
        /// Tagged `NO` to LOGIN (rejected credentials).
        RefuseLogin,
        /// Tagged `NO` to SELECT.
        DenySelect,
        /// Tagged `BAD` to SEARCH.
        BadSearch,
        /// Tagged `NO` to UID FETCH.
        FailFetch,
    }

    struct FakeImap {
        port: u16,
        stop: Arc<std::sync::atomic::AtomicBool>,
        hits: Arc<std::sync::atomic::AtomicUsize>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl FakeImap {
        /// Unblock `accept`, end the serve loop and reap the thread so no test
        /// leaves a listener or thread behind (long suites would leak both).
        fn shutdown(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }

        /// Connections accepted so far (the shutdown poke is excluded), so
        /// fail-closed paths can prove they never touched the network.
        fn hits(&self) -> usize {
            self.hits.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl Drop for FakeImap {
        fn drop(&mut self) {
            self.shutdown();
        }
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

    /// Split command arguments into tokens, keeping double-quoted spans (the
    /// double's inlined literals) together so values carrying spaces survive.
    fn split_command_tokens(args: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut current = String::default();
        let mut quoted = false;
        for ch in args.chars() {
            match ch {
                '"' => {
                    quoted = !quoted;
                    current.push(ch);
                }
                c if c.is_whitespace() && !quoted => {
                    if !current.is_empty() {
                        tokens.push(std::mem::take(&mut current));
                    }
                }
                c => current.push(c),
            }
        }
        if !current.is_empty() {
            tokens.push(current);
        }
        tokens
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
        let tokens = split_command_tokens(args);
        let mut constrained = false;
        let mut i = 0;
        while i < tokens.len() {
            let tok = tokens[i].as_str();
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
                if uid_spec_matches(&tokens[i + 1], uid) {
                    return true;
                }
                i += 2;
                continue;
            }
            i += 1;
        }
        !constrained && args.trim().is_empty()
    }

    /// Size and mode of a trailing command literal (`... {11}` synchronizing,
    /// `... {11+}` non-synchronizing) in a line segment.
    fn trailing_literal_len(seg: &str) -> Option<(usize, bool)> {
        let trimmed = seg.trim_end();
        let inner = trimmed.strip_suffix('}')?;
        let open = inner.rfind('{')?;
        let (digits, non_sync) = inner[open + 1..]
            .strip_suffix('+')
            .map_or((&inner[open + 1..], false), |d| (d, true));
        Some((digits.parse::<usize>().ok()?, non_sync))
    }

    /// Read one logical command line, inlining any `{n}` literals as quoted
    /// strings so callers can treat the command as plain text.
    fn read_command(sock: &mut std::net::TcpStream, buf: &mut Vec<u8>) -> Option<String> {
        let mut out = String::default();
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
            if let Some((n, non_sync)) = trailing_literal_len(&segment) {
                let marker = if non_sync {
                    format!("{{{n}+}}")
                } else {
                    format!("{{{n}}}")
                };
                out.push_str(segment.trim_end().trim_end_matches(&marker));
                out.push('"');
                if !non_sync {
                    // A synchronizing literal pauses the client until the
                    // server grants a continuation request.
                    if sock.write_all(b"+ Continue\r\n").is_err() {
                        return None;
                    }
                }
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
            Self::start_with_fault(messages, None)
        }

        /// The injected protocol fault's canned reply for one tagged command.
        ///
        /// Inputs: `fault` - the scripted fault; `tag` - the command tag;
        /// `upper` - the uppercased command text. Output: `Some(reply)` when
        /// the fault applies to this command, `None` otherwise.
        fn canned_fault_reply(fault: &Option<ImapFault>, tag: &str, upper: &str) -> Option<String> {
            match fault {
                Some(ImapFault::RefuseLogin) if upper.starts_with("LOGIN") => {
                    Some(format!("{tag} NO [AUTHENTICATIONFAILED] login refused\r\n"))
                }
                Some(ImapFault::DenySelect) if upper.starts_with("SELECT") => {
                    Some(format!("{tag} NO select refused\r\n"))
                }
                Some(ImapFault::BadSearch)
                    if upper.starts_with("UID SEARCH") || upper.starts_with("SEARCH") =>
                {
                    Some(format!("{tag} BAD search refused\r\n"))
                }
                Some(ImapFault::FailFetch)
                    if upper.starts_with("UID FETCH") || upper.starts_with("FETCH") =>
                {
                    Some(format!("{tag} NO fetch refused\r\n"))
                }
                _ => None,
            }
        }

        /// Render one FETCH response for the scripted mailbox.
        ///
        /// Inputs: `messages` - the scripted (uid, body) mailbox; `tag` - the
        /// command tag; `rest` - the command text after the tag. Output: the
        /// exact response bytes (literal-framed bodies plus the tagged OK).
        fn fetch_reply(messages: &[(u32, String)], tag: &str, rest: &str) -> Vec<u8> {
            let args = rest
                .strip_prefix("UID FETCH")
                .or_else(|| rest.strip_prefix("FETCH"))
                .unwrap_or(rest);
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
            out
        }

        /// Write the tagged reply for one non-faulted IMAP command.
        ///
        /// Inputs: `sock` - the connection; `messages` - the scripted mailbox;
        /// `tag`/`rest`/`upper` - the parsed command. Output: `true` to keep
        /// reading commands, `false` when the session must end (LOGOUT, or a
        /// FETCH write failure - the other arms ignore write errors exactly as
        /// before).
        fn write_reply(
            sock: &mut std::net::TcpStream,
            messages: &[(u32, String)],
            tag: &str,
            rest: &str,
            upper: &str,
        ) -> bool {
            if upper.starts_with("LOGOUT") {
                let _ = sock.write_all(format!("* BYE\r\n{tag} OK LOGOUT done\r\n").as_bytes());
                return false;
            }
            if upper.starts_with("UID FETCH") || upper.starts_with("FETCH") {
                let out = Self::fetch_reply(messages, tag, rest);
                return sock.write_all(&out).is_ok();
            }
            let reply = if upper.starts_with("LOGIN") {
                format!("{tag} OK LOGIN done\r\n")
            } else if upper.starts_with("SELECT") {
                let next = messages.last().map(|m| m.0 + 1).unwrap_or(1);
                format!(
                    "* {count} EXISTS\r\n* OK [UIDVALIDITY 1]\r\n* OK [UIDNEXT {next}]\r\n* FLAGS (\\Seen)\r\n* OK [PERMANENTFLAGS (\\Seen)]\r\n{tag} OK [READ-WRITE] SELECT done\r\n",
                    count = messages.len(),
                )
            } else if upper.starts_with("UID SEARCH") || upper.starts_with("SEARCH") {
                let ids = messages
                    .iter()
                    .filter(|(u, b)| search_matches(rest, *u, b))
                    .map(|(u, _)| u.to_string())
                    .collect::<Vec<_>>()
                    .join(" ");
                format!("* SEARCH {ids}\r\n{tag} OK SEARCH done\r\n")
            } else {
                format!("{tag} OK done\r\n")
            };
            let _ = sock.write_all(reply.as_bytes());
            true
        }

        fn start_with_fault(messages: Vec<(u32, String)>, fault: Option<ImapFault>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake imap");
            let port = listener.local_addr().expect("addr").port();
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let flag = stop.clone();
            let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counted = hits.clone();
            let handle = thread::spawn(move || {
                // Every transport call opens a fresh connection, so serve them
                // all until shutdown() pokes the listener.
                loop {
                    if flag.load(std::sync::atomic::Ordering::SeqCst) {
                        break;
                    }
                    let Ok((mut sock, _)) = listener.accept() else {
                        break;
                    };
                    if flag.load(std::sync::atomic::Ordering::SeqCst) {
                        break;
                    }
                    counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let _ = sock.write_all(b"* OK [CAPABILITY IMAP4rev1] fake ready\r\n");
                    let mut buf: Vec<u8> = Vec::new();
                    while let Some(line) = read_command(&mut sock, &mut buf) {
                        let (tag, rest) = match line.split_once(' ') {
                            Some((tag, rest)) => (tag.to_string(), rest.to_string()),
                            None => (line.clone(), String::default()),
                        };
                        let upper = rest.to_uppercase();
                        let fault_reply = Self::canned_fault_reply(&fault, &tag, &upper);
                        if let Some(reply) = fault_reply {
                            let _ = sock.write_all(reply.as_bytes());
                            continue;
                        }
                        if !Self::write_reply(&mut sock, &messages, &tag, &rest, &upper) {
                            break;
                        }
                    }
                }
            });
            Self {
                port,
                stop,
                hits,
                handle: Some(handle),
            }
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

    // why (security review finding 15): a hostile server search result above
    // the UID safety bound must abort before any body fetch — the provider
    // refuses to materialize an unbounded result set at all.
    #[test]
    fn hostile_search_results_abort_before_any_fetch() {
        let messages: Vec<(u32, String)> = (1..=5001)
            .map(|u| {
                (
                    u,
                    format!("From: a@x.com\r\nMessage-ID: <m{u}@x.com>\r\n\r\nbody {u}"),
                )
            })
            .collect();
        let fake = FakeImap::start(messages);
        let client = fake.client();
        let error = client.fetch_bodies(Vec1::from(SearchKey::All)).unwrap_err();
        assert!(error.to_string().contains("safety bound"), "{error}");
    }

    // why (security review finding 15): a single oversized message literal is
    // refused while streaming — nothing above the per-message budget is ever
    // stored or parsed.
    #[test]
    fn oversized_messages_are_refused_while_streaming() {
        let body = format!(
            "From: a@x.com\r\nMessage-ID: <big@x.com>\r\nSubject: Big\r\n\r\n{}",
            "x".repeat(MAX_MESSAGE_BYTES + 1024)
        );
        let fake = FakeImap::start(vec![(7, body)]);
        let client = fake.client();
        let error = client.fetch_bodies(Vec1::from(SearchKey::All)).unwrap_err();
        assert!(error.to_string().contains("byte budget"), "{error}");
    }

    // why (security review finding 15): the batch-wide byte budget is
    // enforced mid-stream by the shared counter, not after everything lands.
    #[test]
    fn aggregate_byte_budget_aborts_the_batch_mid_stream() {
        let messages = vec![(1u32, "x".repeat(1000)), (2u32, "y".repeat(1000))];
        let fake = FakeImap::start(messages);
        let client = fake.client();
        let error = client
            .fetch_streamed(Vec1::from(SearchKey::All), 1024, Overflow::Error, 1536)
            .unwrap_err();
        assert!(
            error.to_string().contains("aggregate byte budget"),
            "{error}"
        );
    }

    // why (security review finding 15): thread derivation must never retain
    // message bodies — only the leading header window, and it must still
    // thread.
    #[test]
    fn thread_derivation_retains_only_the_header_window() {
        let body = format!(
            "From: a@x.com\r\nMessage-ID: <win@x.com>\r\n\r\n{}",
            "z".repeat(THREAD_HEADER_WINDOW * 2)
        );
        let fake = FakeImap::start(vec![(3, body)]);
        let client = fake.client();
        let captures = client
            .fetch_thread_headers(Vec1::from(SearchKey::All))
            .expect("fetch");
        assert_eq!(captures.len(), 1);
        assert!(captures[0].1.len() <= THREAD_HEADER_WINDOW);
        let mime = String::from_utf8_lossy(&captures[0].1);
        assert!(
            thread_key(&mime).is_some(),
            "the header window still threads"
        );
    }

    // why (security review finding 15): continuation cursors are real —
    // bounded pages behind an exclusive UID floor, with unsorted server order
    // normalized and no feed restart.
    #[test]
    fn page_refs_serve_bounded_pages_behind_uid_floor_cursors() {
        let refs: Vec<MessageRef> = (1..=300)
            .map(|u| MessageRef {
                id: u.to_string(),
                thread_id: format!("t{u}"),
            })
            .collect();
        let (first, token) = page_refs(refs.clone(), 0);
        assert_eq!(first.len(), MAX_PAGE_REFS);
        assert_eq!(token.as_deref(), Some("251"));
        let (second, end) = page_refs(refs, token.unwrap().parse().unwrap());
        assert_eq!(second.len(), 50);
        assert!(end.is_none());
        let mixed = vec![
            MessageRef {
                id: "30".into(),
                thread_id: "c".into(),
            },
            MessageRef {
                id: "10".into(),
                thread_id: "a".into(),
            },
            MessageRef {
                id: "20".into(),
                thread_id: "b".into(),
            },
        ];
        let (page, _) = page_refs(mixed, 20);
        assert_eq!(
            page.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["20", "30"]
        );
    }

    // why (security review finding 15): a malformed continuation token fails
    // closed instead of silently restarting the feed from the beginning.
    #[test]
    fn malformed_page_tokens_fail_closed() {
        let (fake, _messages) = two_message_mailbox();
        let mut client = fake.client();
        let Err(error) = crate::sync::Provider::list(&mut client, "", Some("junk")) else {
            panic!("a malformed page token must fail closed");
        };
        assert!(
            error.to_string().contains("Invalid IMAP page token"),
            "{error}"
        );
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

    /// Stub bound to the test account with the given provider identity.
    fn stub_with(provider_id: &str, thread_id: &str) -> Stub {
        Stub {
            account: "user@example.com".to_owned(),
            provider_id: provider_id.to_owned(),
            thread_id: thread_id.to_owned(),
            source: crate::types::Source::Gmail,
        }
    }

    /// `depth` nested `multipart/mixed` wrappers: past mailparse's own
    /// recursion limit the parser fails, which is the deterministic way to
    /// make `parse_mail` return `Err` for a malformed-message test.
    fn deeply_nested_mime(depth: usize) -> String {
        let mut body = String::from("Content-Type: text/plain\r\n\r\nleaf");
        for level in (0..depth).rev() {
            let boundary = format!("deep{level}end");
            body = format!(
                "Content-Type: multipart/mixed; boundary={boundary}\r\n\r\n--{boundary}\r\n{body}\r\n--{boundary}--\r\n"
            );
        }
        body
    }

    /// Why: the exact error context is the operator's diagnosis — "bad
    /// password" must never blur into "network down". Each tagged protocol
    /// rejection from the double must surface its own distinct context, and a
    /// refused connection must map to the connection context.
    #[test]
    fn imap_protocol_failures_map_to_exact_error_contexts() {
        use crate::sync::Provider;
        let messages = || {
            vec![(
                12001u32,
                "From: a@x.com\r\nMessage-ID: <m1@x.com>\r\n\r\nhello".to_owned(),
            )]
        };
        // No listener behind the endpoint (secure scheme): connection failure.
        let mut dead = ImapSmtp::new(
            AppPasswordCredentials::new("user@example.com", "abcdefghijklmnop"),
            ImapSmtpConfig {
                imap_host: "127.0.0.1".to_owned(),
                imap_port: 0,
                imap_secure: true,
                ..ImapSmtpConfig::default()
            },
        );
        let error = match Provider::list(&mut dead, "1:*", None) {
            Err(error) => error,
            Ok(_) => panic!("a refused connection must surface an error"),
        };
        assert!(
            error.to_string().starts_with("IMAP connection failed: "),
            "unexpected error: {error:#}"
        );
        for (fault, expected) in [
            (ImapFault::RefuseLogin, "IMAP login failed: "),
            (ImapFault::DenySelect, "select INBOX failed: "),
            (ImapFault::BadSearch, "IMAP search failed: "),
            (ImapFault::FailFetch, "IMAP UID fetch failed: "),
        ] {
            let fake = FakeImap::start_with_fault(messages(), Some(fault));
            let mut client = fake.client();
            let error = match Provider::list(&mut client, "1:*", None) {
                Err(error) => error,
                Ok(_) => panic!("fault {fault:?} must surface an error"),
            };
            assert!(
                error.to_string().starts_with(expected),
                "fault {fault:?}: unexpected error: {error:#}"
            );
        }
    }

    /// Why: the queue classifies fetch failures by kind — a bad provider id or
    /// a parser-fatal payload is `MalformedMessage`, while transport and
    /// protocol failures are `Infrastructure` and must leave the queued item
    /// untouched; a vanished UID is not a failure at all. The error texts are
    /// what the operator sees, so they are pinned exactly.
    #[test]
    fn imap_email_failures_classify_ids_transport_and_parser_errors() {
        use crate::gmail::FetchFailureKind;
        let (fake, _messages) = two_message_mailbox();
        let mut client = fake.client();
        // provider_id that is not a UID: refused before any search.
        let failure = MailTransport::email(&mut client, &stub_with("msg-1", "t")).unwrap_err();
        assert_eq!(failure.kind, FetchFailureKind::MalformedMessage);
        assert_eq!(
            failure.message,
            "app-password fetch: provider id is not a UID"
        );
        // A UID that no longer exists is Ok(None), never an error.
        assert!(
            MailTransport::email(&mut client, &stub_with("99999", "t"))
                .expect("vanished uid")
                .is_none()
        );
        // Transport failure: Infrastructure with the wrapped fetch context.
        let mut dead = ImapSmtp::new(
            AppPasswordCredentials::new("user@example.com", "abcdefghijklmnop"),
            ImapSmtpConfig {
                imap_host: "127.0.0.1".to_owned(),
                imap_port: 0,
                imap_secure: true,
                ..ImapSmtpConfig::default()
            },
        );
        let failure = MailTransport::email(&mut dead, &stub_with("7", "t")).unwrap_err();
        assert_eq!(failure.kind, FetchFailureKind::Infrastructure);
        assert!(
            failure
                .message
                .starts_with("IMAP message fetch failed: IMAP connection failed: "),
            "{}",
            failure.message
        );
        // A payload the MIME parser cannot survive is malformed, not phantom.
        let fake = FakeImap::start(vec![(12003, deeply_nested_mime(120))]);
        let mut client = fake.client();
        let failure = MailTransport::email(&mut client, &stub_with("12003", "t")).unwrap_err();
        assert_eq!(failure.kind, FetchFailureKind::MalformedMessage);
        assert_eq!(failure.message, "IMAP MIME could not be parsed");
    }

    /// Why: `send` maps every pre-dispatch defect to `NotAccepted` with the
    /// exact operator-facing reason; anything that lets garbage reach the SMTP
    /// double would produce a wrong-but-plausible delivery record downstream.
    #[test]
    fn smtp_send_maps_malformed_replies_to_not_accepted() {
        let fake = FakeSmtp::start(false);
        let mut client = fake.client();
        for (raw, expected) in [
            (
                "!!! not base64 !!!".to_owned(),
                "reply is not valid base64url MIME",
            ),
            (
                URL_SAFE_NO_PAD.encode([0xff, 0xfe]),
                "decoded reply is not valid UTF-8 MIME",
            ),
            (b64("To: b@y.com\r\n\r\nx"), "reply has no From address"),
            (b64("From: a@x.com\r\n\r\nx"), "reply has no To address"),
            (
                b64("From: not-an-address\r\nTo: b@y.com\r\n\r\nx"),
                "invalid From address",
            ),
            (
                b64("From: a@x.com\r\nTo: not-an-address\r\n\r\nx"),
                "invalid To address",
            ),
        ] {
            let error = MailTransport::send(&mut client, &raw, "t").unwrap_err();
            assert_eq!(error.kind, SendFailureKind::NotAccepted, "{expected}");
            assert_eq!(error.message, expected);
        }
        assert!(
            fake.captured().dialog.is_empty(),
            "malformed replies must never reach the wire: {:?}",
            fake.captured().dialog
        );
    }

    /// Why: the production send path uses the TLS-required relay builder; a
    /// transport failure there is `Uncertain` (the message may or may not have
    /// left) so the at-most-once delivery record holds instead of replaying.
    #[test]
    fn smtp_send_over_secure_relay_classifies_transport_failure_as_uncertain() {
        let mut client = ImapSmtp::new(
            AppPasswordCredentials::new("user@example.com", "abcdefghijklmnop"),
            ImapSmtpConfig {
                smtp_host: "127.0.0.1".to_owned(),
                smtp_port: 0,
                smtp_secure: true,
                ..ImapSmtpConfig::default()
            },
        );
        let error = MailTransport::send(&mut client, &b64(&sample_reply_mime()), "orig@corp.com")
            .unwrap_err();
        assert!(
            error.message.starts_with("SMTP send failed: "),
            "unexpected error: {}",
            error.message
        );
        assert_eq!(error.kind, SendFailureKind::Uncertain, "{error:?}");
    }

    /// Why: AUTH LOGIN is the fallback mechanism when a server does not offer
    /// AUTH PLAIN; the three-step challenge must complete or sends against such
    /// servers would fail after the envelope was accepted.
    #[test]
    fn smtp_send_completes_the_three_step_login_challenge() {
        let fake = FakeSmtp::start_with(false, true);
        let mut client = fake.client();
        let id = MailTransport::send(&mut client, &b64(&sample_reply_mime()), "orig@corp.com")
            .unwrap_or_else(|e| panic!("send failed: {e:?} dialog={:?}", fake.captured().dialog));
        assert_eq!(id, "smtp-accepted");
        let seen = fake.captured();
        assert!(
            seen.dialog
                .iter()
                .any(|line| line.starts_with("C: AUTH LOGIN")),
            "the LOGIN challenge must have been negotiated: {:?}",
            seen.dialog
        );
        assert!(seen.data.contains("Your process was unfair."), "body lost");
    }

    /// Why: an unrecognized query is a fail-closed "match nothing", never a
    /// mailbox-wide fetch — the empty page must be produced without a single
    /// connection to the mailbox.
    #[test]
    fn imap_list_matches_nothing_on_unrecognized_queries() {
        use crate::sync::Provider;
        let (fake, _messages) = two_message_mailbox();
        let mut client = fake.client();
        let page = Provider::list(&mut client, "from:foo@bar.com", None)
            .expect("unrecognized queries match nothing");
        assert!(page.messages.is_empty());
        assert!(page.next_page_token.is_none());
        assert_eq!(
            fake.hits(),
            0,
            "an unrecognized query must never touch the mailbox"
        );
    }

    /// Why: unsafe search tokens (quote/backslash/CR/LF) must be refused
    /// before any IMAP command is issued, or a crafted Message-ID could inject
    /// SEARCH syntax; both entry points return "nothing" and stay offline.
    #[test]
    fn imap_thread_and_find_sent_fail_closed_on_unsafe_tokens() {
        let (fake, _messages) = two_message_mailbox();
        let mut client = fake.client();
        let thread = MailTransport::thread(&mut client, "a\"b").expect("unsafe id matches nothing");
        assert!(thread.messages.is_empty());
        assert_eq!(
            MailTransport::find_sent(&mut client, "a\r\nb").expect("unsafe id matches nothing"),
            None
        );
        assert_eq!(
            fake.hits(),
            0,
            "unsafe tokens must be refused before any IMAP command"
        );
    }

    /// Why: an app-password session holds its credentials by construction, so
    /// the engine's send gate must read `true` — a regression here silently
    /// disables the whole send pipeline for the app-password backend.
    #[test]
    fn imap_transport_is_always_authorized_to_send() {
        let imap = ImapSmtp::new(
            AppPasswordCredentials::new("user@example.com", "abcdefghijklmnop"),
            ImapSmtpConfig::default(),
        );
        assert!(
            MailTransport::can_send(&imap),
            "the app-password session holds credentials"
        );
    }

    /// Why: a search value carrying non-ASCII cannot ride an IMAP quoted
    /// string, so the codec emits a (synchronizing) literal; the value must
    /// round-trip byte-exact through the wire or `find_sent` would silently
    /// miss its own sent message on such Message-IDs.
    #[test]
    fn imap_search_literals_round_trip_message_ids_byte_exact() {
        let messages = vec![(
            12001u32,
            "From: a@x.com\r\nMessage-ID: <odd-é@x.com>\r\n\r\nbody".to_owned(),
        )];
        let fake = FakeImap::start(messages);
        let mut client = fake.client();
        assert_eq!(
            MailTransport::find_sent(&mut client, "<odd-é@x.com>")
                .expect("find_sent")
                .as_deref(),
            Some("12001")
        );
        assert_eq!(
            MailTransport::find_sent(&mut client, "<other-é@x.com>")
                .expect("find_sent")
                .as_deref(),
            None
        );
    }

    /// Why: a message with no threading header cannot be threaded. Surfacing
    /// it with an empty thread key made `gmail::stub` fail provider-id
    /// validation and abort the entire sync ("Invalid provider ID"); it must
    /// be skipped on both the list and history paths instead, so one odd
    /// message can never stall mailbox ingestion.
    #[test]
    fn imap_refs_skip_messages_without_threading_headers() {
        use crate::sync::Provider;
        let messages = vec![
            (
                12001u32,
                "From: a@x.com\r\nMessage-ID: <m1@x.com>\r\n\r\nhello".to_owned(),
            ),
            (12002, "From: b@x.com\r\n\r\nno id here".to_owned()),
        ];
        let fake = FakeImap::start(messages);
        let mut client = fake.client();
        let page = Provider::list(&mut client, "", None).expect("list");
        let ids: Vec<_> = page.messages.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, vec!["12001"], "the threadable message survives");
        for m in &page.messages {
            crate::gmail::stub("user@example.com", m.clone())
                .expect("every surfaced ref must pass provider-id validation");
        }
        // The history path applies the same skip.
        let HistoryResult::Page(hp) = Provider::history(&mut client, "0", None).expect("history")
        else {
            panic!("expected a history page");
        };
        let added: Vec<_> = hp
            .history
            .iter()
            .flat_map(|r| &r.messages_added)
            .map(|a| a.message.id.as_str())
            .collect();
        assert_eq!(added, vec!["12001"]);
    }

    /// Why: a malformed endpoint host must fail with the endpoint context
    /// before any connection attempt, so a config typo reads as a config typo
    /// and not as a network failure.
    #[test]
    fn imap_rejects_unparseable_endpoints_with_the_endpoint_context() {
        use crate::sync::Provider;
        let mut bad = ImapSmtp::new(
            AppPasswordCredentials::new("user@example.com", "abcdefghijklmnop"),
            ImapSmtpConfig {
                imap_host: "not a valid host".to_owned(),
                ..ImapSmtpConfig::default()
            },
        );
        let error = match Provider::list(&mut bad, "1:*", None) {
            Err(error) => error,
            Ok(_) => panic!("an unparseable endpoint must surface an error"),
        };
        assert!(
            error.to_string().starts_with("invalid IMAP endpoint URL"),
            "unexpected error: {error:#}"
        );
    }

    /// Why: a reply whose MIME the parser cannot survive, or whose body
    /// transfer encoding is corrupt, must be `NotAccepted` with the exact
    /// reason before anything reaches the wire — sending it would produce a
    /// wrong-but-plausible delivery record.
    #[test]
    fn smtp_send_fails_closed_on_unparseable_mime_and_bodies() {
        let fake = FakeSmtp::start(false);
        let mut client = fake.client();
        for (raw, expected) in [
            (
                b64(&deeply_nested_mime(120)),
                "reply MIME could not be parsed",
            ),
            (
                b64(concat!(
                    "From: a@x.com\r\nTo: b@y.com\r\n",
                    "Content-Transfer-Encoding: base64\r\n\r\n!!!not base64!!!"
                )),
                "reply body could not be decoded",
            ),
        ] {
            let error = MailTransport::send(&mut client, &raw, "t").unwrap_err();
            assert_eq!(error.kind, SendFailureKind::NotAccepted, "{expected}");
            assert!(
                error.message.starts_with(expected),
                "expected {expected:?}, got {}",
                error.message
            );
        }
        assert!(
            fake.captured().dialog.is_empty(),
            "unparseable replies must never reach the wire"
        );
    }

    /// Why: Subject is optional in a reply; a subject-less reply must still
    /// deliver instead of failing the message build.
    #[test]
    fn smtp_send_accepts_replies_without_a_subject() {
        let fake = FakeSmtp::start(false);
        let mut client = fake.client();
        let raw = b64("From: user@example.com\r\nTo: recruiter@corp.com\r\n\r\nbody only");
        let id = MailTransport::send(&mut client, &raw, "orig@corp.com")
            .unwrap_or_else(|e| panic!("send failed: {e:?}"));
        assert_eq!(id, "smtp-accepted");
        assert!(fake.captured().data.contains("body only"), "body lost");
    }

    /// Why: unparseable MIME has no thread key and must be skipped by the ref
    /// builder rather than grouped under an empty key.
    #[test]
    fn thread_key_is_none_for_unparseable_mime() {
        assert_eq!(thread_key(&deeply_nested_mime(120)), None);
    }

    // why (security review finding 5): an oversized tracked safety header is
    // recorded as dropped without its attacker-sized value and marks the
    // message's safety-header capture incomplete, so presence-based checks
    // can never read the drop as genuine absence and proceed automatically.
    #[test]
    fn oversized_tracked_headers_mark_the_message_incomplete() {
        let stub = stub_with("9", "t");
        let mime = format!(
            "From: r@co.com\r\nList-Id: {}\r\nSubject: S\r\n\r\nbody",
            "x".repeat(9000)
        );
        let email = email_from_rfc822(mime.as_bytes(), &stub).expect("parse");
        assert!(
            !email.headers.contains_key("list-id"),
            "the attacker-sized value is never retained"
        );
        assert!(
            !email.security_headers_complete,
            "the drop must mark safety-header capture incomplete"
        );
        assert!(
            email.headers.contains_key("from"),
            "bounded headers must still land"
        );
        // The deterministic gate fails closed for the message.
        assert!(!crate::mail::hard_blocks(&email, "me@example.com").is_empty());
    }

    // why (security review finding 5): oversized duplicates cannot launder
    // the signal to absence — one oversized occurrence marks the message
    // even when a bounded duplicate of the same header is retained.
    #[test]
    fn oversized_duplicate_headers_cannot_launder_absence() {
        let stub = stub_with("9", "t");
        let mime = format!(
            "From: r@co.com\r\nList-Id: {}\r\nList-Id: small-id\r\nSubject: S\r\n\r\nbody",
            "x".repeat(9000)
        );
        let email = email_from_rfc822(mime.as_bytes(), &stub).expect("parse");
        assert!(
            email.headers.contains_key("list-id"),
            "the bounded duplicate is retained"
        );
        assert!(!email.security_headers_complete);
    }

    // why (security review finding 3): a text attachment must never supply
    // deterministic rejection evidence or model input — the shared extractor
    // excludes attachments and named parts entirely.
    #[test]
    fn multipart_text_attachments_cannot_supply_rejection_evidence() {
        let stub = stub_with("9", "t");
        let mime = "From: r@co.com\r\nSubject: S\r\nMIME-Version: 1.0\r\n\
            Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n\
            --b\r\nContent-Type: text/plain\r\n\r\nThanks for applying.\r\n\
            --b\r\nContent-Type: text/plain; name=\"notes.txt\"\r\n\
            Content-Disposition: attachment; filename=\"notes.txt\"\r\n\r\n\
            We regret to inform you we are not moving forward.\r\n\
            --b--\r\n";
        let email = email_from_rfc822(mime.as_bytes(), &stub).expect("parse");
        assert!(
            !crate::mail::clear_rejection_language(&email.subject, &email.text),
            "attachment text must not mint rejection evidence: {:?}",
            email.text
        );
    }

    // why (security review finding 3): an embedded message/rfc822 is inert
    // and marks the capture incomplete — forwarded rejection text can never
    // authorize an automatic reply.
    #[test]
    fn embedded_messages_are_inert_and_incomplete() {
        let stub = stub_with("9", "t");
        let mime = "From: r@co.com\r\nSubject: S\r\nMIME-Version: 1.0\r\n\
            Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n\
            --b\r\nContent-Type: text/plain\r\n\r\nPlease see below.\r\n\
            --b\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment\r\n\r\n\
            From: old@co.com\r\nSubject: old\r\n\r\nNot moving forward.\r\n\
            --b--\r\n";
        let email = email_from_rfc822(mime.as_bytes(), &stub).expect("parse");
        assert!(
            !email.body_complete,
            "embedded messages mark capture incomplete"
        );
        assert!(
            !crate::mail::clear_rejection_language(&email.subject, &email.text),
            "forwarded rejection text must not mint evidence"
        );
    }
}
