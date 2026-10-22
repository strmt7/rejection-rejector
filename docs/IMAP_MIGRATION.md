# IMAP transport: supply-chain migration + a sync bug found

Two findings from the 2026-10-22 root-cause pass on the app-password / IMAP path.

## 1. Unsound dependency (`lexical-core`) — fix verified

`imap` 2 pulls `nom` 5 which pulls `lexical-core` 0.7.6 (RUSTSEC-2023-0086,
*Unsound*: `assume_init` on uninitialized data, out-of-bounds `BytesIter`). It is
reachable through number parsing of a **crafted IMAP response**. Practical
exposure is low (the app talks only to Gmail or the operator's own host) but the
crate is unsound.

**Verified fix:** `io-imap` 0.7.1 (Pimalaya) parses via `nom` 7 +
`minimal-lexical` and carries **no `lexical-core`**. It resolves cleanly in this
repo's tree (confirmed: `cargo tree -i lexical-core` → *did not match any
packages*; `nom` 5 → 7, `minimal-lexical` 0.2 added). The only extra is a
feature unification: add `nom = { version = "7", features = ["alloc", "std"] }`
so `imap-codec`'s missing `alloc` is satisfied.

The API mapping is validated by a compiling prototype (connect → login →
select(`Mailbox::try_from("INBOX")`) → search(`Vec1::from(SearchKey::…)`) →
`fetch_bodies_stream(seq, uid, open, done)` → logout). Types live in
`io_imap::types::{mailbox::Mailbox, search::SearchKey, sequence::SequenceSet,
core::Vec1}`; `Vec1` is `VecN<T,1>` (`From<T>`), not `Vec1::new`.

## 2. BUG: the app-password sync query is Gmail syntax sent to IMAP search

`engine::Engine::synchronize` syncs through the generic `sync::synchronize<P:
Provider>`. `full_sync` builds a **Gmail-style** query:

```text
after:<cutoff_unix> before:<now_unix> -in:spam -in:trash -in:sent -in:drafts
```

For the Gmail provider that is correct. But when the transport is `ImapSmtp`
(the app-password path), `ImapSmtp::list` passes that string verbatim to
`uid_search` — and `after:`/`before:`/`-in:` are **not valid IMAP search keys**
(IMAP uses `SINCE`/`BEFORE`/`NOT`). The IMAP server returns `BAD`, so the
**app-password incremental sync fails or returns nothing**. This is a latent
functional bug in a shipping path, independent of the dependency migration.

### Fix direction (design, not a one-liner)

The `Provider::list(query: &str, …)` contract is Gmail-centric. Make it
provider-agnostic in one of two clean ways:

- **Preferred:** change `Provider::list` to take structured bounds (a
  `DateTime<Utc>` cutoff + exclusion flags) and let each provider build its own
  search — Gmail emits the Gmail query, `ImapSmtp` emits `SINCE`/`BEFORE` +
  `NOT`/`UNSEEN` etc. Deterministic and testable per provider.
- Or have `ImapSmtp::list` translate the known Gmail query shape (parse
  `after:`/`before:` timestamps) into an IMAP search, failing closed on any
  unrecognized shape.

Until then, do not describe the app-password path as having working incremental
sync. The parse/send/email()/thread()/find_sent() paths are unaffected (they use
UID sets and `HEADER Message-ID`, which map cleanly to `SearchKey::Uid` /
`SearchKey::Header`).

## Mapping for the io-imap rewrite (when executed)

| current (imap 2) | io-imap |
|---|---|
| `imap::connect((host, port), host, &tls)` | `ImapClientStd::connect(&Url::parse("imaps://host:993"), ImapClientStdConnectOptions::default())` |
| `client.login(user, pass)` | `client.login(user, pass, Default::default())` |
| `session.select("INBOX")` | `client.select(Mailbox::try_from("INBOX").unwrap(), Default::default())` |
| `session.uid_search("124:*")` | `client.search(Vec1::from(SearchKey::Uid(seq)), ImapMessageSearchOptions::default())` |
| `session.uid_fetch(set, "BODY.PEEK[]")` | `client.fetch_bodies_stream(seq, true, open, done)` (callback; `uid=true`) |
| `session.logout()` | `client.logout()` |
