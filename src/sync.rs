use crate::{
    config::Settings,
    gmail::{self, Gmail, HistoryResult, MessagePage, Profile},
    store::Store,
    types::SyncState,
};
use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use std::{
    collections::HashSet,
    sync::atomic::{AtomicBool, Ordering},
};

const MAX_SYNC_PAGES: usize = 512;
const MAX_SYNC_IDENTITIES: usize = 250_000;

/// Charge one sync page against the traversal budget.
///
/// Inputs: `pages_seen` — page counter, incremented with an overflow check;
/// `identities_seen` — identity counter, accumulated; `page_identities` —
/// identities seen on this page. Output: `Result<()>` — `Ok` while the counters
/// advance; error on overflow (the cursor is retained).
fn charge_sync_budget(
    pages_seen: &mut usize,
    identities_seen: &mut usize,
    page_identities: usize,
) -> Result<()> {
    *pages_seen = pages_seen
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("Gmail pagination counter overflow; cursor retained"))?;
    ensure!(
        *pages_seen <= MAX_SYNC_PAGES,
        "Gmail synchronization exceeded the {MAX_SYNC_PAGES}-page safety budget; cursor retained"
    );
    *identities_seen = identities_seen
        .checked_add(page_identities)
        .ok_or_else(|| anyhow::anyhow!("Gmail identity counter overflow; cursor retained"))?;
    ensure!(
        *identities_seen <= MAX_SYNC_IDENTITIES,
        "Gmail synchronization exceeded the {MAX_SYNC_IDENTITIES}-identity safety budget; cursor retained"
    );
    Ok(())
}

/// Mailbox provider surface consumed by synchronization.
///
/// Inputs: none (trait). Output: profile, message listing and history
/// fetching implemented by each transport backend.
pub trait Provider {
    /// Fetch the provider account profile.
    ///
    /// Inputs: none (`&mut self`). Output: `Result<Profile>` — the account profile.
    fn profile(&mut self) -> Result<Profile>;
    /// List one page of provider messages.
    ///
    /// Inputs: `query` — provider search query; `page` — continuation token, if
    /// any. Output: `Result<MessagePage>` — the page of message identities.
    fn list(&mut self, query: &str, page: Option<&str>) -> Result<MessagePage>;
    /// List one page of provider history since a start point.
    ///
    /// Inputs: `start` — history start token; `page` — continuation token, if any.
    /// Output: `Result<HistoryResult>` — the history page and its new start token.
    fn history(&mut self, start: &str, page: Option<&str>) -> Result<HistoryResult>;
}
impl Provider for Gmail {
    /// Fetch the Gmail account profile.
    ///
    /// Inputs: none (`&mut self`). Output: `Result<Profile>` — the account profile,
    /// as the inherent `Gmail::profile` method returns.
    fn profile(&mut self) -> Result<Profile> {
        Gmail::profile(self)
    }
    /// List one page of Gmail messages.
    ///
    /// Inputs: `q` — Gmail search query; `p` — continuation token, if any. Output:
    /// `Result<MessagePage>` — the page of message identities.
    fn list(&mut self, q: &str, p: Option<&str>) -> Result<MessagePage> {
        Gmail::list(self, q, p)
    }
    /// List one page of Gmail history since a start point.
    ///
    /// Inputs: `s` — history start token; `p` — continuation token, if any. Output:
    /// `Result<HistoryResult>` — the history page and its new start token.
    fn history(&mut self, s: &str, p: Option<&str>) -> Result<HistoryResult> {
        Gmail::history(self, s, p)
    }
}

/// A cursor is saved only after EVERY page has been inserted durably. Replays are harmless.
///
/// Inputs: `provider` — mail provider to page through; `db` — store receiving
/// the messages; `settings` — sync settings; `account` — mailbox account key; `now`
/// — sync timestamp; `cancelled` — cancellation flag checked per page. Output: `Result<usize>`
/// — the number of newly inserted messages.
pub fn synchronize<P: Provider>(
    provider: &mut P,
    db: &mut Store,
    settings: &Settings,
    account: &str,
    now: DateTime<Utc>,
    cancelled: &AtomicBool,
) -> Result<usize> {
    let key = format!("sync/{account}");
    let mut state: SyncState = db.meta(&key)?.unwrap_or_default();
    let profile = provider.profile()?;
    ensure!(
        crate::mail::mailbox(&profile.email_address)? == account,
        "Gmail account changed; reconnect explicitly"
    );
    let full = state.history_id.is_none()
        || state.account != account
        || state.lookback_days != settings.lookback_days;
    if full {
        return full_sync(
            provider,
            db,
            settings,
            account,
            now,
            cancelled,
            &profile.history_id,
        );
    }
    let start = state.history_id.as_deref().unwrap_or_default().to_owned();
    let mut page = None;
    let mut tokens = HashSet::new();
    let mut inserted = 0;
    let mut pages_seen = 0usize;
    let mut identities_seen = 0usize;
    let latest = loop {
        ensure!(
            !cancelled.load(Ordering::SeqCst),
            "Synchronization cancelled; previous cursor retained"
        );
        let result = provider.history(&start, page.as_deref())?;
        let p = match result {
            HistoryResult::Expired => {
                return full_sync(
                    provider,
                    db,
                    settings,
                    account,
                    now,
                    cancelled,
                    &profile.history_id,
                );
            }
            HistoryResult::Page(p) => p,
        };
        let mut stubs = Vec::new();
        for record in p.history {
            for added in record.messages_added {
                stubs.push(gmail::stub(account, added.message)?);
            }
        }
        charge_sync_budget(&mut pages_seen, &mut identities_seen, stubs.len())?;
        inserted += db.insert_stubs(stubs, now)?;
        if let Some(next) = p.next_page_token {
            ensure!(
                tokens.insert(next.clone()),
                "Repeated Gmail pagination token; cursor retained"
            );
            page = Some(next);
        } else {
            break p.history_id;
        }
    };
    ensure!(!latest.is_empty(), "Gmail did not return a history cursor");
    state.history_id = Some(latest);
    state.last_poll = Some(now);
    db.change_meta(
        &[(&key, serde_json::to_value(&state)?)],
        &[],
        "sync.incremental",
        &format!("Stored {inserted} new identities"),
    )?;
    Ok(inserted)
}
/// Run one full mailbox sync pass.
///
/// Inputs: `provider` — message provider; `db` — store receiving the
/// identities; `settings` — sync settings; `account` — account key; `now` —
/// sync start time; `cancelled` — cancellation flag; `baseline` — history start
/// token to advance. Output: `Result<usize>` — the number of new identities
/// inserted.
fn full_sync<P: Provider>(
    provider: &mut P,
    db: &mut Store,
    settings: &Settings,
    account: &str,
    now: DateTime<Utc>,
    cancelled: &AtomicBool,
    baseline: &str,
) -> Result<usize> {
    ensure!(!baseline.is_empty(), "Missing Gmail baseline");
    let query = format!(
        "after:{} before:{} -in:spam -in:trash -in:sent -in:drafts",
        settings.cutoff(now).timestamp() - 1,
        now.timestamp() + 1
    );
    let mut page = None;
    let mut tokens = HashSet::new();
    let mut n = 0;
    let mut pages_seen = 0usize;
    let mut identities_seen = 0usize;
    loop {
        ensure!(
            !cancelled.load(Ordering::SeqCst),
            "Synchronization cancelled; previous cursor retained"
        );
        let p = provider.list(&query, page.as_deref())?;
        let mut stubs = Vec::with_capacity(p.messages.len());
        for message in p.messages {
            stubs.push(gmail::stub(account, message)?);
        }
        charge_sync_budget(&mut pages_seen, &mut identities_seen, stubs.len())?;
        n += db.insert_stubs(stubs, now)?;
        if let Some(next) = p.next_page_token {
            ensure!(
                tokens.insert(next.clone()),
                "Repeated Gmail pagination token; cursor retained"
            );
            page = Some(next);
        } else {
            break;
        }
    }
    let key = format!("sync/{account}");
    let old: SyncState = db.meta(&key)?.unwrap_or_default();
    if settings.lookback_days > old.lookback_days {
        db.wake_deferred(account)?;
    }
    // Baseline was taken BEFORE listing; arrivals during listing are caught next poll.
    let state = SyncState {
        account: account.into(),
        history_id: Some(baseline.into()),
        last_poll: Some(now),
        last_full: Some(now),
        lookback_days: settings.lookback_days,
    };
    db.change_meta(
        &[(&key, serde_json::to_value(&state)?)],
        &[],
        "sync.reconciled",
        &format!("Stored {n} new identities; existing content unchanged"),
    )?;
    Ok(n)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        gmail::{HistoryPage, MessageRef},
        vault::Vault,
    };
    struct Fake {
        fail: bool,
        calls: usize,
    }
    impl Provider for Fake {
        fn profile(&mut self) -> Result<Profile> {
            Ok(Profile {
                email_address: "me@example.com".into(),
                history_id: "20".into(),
            })
        }
        fn list(&mut self, _: &str, page: Option<&str>) -> Result<MessagePage> {
            self.calls += 1;
            if page.is_some() {
                ensure!(!self.fail, "simulated second-page failure");
                return Ok(MessagePage::default());
            }
            Ok(MessagePage {
                messages: vec![MessageRef {
                    id: "a".into(),
                    thread_id: "t".into(),
                }],
                next_page_token: Some("next".into()),
            })
        }
        fn history(&mut self, _: &str, _: Option<&str>) -> Result<HistoryResult> {
            Ok(HistoryResult::Page(HistoryPage {
                history_id: "21".into(),
                ..Default::default()
            }))
        }
    }
    #[test]
    fn synchronization_resource_budgets_are_bounded_and_fail_closed() {
        let mut pages = 0usize;
        let mut identities = 0usize;
        charge_sync_budget(&mut pages, &mut identities, MAX_SYNC_IDENTITIES).unwrap();
        assert_eq!(pages, 1);
        assert_eq!(identities, MAX_SYNC_IDENTITIES);
        assert!(charge_sync_budget(&mut pages, &mut identities, 1).is_err());

        let mut pages = MAX_SYNC_PAGES;
        let mut identities = 0usize;
        assert!(charge_sync_budget(&mut pages, &mut identities, 0).is_err());
    }

    /// Provider whose history is always expired, forcing the full-sync fallback.
    struct ExpiredHistory {
        list_calls: usize,
    }
    impl Provider for ExpiredHistory {
        fn profile(&mut self) -> Result<Profile> {
            Ok(Profile {
                email_address: "me@example.com".into(),
                history_id: "20".into(),
            })
        }
        fn list(&mut self, _: &str, _: Option<&str>) -> Result<MessagePage> {
            self.list_calls += 1;
            Ok(MessagePage {
                messages: vec![MessageRef {
                    id: "a".into(),
                    thread_id: "t".into(),
                }],
                next_page_token: None,
            })
        }
        fn history(&mut self, _: &str, _: Option<&str>) -> Result<HistoryResult> {
            Ok(HistoryResult::Expired)
        }
    }

    #[test]
    fn expired_history_falls_back_to_full_sync() {
        // Covers the HistoryResult::Expired arm: the incremental sync must fall
        // back to full_sync and still insert the recovered identities.
        let d = tempfile::tempdir().unwrap();
        let mut db = Store::open(&d.path().join("db"), Vault::random()).unwrap();
        let mut f = ExpiredHistory { list_calls: 0 };
        let stop = AtomicBool::new(false);
        let s = Settings::default();
        let n = synchronize(&mut f, &mut db, &s, "me@example.com", Utc::now(), &stop).unwrap();
        assert_eq!(
            n, 1,
            "the full-sync fallback must insert the recovered identity"
        );
        assert!(f.list_calls >= 1, "full_sync must have listed messages");
        assert_eq!(db.counts("me@example.com").unwrap().stored, 1);
    }

    #[test]
    fn failed_pagination_never_advances_cursor_and_replay_deduplicates() {
        let d = tempfile::tempdir().unwrap();
        let mut db = Store::open(&d.path().join("db"), Vault::random()).unwrap();
        let mut f = Fake {
            fail: true,
            calls: 0,
        };
        let stop = AtomicBool::new(false);
        let s = Settings::default();
        assert!(synchronize(&mut f, &mut db, &s, "me@example.com", Utc::now(), &stop).is_err());
        assert!(
            db.meta::<SyncState>("sync/me@example.com")
                .unwrap()
                .is_none()
        );
        f.fail = false;
        assert_eq!(
            synchronize(&mut f, &mut db, &s, "me@example.com", Utc::now(), &stop).unwrap(),
            0
        );
        assert_eq!(db.counts("me@example.com").unwrap().stored, 1);
        let calls = f.calls;
        synchronize(&mut f, &mut db, &s, "me@example.com", Utc::now(), &stop).unwrap();
        assert_eq!(calls, f.calls);
        assert!(
            db.events(0, 100)
                .unwrap()
                .iter()
                .any(|event| matches!(event.kind.as_str(), "sync.reconciled" | "sync.incremental"))
        );
    }
}

#[cfg(test)]
mod gmail_provider_and_checkpoint_tests {
    use super::*;
    use crate::gmail::{Gmail, HistoryPage, MessageRef};
    use crate::oauth::Credentials;
    use crate::vault::Vault;
    use serde_json::json;
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};
    use std::time::Duration;
    use tiny_http::{Header, Response, Server};

    /// Minimal Gmail API double: token refresh plus profile/list/history
    /// routes, so the `Provider` glue for the real client can be exercised
    /// without touching the network.
    struct Api {
        stop: Arc<AtomicBool>,
        handle: Option<JoinHandle<()>>,
        token_handle: Option<JoinHandle<()>>,
        root: String,
        token: String,
    }
    impl Api {
        fn new() -> Self {
            let server = Server::http("127.0.0.1:0").unwrap();
            let root = format!("http://{}", server.server_addr().to_ip().unwrap());
            let token_server = Server::http("127.0.0.1:0").unwrap();
            let token = format!("http://{}", token_server.server_addr().to_ip().unwrap());
            let stop = Arc::new(AtomicBool::new(false));
            let flag = stop.clone();
            let token_stop = stop.clone();
            let api = thread::spawn(move || {
                while !flag.load(Ordering::SeqCst) {
                    let Some(request) = server.recv_timeout(Duration::from_millis(50)).unwrap()
                    else {
                        continue;
                    };
                    let route = request
                        .url()
                        .split('?')
                        .next()
                        .unwrap_or_default()
                        .to_owned();
                    let answer = match route.as_str() {
                        "/profile" => {
                            json!({"emailAddress": "me@example.com", "historyId": "20"})
                        }
                        "/messages" => {
                            json!({"messages": [{"id": "a", "threadId": "t"}], "nextPageToken": "p2"})
                        }
                        "/history" => {
                            json!({"history": [], "historyId": "21", "nextPageToken": null})
                        }
                        path => panic!("unexpected Gmail route {path}"),
                    };
                    let response = Response::from_string(answer.to_string()).with_header(
                        Header::from_bytes("Content-Type", "application/json").unwrap(),
                    );
                    let _ = request.respond(response);
                }
            });
            let token_handle = thread::spawn(move || {
                while !token_stop.load(Ordering::SeqCst) {
                    let Some(request) = token_server
                        .recv_timeout(Duration::from_millis(50))
                        .unwrap()
                    else {
                        continue;
                    };
                    let response = Response::from_string(
                        r#"{"access_token":"t","expires_in":3600}"#.to_string(),
                    )
                    .with_header(Header::from_bytes("Content-Type", "application/json").unwrap());
                    let _ = request.respond(response);
                }
            });
            Self {
                stop,
                handle: Some(api),
                token_handle: Some(token_handle),
                root,
                token,
            }
        }
    }
    impl Drop for Api {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            let _ = self.handle.take().unwrap().join();
            let _ = self.token_handle.take().unwrap().join();
        }
    }

    fn credentials() -> Credentials {
        Credentials {
            client_id: "id".into(),
            client_secret: "secret".into(),
            refresh_token: "refresh".into(),
            can_send: true,
        }
    }

    struct Fake {
        fail_second_page: bool,
    }
    impl Provider for Fake {
        fn profile(&mut self) -> Result<Profile> {
            Ok(Profile {
                email_address: "me@example.com".into(),
                history_id: "20".into(),
            })
        }
        fn list(&mut self, _: &str, page: Option<&str>) -> Result<MessagePage> {
            if page.is_some() {
                ensure!(!self.fail_second_page, "simulated second-page failure");
                return Ok(MessagePage::default());
            }
            Ok(MessagePage {
                messages: vec![MessageRef {
                    id: "a".into(),
                    thread_id: "t".into(),
                }],
                next_page_token: Some("next".into()),
            })
        }
        fn history(&mut self, _: &str, _: Option<&str>) -> Result<HistoryResult> {
            Ok(HistoryResult::Page(HistoryPage {
                history_id: "21".into(),
                ..Default::default()
            }))
        }
    }

    /// Why: `Provider for Gmail` must faithfully delegate to the Gmail client
    /// (parse and return its results), because `synchronize` is generic over
    /// the trait and a broken shim would silently stop mailbox ingestion.
    #[test]
    fn gmail_provider_impl_delegates_to_the_gmail_client() {
        let api = Api::new();
        let mut gmail = Gmail::with_endpoints(credentials(), &api.root, &api.token);

        let profile = Provider::profile(&mut gmail).unwrap();
        assert_eq!(profile.email_address, "me@example.com");
        assert_eq!(profile.history_id, "20");

        let page = Provider::list(&mut gmail, "query", None).unwrap();
        assert_eq!(page.messages.len(), 1);
        assert_eq!(page.messages[0].id, "a");
        assert_eq!(page.messages[0].thread_id, "t");
        assert_eq!(page.next_page_token.as_deref(), Some("p2"));

        let history = Provider::history(&mut gmail, "20", None).unwrap();
        match history {
            HistoryResult::Page(page) => {
                assert!(page.history.is_empty());
                assert_eq!(page.history_id, "21");
            }
            HistoryResult::Expired => panic!("history must parse as a page"),
        }
    }

    fn install_checkpoint_failure(path: &std::path::Path) {
        let raw = rusqlite::Connection::open(path).unwrap();
        raw.execute_batch(
            "CREATE TRIGGER block_sync_insert BEFORE INSERT ON meta \
             WHEN NEW.name LIKE 'sync/%' BEGIN SELECT RAISE(ABORT, 'checkpoint blocked'); END;
             CREATE TRIGGER block_sync_update BEFORE UPDATE ON meta \
             WHEN NEW.name LIKE 'sync/%' BEGIN SELECT RAISE(ABORT, 'checkpoint blocked'); END;",
        )
        .unwrap();
    }

    /// Why: the sync cursor may advance only when its checkpoint commits. If
    /// the checkpoint write fails, synchronization must error out and leave the
    /// previous cursor in place so the next run replays instead of skipping
    /// messages.
    #[test]
    fn cursor_never_advances_when_the_sync_checkpoint_cannot_commit() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("db");
        let mut db = Store::open(&path, Vault::random()).unwrap();
        let mut fake = Fake {
            fail_second_page: false,
        };
        let stop = AtomicBool::new(false);
        let settings = Settings::default();
        synchronize(
            &mut fake,
            &mut db,
            &settings,
            "me@example.com",
            Utc::now(),
            &stop,
        )
        .unwrap();
        let before: SyncState = db
            .meta("sync/me@example.com")
            .unwrap()
            .expect("full sync stores a cursor");
        assert_eq!(before.history_id.as_deref(), Some("20"));

        install_checkpoint_failure(&path);
        let error = synchronize(
            &mut fake,
            &mut db,
            &settings,
            "me@example.com",
            Utc::now(),
            &stop,
        )
        .expect_err("blocked checkpoint must fail the sync");
        assert!(
            format!("{error:#}").contains("checkpoint blocked"),
            "unexpected error: {error:#}"
        );
        let after: SyncState = db.meta("sync/me@example.com").unwrap().unwrap();
        assert_eq!(after.history_id.as_deref(), Some("20"), "cursor retained");
        assert_eq!(after.last_poll, before.last_poll);
    }

    /// Why: the same atomicity applies to the full reconciliation path — a
    /// failed checkpoint must abort before claiming a stored baseline.
    #[test]
    fn full_sync_checkpoint_failure_leaves_no_baseline_behind() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("db");
        let mut db = Store::open(&path, Vault::random()).unwrap();
        let mut fake = Fake {
            fail_second_page: false,
        };
        let stop = AtomicBool::new(false);
        let settings = Settings::default();
        install_checkpoint_failure(&path);
        let error = synchronize(
            &mut fake,
            &mut db,
            &settings,
            "me@example.com",
            Utc::now(),
            &stop,
        )
        .expect_err("blocked checkpoint must fail the full sync");
        assert!(
            format!("{error:#}").contains("checkpoint blocked"),
            "unexpected error: {error:#}"
        );
        assert!(
            db.meta::<SyncState>("sync/me@example.com")
                .unwrap()
                .is_none()
        );
    }
}
