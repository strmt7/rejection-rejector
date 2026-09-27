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

pub trait Provider {
    fn profile(&mut self) -> Result<Profile>;
    fn list(&mut self, query: &str, page: Option<&str>) -> Result<MessagePage>;
    fn history(&mut self, start: &str, page: Option<&str>) -> Result<HistoryResult>;
}
impl Provider for Gmail {
    fn profile(&mut self) -> Result<Profile> {
        Gmail::profile(self)
    }
    fn list(&mut self, q: &str, p: Option<&str>) -> Result<MessagePage> {
        Gmail::list(self, q, p)
    }
    fn history(&mut self, s: &str, p: Option<&str>) -> Result<HistoryResult> {
        Gmail::history(self, s, p)
    }
}

/// A cursor is saved only after EVERY page has been inserted durably. Replays are harmless.
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
        inserted += db.insert_stubs(stubs, now)?;
        if let Some(next) = p.next_page_token {
            ensure!(
                tokens.insert(next.clone()) && tokens.len() <= 10000,
                "Invalid or excessive Gmail pagination; cursor retained"
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
        n += db.insert_stubs(stubs, now)?;
        if let Some(next) = p.next_page_token {
            ensure!(
                tokens.insert(next.clone()) && tokens.len() <= 10000,
                "Invalid or excessive Gmail pagination; cursor retained"
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
