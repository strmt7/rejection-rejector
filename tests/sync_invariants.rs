//! Sync ingestion invariants: the cursor is the at-least-once contract.
//!
//! A cursor may advance only after every page is durably inserted, replays
//! must never duplicate identities, provider pathologies (token loops,
//! account swaps) must be rejected with the cursor retained.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::Utc;
use rejection_rejector::config::Settings;
use rejection_rejector::gmail::{
    Added, HistoryPage, HistoryRecord, HistoryResult, MessagePage, MessageRef, Profile,
};
use rejection_rejector::store::Store;
use rejection_rejector::sync::{Provider, synchronize};
use rejection_rejector::types::SyncState;
use rejection_rejector::vault::Vault;

/// Scripted provider: pops canned history pages and can trip the
/// cancellation flag mid-run to simulate a stopped worker.
struct FakeProvider {
    email: String,
    pages: VecDeque<HistoryResult>,
    cancel: Option<Arc<AtomicBool>>,
    cancel_after: usize,
    calls: usize,
}

impl Provider for FakeProvider {
    fn profile(&mut self) -> anyhow::Result<Profile> {
        Ok(Profile {
            email_address: self.email.clone(),
            history_id: "900".to_string(),
        })
    }
    fn list(&mut self, _query: &str, _page: Option<&str>) -> anyhow::Result<MessagePage> {
        unimplemented!("incremental synchronization never lists")
    }
    fn history(&mut self, _start: &str, _page: Option<&str>) -> anyhow::Result<HistoryResult> {
        self.calls += 1;
        if let Some(flag) = &self.cancel
            && self.calls >= self.cancel_after
        {
            flag.store(true, Ordering::SeqCst);
        }
        Ok(self.pages.pop_front().expect("scripted history exhausted"))
    }
}

fn harness() -> (tempfile::TempDir, Store, Settings) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = Store::open(&dir.path().join("state.sqlite3"), Vault::random()).expect("store");
    (dir, db, Settings::default())
}

fn page(ids: &[&str], next: Option<&str>, history_id: &str) -> HistoryResult {
    HistoryResult::Page(HistoryPage {
        history: vec![HistoryRecord {
            messages_added: ids
                .iter()
                .map(|id| Added {
                    message: MessageRef {
                        id: id.to_string(),
                        thread_id: format!("t-{id}"),
                    },
                })
                .collect(),
        }],
        next_page_token: next.map(str::to_string),
        history_id: history_id.to_string(),
    })
}

fn seed(db: &mut Store, settings: &Settings, account: &str, history_id: &str) {
    let state = SyncState {
        history_id: Some(history_id.to_string()),
        account: account.to_string(),
        lookback_days: settings.lookback_days,
        last_poll: None,
        last_full: None,
    };
    let key = format!("sync/{account}");
    db.change_meta(
        &[(&key, serde_json::to_value(&state).expect("serialize"))],
        &[],
        "test.seed",
        "seed cursor",
    )
    .expect("seed");
}

fn stored_cursor(db: &Store, account: &str) -> Option<String> {
    let key = format!("sync/{account}");
    let state: SyncState = db.meta(&key).expect("meta").expect("state present");
    state.history_id
}

/// The cursor advances only after EVERY page is durably inserted; the final
/// history id from the last page is what gets persisted.
#[test]
fn cursor_advances_only_after_all_pages() {
    let (_dir, mut db, settings) = harness();
    seed(&mut db, &settings, "tester@example.com", "900");
    let mut provider = FakeProvider {
        email: "tester@example.com".into(),
        pages: VecDeque::from([page(&["m1"], Some("p2"), "901"), page(&["m2"], None, "902")]),
        cancel: None,
        cancel_after: 0,
        calls: 0,
    };
    let cancelled = AtomicBool::new(false);
    let inserted = synchronize(
        &mut provider,
        &mut db,
        &settings,
        "tester@example.com",
        Utc::now(),
        &cancelled,
    )
    .expect("two-page sync");
    assert_eq!(inserted, 2);
    assert_eq!(
        stored_cursor(&db, "tester@example.com").as_deref(),
        Some("902")
    );
}

/// A sync stopped mid-run retains the previous cursor, and a later replay
/// must not duplicate identities (at-least-once with deduplication).
#[test]
fn cancelled_sync_retains_cursor_and_replay_is_idempotent() {
    let (_dir, mut db, settings) = harness();
    seed(&mut db, &settings, "tester@example.com", "900");
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut provider = FakeProvider {
        email: "tester@example.com".into(),
        pages: VecDeque::from([
            page(&["m1", "m2"], Some("p2"), "901"),
            page(&["m2", "m3"], None, "902"),
        ]),
        cancel: Some(cancelled.clone()),
        // Flip during the first page fetch so the second loop-top
        // cancellation check observes it: page 1 is already inserted.
        cancel_after: 1,
        calls: 0,
    };
    let err = synchronize(
        &mut provider,
        &mut db,
        &settings,
        "tester@example.com",
        Utc::now(),
        &cancelled,
    )
    .expect_err("second page must observe cancellation");
    assert!(err.to_string().contains("previous cursor retained"));
    assert_eq!(
        stored_cursor(&db, "tester@example.com").as_deref(),
        Some("900"),
        "no partial cursor commit"
    );

    let mut replay = FakeProvider {
        email: "tester@example.com".into(),
        pages: VecDeque::from([
            page(&["m1", "m2"], Some("p2"), "901"),
            page(&["m2", "m3"], None, "902"),
        ]),
        cancel: None,
        cancel_after: 0,
        calls: 0,
    };
    let fresh = AtomicBool::new(false);
    let replayed = synchronize(
        &mut replay,
        &mut db,
        &settings,
        "tester@example.com",
        Utc::now(),
        &fresh,
    )
    .expect("replay completes");
    assert_eq!(
        replayed, 1,
        "replay inserts only the missing identity: at-least-once without duplicates"
    );
    assert_eq!(
        stored_cursor(&db, "tester@example.com").as_deref(),
        Some("902")
    );
}

/// A provider that loops its pagination token must be rejected with the
/// cursor retained, or the loop could run forever.
#[test]
fn repeated_pagination_token_is_rejected() {
    let (_dir, mut db, settings) = harness();
    seed(&mut db, &settings, "tester@example.com", "900");
    let mut provider = FakeProvider {
        email: "tester@example.com".into(),
        pages: VecDeque::from([
            page(&["m1"], Some("same"), "901"),
            page(&["m2"], Some("same"), "902"),
        ]),
        cancel: None,
        cancel_after: 0,
        calls: 0,
    };
    let cancelled = AtomicBool::new(false);
    let err = synchronize(
        &mut provider,
        &mut db,
        &settings,
        "tester@example.com",
        Utc::now(),
        &cancelled,
    )
    .expect_err("duplicate token");
    assert!(err.to_string().contains("Repeated Gmail pagination token"));
    assert_eq!(
        stored_cursor(&db, "tester@example.com").as_deref(),
        Some("900")
    );
}

/// The provider profile account must match the workspace account, or mail
/// from a different mailbox could be ingested into this workspace.
#[test]
fn account_mismatch_is_rejected() {
    let (_dir, mut db, settings) = harness();
    let mut provider = FakeProvider {
        email: "someone-else@example.com".into(),
        pages: VecDeque::new(),
        cancel: None,
        cancel_after: 0,
        calls: 0,
    };
    let cancelled = AtomicBool::new(false);
    let err = synchronize(
        &mut provider,
        &mut db,
        &settings,
        "tester@example.com",
        Utc::now(),
        &cancelled,
    )
    .expect_err("wrong account");
    assert!(err.to_string().contains("Gmail account changed"));
}
