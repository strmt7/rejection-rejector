//! Deterministic provider fixtures. These tests never authorize or contact Gmail.
use anyhow::{anyhow, Result};
use chrono::Utc;
use rejection_rejector::{config::Settings, gmail::{Added, HistoryPage, HistoryRecord, HistoryResult, MessagePage, MessageRef, Profile}, store::Store, sync::{synchronize, Provider}, types::{JobState, Source, Stub, SyncState}, vault::Vault};
use std::{collections::VecDeque, sync::atomic::AtomicBool};

const ACCOUNT: &str = "candidate@example.com";
const KEY: &str = "sync/candidate@example.com";
struct Fake {
    account: String,
    lists: VecDeque<Result<MessagePage>>,
    histories: VecDeque<Result<HistoryResult>>,
    list_calls: usize,
}
impl Default for Fake {
    fn default() -> Self { Self { account: ACCOUNT.into(), lists: VecDeque::new(), histories: VecDeque::new(), list_calls: 0 } }
}
impl Provider for Fake {
    fn profile(&mut self) -> Result<Profile> { Ok(Profile { email_address: self.account.clone(), history_id: "90".into() }) }
    fn list(&mut self, _: &str, _: Option<&str>) -> Result<MessagePage> {
        self.list_calls += 1;
        self.lists.pop_front().unwrap_or_else(|| Err(anyhow!("Unexpected listing")))
    }
    fn history(&mut self, _: &str, _: Option<&str>) -> Result<HistoryResult> {
        self.histories.pop_front().unwrap_or_else(|| Err(anyhow!("Unexpected history page")))
    }
}
fn message(id: &str) -> MessageRef { MessageRef { id: id.into(), thread_id: format!("thread-{id}") } }
fn history(id: &str, next: Option<&str>) -> Result<HistoryResult> {
    Ok(HistoryResult::Page(HistoryPage { history: vec![HistoryRecord { messages_added: vec![Added { message: message(id) }] }], next_page_token: next.map(str::to_owned), history_id: "91".into() }))
}
fn setup() -> (tempfile::TempDir, Store) {
    let d = tempfile::tempdir().unwrap();
    let mut db = Store::open(&d.path().join("db"), Vault::random()).unwrap();
    db.set_meta(KEY, &SyncState { account: ACCOUNT.into(), history_id: Some("10".into()), lookback_days: 7, ..Default::default() }).unwrap();
    (d, db)
}
fn cursor(db: &Store) -> Option<String> { db.meta::<SyncState>(KEY).unwrap().unwrap().history_id }
#[test]
fn expired_history_runs_full_reconciliation_with_prelisting_baseline() {
    let (_d, mut db) = setup();
    let mut f = Fake::default();
    f.histories.push_back(Ok(HistoryResult::Expired));
    f.lists.push_back(Ok(MessagePage { messages: vec![message("one")], next_page_token: None }));
    assert_eq!(synchronize(&mut f, &mut db, &Settings::default(), ACCOUNT, Utc::now(), &AtomicBool::new(false)).unwrap(), 1);
    assert_eq!(cursor(&db).as_deref(), Some("90"));
    assert_eq!(f.list_calls, 1);
}
#[test]
fn partial_history_failure_retains_cursor_and_replay_deduplicates() {
    let (_d, mut db) = setup();
    let mut f = Fake::default();
    f.histories.push_back(history("one", Some("next")));
    f.histories.push_back(Err(anyhow!("Synthetic second-page failure")));
    assert!(synchronize(&mut f, &mut db, &Settings::default(), ACCOUNT, Utc::now(), &AtomicBool::new(false)).is_err());
    assert_eq!(cursor(&db).as_deref(), Some("10"));
    assert_eq!(db.counts(ACCOUNT).unwrap().stored, 1);
    f.histories.push_back(history("one", Some("next")));
    f.histories.push_back(history("two", None));
    assert_eq!(synchronize(&mut f, &mut db, &Settings::default(), ACCOUNT, Utc::now(), &AtomicBool::new(false)).unwrap(), 1);
    assert_eq!(db.counts(ACCOUNT).unwrap().stored, 2);
    assert_eq!(cursor(&db).as_deref(), Some("91"));
}
#[test]
fn repeated_page_token_fails_without_checkpointing() {
    let (_d, mut db) = setup();
    let mut f = Fake::default();
    f.histories.push_back(history("one", Some("same")));
    f.histories.push_back(history("two", Some("same")));
    assert!(synchronize(&mut f, &mut db, &Settings::default(), ACCOUNT, Utc::now(), &AtomicBool::new(false)).is_err());
    assert_eq!(cursor(&db).as_deref(), Some("10"));
}
#[test]
fn cancellation_keeps_previous_cursor() {
    let (_d, mut db) = setup();
    assert!(synchronize(&mut Fake::default(), &mut db, &Settings::default(), ACCOUNT, Utc::now(), &AtomicBool::new(true)).is_err());
    assert_eq!(cursor(&db).as_deref(), Some("10"));
}
#[test]
fn account_switch_is_rejected_before_listing() {
    let (_d, mut db) = setup();
    let mut f = Fake { account: "another@example.com".into(), ..Default::default() };
    assert!(synchronize(&mut f, &mut db, &Settings::default(), ACCOUNT, Utc::now(), &AtomicBool::new(false)).is_err());
    assert_eq!(f.list_calls, 0);
    assert_eq!(cursor(&db).as_deref(), Some("10"));
}
#[test]
fn widened_window_requeues_deferred_identity_without_duplicate() {
    let (_d, mut db) = setup();
    db.set_meta(KEY, &SyncState { account: ACCOUNT.into(), history_id: Some("10".into()), lookback_days: 1, ..Default::default() }).unwrap();
    let stub = Stub { account: ACCOUNT.into(), provider_id: "one".into(), thread_id: "thread-one".into(), source: Source::Gmail };
    let id = stub.id();
    db.insert_stub(stub, Utc::now()).unwrap();
    let mut job = db.get(&id).unwrap();
    job.state = JobState::Deferred;
    db.save(&mut job, "test", "Deferred synthetic item").unwrap();
    let mut f = Fake::default();
    f.lists.push_back(Ok(MessagePage { messages: vec![message("one")], next_page_token: None }));
    synchronize(&mut f, &mut db, &Settings::default(), ACCOUNT, Utc::now(), &AtomicBool::new(false)).unwrap();
    assert_eq!(db.counts(ACCOUNT).unwrap().stored, 1);
    assert_eq!(db.get(&id).unwrap().state, JobState::Queued);
}
