use crate::{
    config::Settings,
    engine::Engine,
    oauth,
    ollama::{self, ModelStatus, Ollama},
    types::*,
};
use anyhow::Result;
use chrono::{DateTime, Utc};
use crossbeam_channel::{bounded, Receiver, Sender};
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

#[derive(Clone, Default)]
pub struct Snapshot {
    pub initialized: bool,
    pub fatal: bool,
    pub busy: String,
    pub notice: String,
    pub error: String,
    pub settings: Settings,
    pub settings_revision: u64,
    pub account: String,
    pub connected: bool,
    pub send_scope: bool,
    pub demo: bool,
    pub counts: Counts,
    pub model: ModelStatus,
    pub last_poll: Option<DateTime<Utc>>,
    pub next_poll: Option<DateTime<Utc>>,
    pub items: Vec<Job>,
    pub selected: Option<Job>,
    pub events: Vec<AuditEvent>,
    pub page: u32,
    pub review_only: bool,
    pub api_token: Option<String>,
    pub api_listening: bool,
}
pub enum Command {
    Refresh,
    CheckNow,
    Connect {
        path: PathBuf,
        send: bool,
    },
    Disconnect,
    Settings(Settings),
    InstallOllama,
    StartOllama,
    PullModel,
    InspectModel,
    QualifyModel,
    EvaluateModel,
    List {
        review: bool,
        page: u32,
    },
    Select(String),
    Edit {
        id: String,
        revision: u64,
        body: String,
    },
    Regenerate {
        id: String,
        revision: u64,
    },
    Dismiss {
        id: String,
        revision: u64,
    },
    Send {
        id: String,
        revision: u64,
        body_hash: String,
    },
    Reconcile(String),
    Purge,
    RevealApiToken,
    Api {
        path: String,
        reply: Sender<Value>,
    },
}
pub struct Worker {
    pub tx: Sender<Command>,
    pub snapshot: Arc<Mutex<Snapshot>>,
    pub paused: Arc<AtomicBool>,
    pub stop: Arc<AtomicBool>,
}
impl Worker {
    pub fn spawn(dir: PathBuf, demo: bool) -> Self {
        let (tx, rx) = bounded(32);
        let snapshot = Arc::new(Mutex::new(Snapshot::default()));
        let paused = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let (s, p, c, sender) = (snapshot.clone(), paused.clone(), stop.clone(), tx.clone());
        std::thread::spawn(move || {
            let result = Engine::open(dir, demo, p, c.clone())
                .and_then(|engine| run(engine, rx, s.clone(), sender));
            if let Err(e) = result {
                if let Ok(mut view) = s.lock() {
                    view.error = format!("{e:#}");
                    view.fatal = true;
                    view.busy.clear();
                }
            }
        });
        Self {
            tx,
            snapshot,
            paused,
            stop,
        }
    }
    pub fn command(&self, command: Command) {
        if self.tx.try_send(command).is_err() {
            if let Ok(mut s) = self.snapshot.lock() {
                s.error = "Command queue is busy. Wait for the current operation to finish.".into();
            }
        }
    }
    pub fn view(&self) -> Snapshot {
        self.snapshot.lock().map(|s| s.clone()).unwrap_or_default()
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.paused.store(true, Ordering::SeqCst);
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn refresh(
    e: &Engine,
    shared: &Arc<Mutex<Snapshot>>,
    selected: Option<&str>,
    review: bool,
    page: u32,
) -> Result<()> {
    let counts = e.db.counts(&e.account)?;
    let items = e.db.list(&e.account, review, page, 25)?;
    let last = e.last_poll()?;
    let events = e.db.events((e.db.latest_event_seq()? - 60).max(0), 60)?;
    let selected = selected.and_then(|id| e.owned(id).ok());
    let mut s = shared
        .lock()
        .map_err(|_| anyhow::anyhow!("UI state lock failed"))?;
    s.initialized = true;
    s.account = e.account.clone();
    s.connected = e.connected();
    s.send_scope = e.send_scope();
    s.demo = e.demo;
    s.settings = e.settings.clone();
    s.counts = counts;
    s.model = e.model.clone();
    s.last_poll = last;
    s.next_poll = last.map(|t| t + chrono::Duration::seconds(e.settings.interval_seconds()));
    s.items = items;
    s.events = events;
    s.selected = selected;
    s.page = page;
    s.review_only = review;
    Ok(())
}
fn busy(shared: &Arc<Mutex<Snapshot>>, text: &str) {
    if let Ok(mut s) = shared.lock() {
        s.busy = text.into();
    }
}
fn report(shared: &Arc<Mutex<Snapshot>>, result: &Result<()>) {
    if let Ok(mut s) = shared.lock() {
        s.busy.clear();
        match result {
            Ok(()) => {
                s.error.clear();
                s.notice = "Operation completed.".into();
            }
            Err(e) => {
                s.error = format!("{e:#}");
                s.notice.clear();
            }
        }
    }
}
fn run(
    mut e: Engine,
    rx: Receiver<Command>,
    shared: Arc<Mutex<Snapshot>>,
    sender: Sender<Command>,
) -> Result<()> {
    let mut selected: Option<String> = None;
    let mut review = true;
    let mut page = 0;
    refresh(&e, &shared, None, review, page)?;
    if e.settings.api_enabled && !e.demo {
        let token: String = match e.db.meta("api_token")? {
            Some(t) => t,
            None => {
                let t = oauth::secret();
                e.db.set_meta("api_token", &t)?;
                t
            }
        };
        match crate::api::start(e.settings.api_port, token, sender, e.stop.clone()) {
            Ok(()) => {
                if let Ok(mut s) = shared.lock() {
                    s.api_listening = true;
                }
            }
            Err(error) => {
                if let Ok(mut s) = shared.lock() {
                    s.error = format!("Integration API did not start: {error}");
                }
            }
        }
    }
    let mut sync_retry = Instant::now();
    let mut auto_due = Instant::now();
    let mut process_due = Instant::now();
    while !e.stop.load(Ordering::SeqCst) {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(Command::Api { path, reply }) => {
                let data = api_query(&e, &path)
                    .unwrap_or_else(|_| json!({"error":"Invalid request or unavailable resource"}));
                let _ = reply.try_send(data);
            }
            Ok(command) => {
                busy(&shared, "Working locally…");
                let mut settings_changed = false;
                let result: Result<()> = match command {
                    Command::Refresh => Ok(()),
                    Command::CheckNow => {
                        busy(&shared, "Checking Gmail for missing messages…");
                        e.synchronize().map(|_| ())
                    }
                    Command::Connect { path, send } => {
                        busy(&shared,"Complete Google sign-in in your browser. This expires after five minutes.");
                        let r = e.connect(&path, send);
                        settings_changed = r.is_ok();
                        r
                    }
                    Command::Disconnect => {
                        selected = None;
                        settings_changed = true;
                        e.disconnect()
                    }
                    Command::Settings(s) => {
                        let r = e.update_settings(s);
                        settings_changed = r.is_ok();
                        r
                    }
                    Command::InstallOllama => {
                        busy(
                            &shared,
                            "Running the Ollama installer. Approve its Windows prompts.",
                        );
                        ollama::install()
                    }
                    Command::StartOllama => Ollama::new(&e.settings).and_then(|o| o.start()),
                    Command::PullModel => {
                        busy(&shared, "Downloading the selected local model…");
                        Ollama::new(&e.settings)
                            .and_then(|o| o.pull(&e.stop, |p| busy(&shared, &p)))
                    }
                    Command::InspectModel => {
                        busy(&shared, "Refreshing local model status…");
                        e.inspect_model_status()
                    }
                    Command::QualifyModel => {
                        busy(
                            &shared,
                            "Running a local model smoke test and checking GPU residency…",
                        );
                        let r = e.qualify();
                        settings_changed = r.is_ok();
                        r
                    }
                    Command::EvaluateModel => {
                        busy(&shared, "Running the local synthetic evaluation suite…");
                        e.evaluate_model().map(|_| ())
                    }
                    Command::List { review: r, page: p } => {
                        review = r;
                        page = p;
                        Ok(())
                    }
                    Command::Select(id) => {
                        selected = Some(id);
                        Ok(())
                    }
                    Command::Edit { id, revision, body } => e.edit(&id, revision, body),
                    Command::Regenerate { id, revision } => e.regenerate(&id, revision),
                    Command::Dismiss { id, revision } => e.dismiss(&id, revision),
                    Command::Send {
                        id,
                        revision,
                        body_hash,
                    } => {
                        busy(
                            &shared,
                            "Rechecking the conversation and sending your confirmed reply…",
                        );
                        e.send(&id, revision, &body_hash, false)
                    }
                    Command::Reconcile(id) => e.reconcile(&id),
                    Command::Purge => e.db.purge(e.settings.retention_days).map(|_| ()),
                    Command::RevealApiToken => {
                        let t = e.db.meta::<String>("api_token")?;
                        if let Ok(mut s) = shared.lock() {
                            s.api_token = t;
                        }
                        Ok(())
                    }
                    Command::Api { .. } => Err(anyhow::anyhow!(
                        "Internal API command reached the wrong dispatcher"
                    )),
                };
                if settings_changed {
                    if let Ok(mut s) = shared.lock() {
                        s.settings_revision += 1;
                    }
                }
                report(&shared, &result);
                refresh(&e, &shared, selected.as_deref(), review, page)?;
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
        }
        if e.paused.load(Ordering::SeqCst) || e.demo || !e.connected() {
            continue;
        }
        let now = Utc::now();
        if Instant::now() >= sync_retry
            && e.last_poll()?.is_none_or(|t| {
                now.signed_duration_since(t).num_seconds() >= e.settings.interval_seconds()
            })
        {
            busy(
                &shared,
                "Scheduled Gmail check: fetching only missing identities…",
            );
            let result = e.synchronize().map(|_| ());
            report(&shared, &result);
            sync_retry =
                Instant::now() + Duration::from_secs(if result.is_ok() { 30 } else { 300 });
            refresh(&e, &shared, selected.as_deref(), review, page)?;
        }
        if Instant::now() >= process_due
            && e.settings.model_digest.is_some()
            && e.db.next_queued(&e.account, Utc::now())?.is_some()
        {
            busy(
                &shared,
                "Local AI: classifying, drafting and checking one new email…",
            );
            let result = e.process_one().map(|_| ());
            report(&shared, &result);
            process_due = Instant::now() + Duration::from_secs(if result.is_ok() { 1 } else { 30 });
            refresh(&e, &shared, selected.as_deref(), review, page)?;
        }
        if Instant::now() >= auto_due {
            let result = e.automatic_tick();
            if !matches!(result, Ok(false)) {
                report(&shared, &result.map(|_| ()));
                refresh(&e, &shared, selected.as_deref(), review, page)?;
            }
            auto_due = Instant::now() + Duration::from_secs(30);
        }
    }
    Ok(())
}
fn api_query(e: &Engine, path: &str) -> Result<Value> {
    let u = url::Url::parse(&format!("http://127.0.0.1{path}"))?;
    let query: std::collections::HashMap<_, _> = u.query_pairs().collect();
    match u.path() {
        "/v1/capabilities" => Ok(json!({
            "api_version": 1,
            "application_version": env!("CARGO_PKG_VERSION"),
            "read_only": true,
            "mail_provider": "gmail",
            "modes": ["human_review", "automatic"],
            "features": {
                "encrypted_local_store": true,
                "incremental_sync": true,
                "local_ollama": true,
                "review_queue": true,
                "automatic_policy": true,
                "delivery_reconciliation": true,
                "events": true
            },
            "poll_hours": crate::config::POLL_HOURS,
            "lookback_days": crate::config::LOOKBACK_DAYS
        })),
        "/v1/status" => Ok(
            json!({"version":env!("CARGO_PKG_VERSION"),"account":e.account,"connected":e.connected(),"paused":e.paused.load(Ordering::SeqCst),"mode":e.settings.mode,"sending_enabled":e.settings.sending_enabled,"counts":e.db.counts(&e.account)?,"last_poll":e.last_poll()?}),
        ),
        "/v1/items" => {
            let page = query
                .get("page")
                .map(|v| v.parse::<u32>())
                .transpose()?
                .unwrap_or(0);
            Ok(json!({"page":page,"page_size":25,"items":e.db.list(&e.account,false,page,25)?}))
        }
        "/v1/events" => {
            let after = query
                .get("after")
                .map(|v| v.parse::<i64>())
                .transpose()?
                .unwrap_or(0);
            Ok(json!({"events":e.db.events(after.max(0),100)?}))
        }
        path if path.starts_with("/v1/items/") => {
            let id = path.trim_start_matches("/v1/items/");
            Ok(serde_json::to_value(e.owned(id)?)?)
        }
        _ => Err(anyhow::anyhow!("Unknown API route")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capabilities_are_versioned_and_read_only() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(
            dir.path().into(),
            true,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let value = api_query(&engine, "/v1/capabilities").unwrap();
        assert_eq!(value["api_version"], 1);
        assert_eq!(value["read_only"], true);
        assert_eq!(value["mail_provider"], "gmail");
        assert_eq!(
            value["poll_hours"],
            serde_json::json!(crate::config::POLL_HOURS)
        );
    }

    #[test]
    fn demo_worker_initializes_and_publishes_selection() {
        let dir = tempfile::tempdir().unwrap();
        let worker = Worker::spawn(dir.path().into(), true);
        let start = Instant::now();
        let first = loop {
            let s = worker.view();
            assert!(!s.fatal, "{}", s.error);
            if s.initialized {
                assert_eq!(s.items.len(), 3);
                break s.items[0].id.clone();
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "Worker did not initialize"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        worker.command(Command::Select(first.clone()));
        loop {
            let s = worker.view();
            assert!(!s.fatal, "{}", s.error);
            if let Some(job) = s.selected {
                assert_eq!(job.id, first);
                assert!(job.draft.is_some());
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "Worker did not publish selection"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
