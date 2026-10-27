use crate::{
    types::{OperationKind, OperationState, OperationStatus},
    vault::private_dir,
};
use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

/// Default rotation size of the current runtime log.
///
/// Inputs: none (constant). Output: `u64` — the byte cap before rotation.
pub const DEFAULT_MAX_CURRENT_BYTES: u64 = 2 * 1024 * 1024;
/// Default number of rotated runtime-log archives kept.
///
/// Inputs: none (constant). Output: `usize` — the retained archive count.
pub const DEFAULT_MAX_ARCHIVES: usize = 3;
const LOG_SCHEMA_VERSION: u32 = 3;
const CURRENT_FILE: &str = "runtime.jsonl";

/// Notable process-level event recorded in the runtime log.
///
/// Inputs: none (plain enum). Output: the event kind from process start
/// through worker and API listener failures.
#[derive(Clone, Copy, Debug)]
pub enum RuntimeEvent {
    /// The application process started.
    ProcessStarted,
    /// The application process stopped.
    ProcessStopped,
    /// The background worker failed to start.
    WorkerStartupFailed,
    /// The background worker panicked.
    WorkerPanicked,
    /// The local API listener started.
    ApiListenerStarted,
    /// The local API listener failed to start or serve.
    ApiListenerFailed,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum RuntimeSignal {
    GmailCircuitOpened,
    GmailCircuitClosed,
    LocalAiCircuitOpened,
    LocalAiCircuitClosed,
}

impl RuntimeEvent {
    /// Render one runtime event as its stable code.
    ///
    /// Inputs: `self` — the event. Output: `&'static str` — the wire code.
    fn code(self) -> &'static str {
        match self {
            Self::ProcessStarted => "process_started",
            Self::ProcessStopped => "process_stopped",
            Self::WorkerStartupFailed => "worker_startup_failed",
            Self::WorkerPanicked => "worker_panicked",
            Self::ApiListenerStarted => "api_listener_started",
            Self::ApiListenerFailed => "api_listener_failed",
        }
    }

    /// Classify one runtime event's severity.
    ///
    /// Inputs: `self` — the event. Output: `&'static str` — `error` for failure
    /// events, `info` otherwise.
    fn level(self) -> &'static str {
        match self {
            Self::WorkerStartupFailed | Self::WorkerPanicked | Self::ApiListenerFailed => "error",
            _ => "info",
        }
    }
}

impl RuntimeSignal {
    /// Render one runtime signal as its stable code.
    ///
    /// Inputs: `self` — the signal. Output: `&'static str` — the wire code.
    fn code(self) -> &'static str {
        match self {
            Self::GmailCircuitOpened => "gmail_circuit_opened",
            Self::GmailCircuitClosed => "gmail_circuit_closed",
            Self::LocalAiCircuitOpened => "local_ai_circuit_opened",
            Self::LocalAiCircuitClosed => "local_ai_circuit_closed",
        }
    }

    /// Classify one runtime signal's severity.
    ///
    /// Inputs: `self` — the signal. Output: `&'static str` — `warning` when a
    /// circuit opens, `info` when it closes.
    fn level(self) -> &'static str {
        match self {
            Self::GmailCircuitOpened | Self::LocalAiCircuitOpened => "warning",
            Self::GmailCircuitClosed | Self::LocalAiCircuitClosed => "info",
        }
    }
}

/// Operation-duration summary parsed from the runtime log.
///
/// Inputs: none (plain struct). Output: retained, succeeded, failed and
/// timed operation counts with mean and max durations and parse errors.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct RuntimePerformanceSummary {
    /// Schema version of the summary record.
    pub schema_version: u32,
    /// Operation records retained in the log.
    pub retained_operation_records: u64,
    /// Operations recorded as succeeded.
    pub succeeded_operations: u64,
    /// Operations recorded as failed.
    pub failed_operations: u64,
    /// Operations recorded with duration data.
    pub timed_operations: u64,
    /// Mean operation duration in milliseconds.
    pub mean_duration_ms: Option<u64>,
    /// Maximum operation duration in milliseconds.
    pub max_duration_ms: Option<u64>,
    /// Log lines that could not be parsed.
    pub parse_errors: u64,
}

/// Rotation status of the runtime log files.
///
/// Inputs: none (plain struct). Output: availability, per-file byte sizes,
/// archive count and the configured caps.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct RuntimeLogStatus {
    /// Schema version of the status record.
    pub schema_version: u32,
    /// Whether runtime logging is available.
    pub available: bool,
    /// Size of the current log file in bytes.
    pub current_bytes: u64,
    /// Total size of archived logs in bytes.
    pub archive_bytes: u64,
    /// Combined size of current and archived logs in bytes.
    pub total_bytes: u64,
    /// Number of archived log files.
    pub archive_count: usize,
    /// Rotation threshold for the current log in bytes.
    pub max_current_bytes: u64,
    /// Maximum number of archived logs retained.
    pub max_archives: usize,
}

#[derive(Serialize)]
struct RuntimeRecord {
    schema_version: u32,
    at: DateTime<Utc>,
    level: &'static str,
    event: &'static str,
    operation: Option<OperationKind>,
    operation_id: Option<String>,
    state: Option<OperationState>,
    code: Option<String>,
    retryable: bool,
    duration_ms: Option<u64>,
}

#[derive(Deserialize)]
struct RuntimeRecordView {
    event: String,
    state: Option<OperationState>,
    #[serde(default)]
    duration_ms: Option<u64>,
}

struct Inner {
    directory: PathBuf,
    max_bytes: u64,
    max_archives: usize,
}

/// Cloneable handle appending events to the runtime journal.
///
/// Inputs: none (plain struct). Output: the shared journal writer.
#[derive(Clone)]
pub struct RuntimeJournal {
    inner: Arc<Mutex<Inner>>,
}

impl RuntimeJournal {
    /// Open the runtime log for one workspace.
    ///
    /// Inputs: `data_dir` — workspace directory. Output: `Result<Self>` with the
    /// default size and archive limits.
    pub fn open(data_dir: &Path) -> Result<Self> {
        Self::open_with_limits(data_dir, DEFAULT_MAX_CURRENT_BYTES, DEFAULT_MAX_ARCHIVES)
    }

    /// Open (or create) the runtime journal under size limits.
    ///
    /// Inputs: `data_dir` — workspace data directory (logs live in `logs/`);
    /// `max_bytes` — rotation size limit (at least 256); `max_archives` — archive
    /// count to keep (1..=16). Output: `Result<Self>` — the open journal.
    fn open_with_limits(data_dir: &Path, max_bytes: u64, max_archives: usize) -> Result<Self> {
        ensure!(max_bytes >= 256, "Runtime log size limit is too small");
        ensure!(
            (1..=16).contains(&max_archives),
            "Runtime log archive limit is invalid"
        );
        let directory = data_dir.join("logs");
        private_dir(&directory)?;
        ensure!(
            !fs::symlink_metadata(&directory)?.file_type().is_symlink(),
            "Runtime log directory must not be a symlink"
        );
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner {
                directory,
                max_bytes,
                max_archives,
            })),
        })
    }

    /// Append one runtime event record.
    ///
    /// Inputs: `event` — event to record. Output: `Ok(())` once written.
    pub fn record_event(&self, event: RuntimeEvent) -> Result<()> {
        self.write(RuntimeRecord {
            schema_version: LOG_SCHEMA_VERSION,
            at: Utc::now(),
            level: event.level(),
            event: event.code(),
            operation: None,
            operation_id: None,
            state: None,
            code: None,
            retryable: false,
            duration_ms: None,
        })
    }

    /// Append one runtime signal record.
    ///
    /// Inputs: `signal` — signal to record. Output: `Ok(())` once written.
    pub(crate) fn record_signal(&self, signal: RuntimeSignal) -> Result<()> {
        self.write(RuntimeRecord {
            schema_version: LOG_SCHEMA_VERSION,
            at: Utc::now(),
            level: signal.level(),
            event: signal.code(),
            operation: None,
            operation_id: None,
            state: None,
            code: None,
            retryable: false,
            duration_ms: None,
        })
    }

    /// Append an operation state-change record.
    ///
    /// Inputs: `kind` — operation kind; `state` — operation state. Output: `Ok(())`
    /// once written.
    pub fn record_operation(&self, kind: OperationKind, state: OperationState) -> Result<()> {
        let status = OperationStatus {
            operation_id: None,
            kind,
            state,
            code: (state == OperationState::Failed).then(|| kind.failure_code().into()),
            retryable: state == OperationState::Failed && kind.retryable(),
            message: String::default(),
            started_at: None,
            finished_at: None,
        };
        self.record_operation_status(&status)
    }

    /// Append a full operation status record.
    ///
    /// Inputs: `status` — operation status to record. Output: `Ok(())` once
    /// written; malformed operation ids are refused.
    pub fn record_operation_status(&self, status: &OperationStatus) -> Result<()> {
        if let Some(operation_id) = &status.operation_id {
            ensure!(
                uuid::Uuid::parse_str(operation_id).is_ok(),
                "Runtime operation ID must be a UUID"
            );
        }
        let failed = status.state == OperationState::Failed;
        self.write(RuntimeRecord {
            schema_version: LOG_SCHEMA_VERSION,
            at: Utc::now(),
            level: if failed { "error" } else { "info" },
            event: "operation",
            operation: Some(status.kind),
            operation_id: status.operation_id.clone(),
            state: Some(status.state),
            code: status.code.clone(),
            retryable: status.retryable,
            duration_ms: operation_duration_ms(status),
        })
    }

    /// Append one record to the runtime journal.
    ///
    /// Inputs: `record` — record to serialize. Output: `Result<()>` — `Ok` once the
    /// JSONL line is appended (the journal rotates when full).
    fn write(&self, record: RuntimeRecord) -> Result<()> {
        let mut line = serde_json::to_vec(&record)?;
        line.push(b'\n');
        let inner = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("Runtime log lock is poisoned"))?;
        let current = inner.directory.join(CURRENT_FILE);
        reject_symlink_if_present(&current)?;
        let current_bytes = fs::metadata(&current).map_or(0, |m| m.len());
        if current_bytes > 0 && current_bytes.saturating_add(line.len() as u64) > inner.max_bytes {
            rotate(&inner.directory, inner.max_archives)?;
        }
        append_private(&current, &line)?;
        Ok(())
    }

    /// Report the runtime log's current status.
    ///
    /// Inputs: none beyond the log. Output: `Result<RuntimeLogStatus>` with sizes,
    /// archives and truncation counters.
    pub fn status(&self) -> Result<RuntimeLogStatus> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("Runtime log lock is poisoned"))?;
        status_for(&inner.directory, inner.max_bytes, inner.max_archives)
    }
}

/// Compute one operation's duration in milliseconds.
///
/// Inputs: `status` — operation status carrying both timestamps. Output:
/// `Option<u64>` — the non-negative duration; `None` when either timestamp is
/// missing or time ran backwards.
fn operation_duration_ms(status: &OperationStatus) -> Option<u64> {
    let (Some(started), Some(finished)) = (status.started_at, status.finished_at) else {
        return None;
    };
    let milliseconds = finished.signed_duration_since(started).num_milliseconds();
    (milliseconds >= 0).then_some(milliseconds as u64)
}

/// Summarize recorded performance across the log and its archives.
///
/// Inputs: `data_dir` — workspace directory. Output: `Result<RuntimePerformanceSummary>`
/// for monitoring surfaces.
pub fn performance_summary(data_dir: &Path) -> Result<RuntimePerformanceSummary> {
    let directory = data_dir.join("logs");
    if !directory.exists() {
        return Ok(RuntimePerformanceSummary {
            schema_version: LOG_SCHEMA_VERSION,
            ..RuntimePerformanceSummary::default()
        });
    }
    ensure!(
        !fs::symlink_metadata(&directory)?.file_type().is_symlink(),
        "Runtime log directory must not be a symlink"
    );

    let mut summary = RuntimePerformanceSummary {
        schema_version: LOG_SCHEMA_VERSION,
        ..RuntimePerformanceSummary::default()
    };
    let mut duration_sum = 0u128;

    for path in std::iter::once(directory.join(CURRENT_FILE))
        .chain((1..=DEFAULT_MAX_ARCHIVES).map(|index| archive_path(&directory, index)))
    {
        reject_symlink_if_present(&path)?;
        if !path.is_file() {
            continue;
        }
        for line in BufReader::new(fs::File::open(&path)?).lines() {
            let line = line?;
            if line.len() > 16 * 1024 {
                summary.parse_errors = summary.parse_errors.saturating_add(1);
                continue;
            }
            let record: RuntimeRecordView = match serde_json::from_str(&line) {
                Ok(record) => record,
                Err(_) => {
                    summary.parse_errors = summary.parse_errors.saturating_add(1);
                    continue;
                }
            };
            if record.event != "operation" {
                continue;
            }
            summary.retained_operation_records =
                summary.retained_operation_records.saturating_add(1);
            match record.state {
                Some(OperationState::Succeeded) => {
                    summary.succeeded_operations = summary.succeeded_operations.saturating_add(1);
                }
                Some(OperationState::Failed) => {
                    summary.failed_operations = summary.failed_operations.saturating_add(1);
                }
                _ => {}
            }
            if let Some(duration_ms) = record.duration_ms {
                summary.timed_operations = summary.timed_operations.saturating_add(1);
                duration_sum = duration_sum.saturating_add(u128::from(duration_ms));
                summary.max_duration_ms = Some(
                    summary
                        .max_duration_ms
                        .map_or(duration_ms, |current| current.max(duration_ms)),
                );
            }
        }
    }
    if summary.timed_operations > 0 {
        summary.mean_duration_ms =
            Some((duration_sum / u128::from(summary.timed_operations)) as u64);
    }
    Ok(summary)
}

/// Report the runtime log status for one workspace directory.
///
/// Inputs: `data_dir` — workspace directory. Output: `Result<RuntimeLogStatus>`
/// with the default limits applied.
pub fn status(data_dir: &Path) -> Result<RuntimeLogStatus> {
    status_for(
        &data_dir.join("logs"),
        DEFAULT_MAX_CURRENT_BYTES,
        DEFAULT_MAX_ARCHIVES,
    )
}

/// Report the runtime log's on-disk status.
///
/// Inputs: `directory` — log directory; `max_bytes` — rotation size limit;
/// `max_archives` — archive count. Output: `Result<RuntimeLogStatus>` — byte
/// totals and rotation limits (`available: false` when the directory is
/// absent).
fn status_for(directory: &Path, max_bytes: u64, max_archives: usize) -> Result<RuntimeLogStatus> {
    if !directory.exists() {
        return Ok(RuntimeLogStatus {
            schema_version: LOG_SCHEMA_VERSION,
            available: false,
            current_bytes: 0,
            archive_bytes: 0,
            total_bytes: 0,
            archive_count: 0,
            max_current_bytes: max_bytes,
            max_archives,
        });
    }
    ensure!(
        !fs::symlink_metadata(directory)?.file_type().is_symlink(),
        "Runtime log directory must not be a symlink"
    );
    let current = directory.join(CURRENT_FILE);
    reject_symlink_if_present(&current)?;
    let current_bytes = fs::metadata(&current).map_or(0, |m| m.len());
    let mut archive_count = 0usize;
    let mut archive_bytes = 0u64;
    for index in 1..=max_archives {
        let path = archive_path(directory, index);
        reject_symlink_if_present(&path)?;
        if path.is_file() {
            archive_count += 1;
            archive_bytes = archive_bytes.saturating_add(fs::metadata(&path)?.len());
        }
    }
    Ok(RuntimeLogStatus {
        schema_version: LOG_SCHEMA_VERSION,
        available: current.is_file(),
        current_bytes,
        archive_bytes,
        total_bytes: current_bytes.saturating_add(archive_bytes),
        archive_count,
        max_current_bytes: max_bytes,
        max_archives,
    })
}

/// Rotate the runtime log archives.
///
/// Inputs: `directory` — log directory; `max_archives` — archive count to keep.
/// Output: `Result<()>` — `Ok` once the oldest archive is dropped and the rest
/// shift up.
fn rotate(directory: &Path, max_archives: usize) -> Result<()> {
    let oldest = archive_path(directory, max_archives);
    if oldest.exists() {
        reject_symlink_if_present(&oldest)?;
        fs::remove_file(&oldest)?;
    }
    for index in (1..max_archives).rev() {
        let from = archive_path(directory, index);
        if from.exists() {
            reject_symlink_if_present(&from)?;
            fs::rename(&from, archive_path(directory, index + 1))?;
        }
    }
    let current = directory.join(CURRENT_FILE);
    if current.exists() {
        reject_symlink_if_present(&current)?;
        fs::rename(current, archive_path(directory, 1))?;
    }
    Ok(())
}

/// Build one archive file path.
///
/// Inputs: `directory` — log directory; `index` — archive index. Output:
/// `PathBuf` — the `runtime.<index>.jsonl` path.
fn archive_path(directory: &Path, index: usize) -> PathBuf {
    directory.join(format!("runtime.{index}.jsonl"))
}

/// Refuse a symlinked runtime log path.
///
/// Inputs: `path` — file path to check. Output: `Result<()>` — `Ok` when the
/// path is absent or a regular file; error for symlinks.
fn reject_symlink_if_present(path: &Path) -> Result<()> {
    if path.exists() {
        ensure!(
            !fs::symlink_metadata(path)?.file_type().is_symlink(),
            "Runtime log files must not be symlinks"
        );
    }
    Ok(())
}

/// Append bytes to one private file.
///
/// Inputs: `path` — file to append to (created when absent); `bytes` — content
/// to append. Output: `Result<()>` — `Ok` once written.
fn append_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_journal_contains_only_typed_operational_fields() {
        let root = tempfile::tempdir().unwrap();
        let journal = RuntimeJournal::open(root.path()).unwrap();
        journal.record_event(RuntimeEvent::ProcessStarted).unwrap();
        journal
            .record_operation(OperationKind::SendReply, OperationState::Failed)
            .unwrap();

        let text = fs::read_to_string(root.path().join("logs").join(CURRENT_FILE)).unwrap();
        assert!(text.contains("\"event\":\"process_started\""));
        assert!(text.contains("\"operation\":\"send_reply\""));
        assert!(text.contains("\"code\":\"reply_send_failed\""));
        for forbidden in [
            "message",
            "subject",
            "recipient",
            "email",
            "token",
            "signature",
            "candidate_context",
        ] {
            assert!(!text.contains(forbidden));
        }
    }

    #[test]
    fn runtime_operation_id_is_stable_and_privacy_safe() {
        let root = tempfile::tempdir().unwrap();
        let journal = RuntimeJournal::open(root.path()).unwrap();
        let operation_id = uuid::Uuid::new_v4().to_string();
        let status = OperationStatus {
            operation_id: Some(operation_id.clone()),
            kind: OperationKind::Backup,
            state: OperationState::Running,
            code: None,
            retryable: false,
            message: "PRIVATE_MESSAGE_MUST_NOT_BE_LOGGED".into(),
            started_at: Some(Utc::now()),
            finished_at: None,
        };
        journal.record_operation_status(&status).unwrap();
        let line = fs::read_to_string(root.path().join("logs").join(CURRENT_FILE)).unwrap();
        let value: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(value["schema_version"], LOG_SCHEMA_VERSION);
        assert_eq!(value["operation_id"], operation_id);
        assert!(uuid::Uuid::parse_str(value["operation_id"].as_str().unwrap()).is_ok());
        assert!(!line.contains("PRIVATE_MESSAGE_MUST_NOT_BE_LOGGED"));
    }

    #[test]
    fn runtime_journal_records_and_summarizes_operation_durations() {
        let root = tempfile::tempdir().unwrap();
        let journal = RuntimeJournal::open(root.path()).unwrap();
        let started = Utc::now();
        let status = OperationStatus {
            operation_id: Some(uuid::Uuid::new_v4().to_string()),
            kind: OperationKind::Backup,
            state: OperationState::Succeeded,
            code: None,
            retryable: false,
            message: "PRIVATE_MESSAGE_MUST_NOT_BE_LOGGED".into(),
            started_at: Some(started),
            finished_at: Some(started + chrono::Duration::milliseconds(1250)),
        };
        journal.record_operation_status(&status).unwrap();

        let summary = performance_summary(root.path()).unwrap();
        assert_eq!(summary.retained_operation_records, 1);
        assert_eq!(summary.succeeded_operations, 1);
        assert_eq!(summary.failed_operations, 0);
        assert_eq!(summary.timed_operations, 1);
        assert_eq!(summary.mean_duration_ms, Some(1250));
        assert_eq!(summary.max_duration_ms, Some(1250));
        assert_eq!(summary.parse_errors, 0);

        let text = fs::read_to_string(root.path().join("logs").join(CURRENT_FILE)).unwrap();
        assert!(text.contains("\"duration_ms\":1250"));
        assert!(!text.contains("PRIVATE_MESSAGE_MUST_NOT_BE_LOGGED"));
    }

    #[test]
    fn runtime_journal_rotates_with_a_bounded_archive_set() {
        let root = tempfile::tempdir().unwrap();
        let journal = RuntimeJournal::open_with_limits(root.path(), 256, 2).unwrap();
        for _ in 0..30 {
            journal
                .record_operation(OperationKind::SyncMailbox, OperationState::Succeeded)
                .unwrap();
        }
        let status = journal.status().unwrap();
        assert!(status.available);
        assert!(status.current_bytes > 0);
        assert!(status.archive_count <= 2);
        assert!(status.archive_bytes > 0);
        assert_eq!(
            status.total_bytes,
            status.current_bytes + status.archive_bytes
        );
        assert!(root.path().join("logs/runtime.1.jsonl").is_file());
        assert!(!root.path().join("logs/runtime.3.jsonl").exists());
    }

    #[test]
    fn status_is_non_creating_for_unused_workspaces() {
        let root = tempfile::tempdir().unwrap();
        let status = status(root.path()).unwrap();
        assert!(!status.available);
        assert_eq!(status.current_bytes, 0);
        assert_eq!(status.archive_bytes, 0);
        assert_eq!(status.total_bytes, 0);
        assert_eq!(status.archive_count, 0);
        assert!(!root.path().join("logs").exists());
    }

    /// Why: journal event codes and their severity levels are a stable operator
    /// contract; a renamed code or a demoted error level would silently break
    /// severity filters and incident tooling while still parsing cleanly.
    /// Inputs: one record per `RuntimeEvent` variant. Output: each contracted
    /// code appears verbatim with its contracted level.
    #[test]
    fn runtime_event_codes_and_levels_are_stable() {
        let root = tempfile::tempdir().unwrap();
        let journal = RuntimeJournal::open(root.path()).unwrap();
        for event in [
            RuntimeEvent::ProcessStarted,
            RuntimeEvent::ProcessStopped,
            RuntimeEvent::WorkerStartupFailed,
            RuntimeEvent::WorkerPanicked,
            RuntimeEvent::ApiListenerStarted,
            RuntimeEvent::ApiListenerFailed,
        ] {
            journal.record_event(event).unwrap();
        }
        let text = fs::read_to_string(root.path().join("logs").join(CURRENT_FILE)).unwrap();
        for (code, level) in [
            ("process_started", "info"),
            ("process_stopped", "info"),
            ("worker_startup_failed", "error"),
            ("worker_panicked", "error"),
            ("api_listener_started", "info"),
            ("api_listener_failed", "error"),
        ] {
            let line = text
                .lines()
                .find(|line| line.contains(&format!("\"event\":\"{code}\"")))
                .unwrap_or_else(|| panic!("journal is missing event {code}"));
            assert!(
                line.contains(&format!("\"level\":\"{level}\"")),
                "event {code} was logged at the wrong level: {line}"
            );
        }
    }

    /// Why: circuit-breaker signals feed operator alerting; opened circuits must
    /// log as warnings while closes log as info, and the code strings must not
    /// drift. A wrong level would drop breaker flaps from warning dashboards.
    /// Inputs: one record per `RuntimeSignal` variant. Output: each signal code
    /// appears with warning (opened) or info (closed) level.
    #[test]
    fn runtime_signals_are_journalled_with_warning_levels() {
        let root = tempfile::tempdir().unwrap();
        let journal = RuntimeJournal::open(root.path()).unwrap();
        for signal in [
            RuntimeSignal::GmailCircuitOpened,
            RuntimeSignal::GmailCircuitClosed,
            RuntimeSignal::LocalAiCircuitOpened,
            RuntimeSignal::LocalAiCircuitClosed,
        ] {
            journal.record_signal(signal).unwrap();
        }
        let text = fs::read_to_string(root.path().join("logs").join(CURRENT_FILE)).unwrap();
        for (code, level) in [
            ("gmail_circuit_opened", "warning"),
            ("gmail_circuit_closed", "info"),
            ("local_ai_circuit_opened", "warning"),
            ("local_ai_circuit_closed", "info"),
        ] {
            let line = text
                .lines()
                .find(|line| line.contains(&format!("\"event\":\"{code}\"")))
                .unwrap_or_else(|| panic!("journal is missing signal {code}"));
            assert!(
                line.contains(&format!("\"level\":\"{level}\"")),
                "signal {code} was logged at the wrong level: {line}"
            );
        }
    }

    /// Why: the performance summary must tolerate a damaged journal (partial
    /// writes, hostile bytes) without losing counts from intact records; a
    /// single bad line aborting or corrupting the summary would mask real
    /// failure rates. Also proves non-operation events are not counted as
    /// operations and that the counter split (succeeded/failed/idle) is exact.
    /// Inputs: journal with one skipped event, three operation records and two
    /// damaged lines (unparseable, oversized). Output: parse_errors == 2 and
    /// exact per-state counts from the intact records only.
    #[test]
    fn performance_summary_tolerates_corrupt_oversized_and_non_operation_lines() {
        let root = tempfile::tempdir().unwrap();
        let journal = RuntimeJournal::open(root.path()).unwrap();
        journal.record_event(RuntimeEvent::ProcessStarted).unwrap();
        journal
            .record_operation(OperationKind::SendReply, OperationState::Failed)
            .unwrap();
        journal
            .record_operation(OperationKind::SyncMailbox, OperationState::Running)
            .unwrap();
        journal
            .record_operation(OperationKind::Backup, OperationState::Succeeded)
            .unwrap();
        let current = root.path().join("logs").join(CURRENT_FILE);
        let mut file = fs::OpenOptions::new().append(true).open(&current).unwrap();
        file.write_all(b"not json at all\n").unwrap();
        file.write_all(&vec![b'x'; 17 * 1024]).unwrap();
        file.write_all(b"\n").unwrap();
        file.sync_all().unwrap();
        drop(file);

        let summary = performance_summary(root.path()).unwrap();
        assert_eq!(summary.parse_errors, 2);
        assert_eq!(summary.retained_operation_records, 3);
        assert_eq!(summary.succeeded_operations, 1);
        assert_eq!(summary.failed_operations, 1);
        assert_eq!(summary.timed_operations, 0);
        assert_eq!(summary.mean_duration_ms, None);
        assert_eq!(summary.max_duration_ms, None);
    }

    /// Builds a journal record with a fixed timestamp so its serialized line has
    /// a deterministic byte length.
    /// Inputs: `code` tag stored in the record (must be the same length across
    /// records that must share a line length). Output: the record value.
    fn fixed_record(code: &str) -> RuntimeRecord {
        RuntimeRecord {
            schema_version: LOG_SCHEMA_VERSION,
            at: "2024-01-01T00:00:00Z".parse().unwrap(),
            level: "info",
            event: "process_started",
            operation: None,
            operation_id: None,
            state: None,
            code: Some(code.to_owned()),
            retryable: false,
            duration_ms: None,
        }
    }

    /// Serialized on-disk line (record plus newline) for [`fixed_record`].
    /// Inputs: `code` tag. Output: the exact bytes the journal writes.
    fn fixed_line(code: &str) -> Vec<u8> {
        let mut line = serde_json::to_vec(&fixed_record(code)).unwrap();
        line.push(b'\n');
        line
    }

    /// Why: the rotation trigger is an exact byte comparison; rotating at
    /// `>=` or at `max+1` would either split a fitting record or let the
    /// current file exceed its documented limit. Equality must not rotate, one
    /// byte over must rotate immediately.
    /// Inputs: journal limited to exactly two record lines. Output: two lines
    /// fit without rotation; the third write rotates the first two into the
    /// archive and starts the current file with only the third line.
    #[test]
    fn rotation_respects_the_exact_byte_limit_boundary() {
        let root = tempfile::tempdir().unwrap();
        let line = fixed_line("a").len() as u64;
        let max = 2 * line;
        assert!(max >= 256);
        let journal = RuntimeJournal::open_with_limits(root.path(), max, 3).unwrap();
        let logs = root.path().join("logs");

        journal.write(fixed_record("a")).unwrap();
        journal.write(fixed_record("a")).unwrap();
        assert!(
            !logs.join("runtime.1.jsonl").exists(),
            "rotation fired even though the records fit the limit exactly"
        );
        assert_eq!(fs::metadata(logs.join(CURRENT_FILE)).unwrap().len(), max);

        journal.write(fixed_record("a")).unwrap();
        assert_eq!(
            fs::read(logs.join("runtime.1.jsonl")).unwrap(),
            [fixed_line("a"), fixed_line("a")].concat(),
            "the rotated archive must hold exactly the two pre-rotation lines in order"
        );
        assert_eq!(fs::read(logs.join(CURRENT_FILE)).unwrap(), fixed_line("a"));
    }

    /// Why: the boundary is `current + next > max`, so a limit of `max-1` must
    /// rotate one byte early; getting the comparison wrong in the other
    /// direction silently allows over-limit files.
    /// Inputs: journal limited to one byte under two record lines. Output: the
    /// second write rotates immediately, leaving one line in each file.
    #[test]
    fn rotation_triggers_when_the_next_record_exceeds_the_limit_by_one_byte() {
        let root = tempfile::tempdir().unwrap();
        let line = fixed_line("a").len() as u64;
        let max = 2 * line - 1;
        let journal = RuntimeJournal::open_with_limits(root.path(), max, 3).unwrap();
        let logs = root.path().join("logs");

        journal.write(fixed_record("a")).unwrap();
        journal.write(fixed_record("a")).unwrap();
        assert_eq!(
            fs::read(logs.join("runtime.1.jsonl")).unwrap(),
            fixed_line("a")
        );
        assert_eq!(fs::read(logs.join(CURRENT_FILE)).unwrap(), fixed_line("a"));
    }

    /// Why: retention must drop exactly the oldest generations and never reorder
    /// the surviving records; losing newest-first order or leaking extra
    /// archives would corrupt incident timelines and the size accounting.
    /// Inputs: journal capped at two archives sized so every write rotates;
    /// six distinguishable records. Output: the three newest survive in write
    /// order (archives then current), older generations are gone, and the
    /// status byte accounting matches the retained files exactly.
    #[test]
    fn rotation_preserves_ordering_and_drops_only_the_oldest_archives() {
        let root = tempfile::tempdir().unwrap();
        let line = fixed_line("a").len() as u64;
        // The limit floor is 256 bytes; any limit below two record lines makes
        // every write rotate, which is exactly the stress case here.
        let max = std::cmp::max(256, line + 1);
        assert!(2 * line > max);
        let journal = RuntimeJournal::open_with_limits(root.path(), max, 2).unwrap();
        let logs = root.path().join("logs");
        for code in ["a", "b", "c", "d", "e", "f"] {
            journal.write(fixed_record(code)).unwrap();
        }

        assert!(!logs.join("runtime.3.jsonl").exists());
        assert_eq!(
            fs::read(logs.join("runtime.2.jsonl")).unwrap(),
            fixed_line("d")
        );
        assert_eq!(
            fs::read(logs.join("runtime.1.jsonl")).unwrap(),
            fixed_line("e")
        );
        assert_eq!(fs::read(logs.join(CURRENT_FILE)).unwrap(), fixed_line("f"));

        let status = journal.status().unwrap();
        assert_eq!(status.archive_count, 2);
        assert_eq!(status.current_bytes, line);
        assert_eq!(status.archive_bytes, 2 * line);
        assert_eq!(status.total_bytes, 3 * line);
        assert_eq!(status.max_current_bytes, max);
        assert_eq!(status.max_archives, 2);
    }

    /// Why: the journal limit bounds protect against both unusable tiny logs and
    /// unbounded archive sets; each rejected boundary must fail at open time
    /// instead of surfacing later as data loss during rotation.
    /// Inputs: limit values on both sides of the accepted ranges. Output: sizes
    /// below 256 bytes and archive counts outside 1..=16 are refused, boundary
    /// values are accepted.
    #[test]
    fn journal_limits_are_validated_at_open() {
        let root = tempfile::tempdir().unwrap();
        assert!(RuntimeJournal::open_with_limits(root.path(), 255, 3).is_err());
        assert!(RuntimeJournal::open_with_limits(root.path(), 256, 3).is_ok());
        assert!(RuntimeJournal::open_with_limits(root.path(), 256, 0).is_err());
        assert!(RuntimeJournal::open_with_limits(root.path(), 256, 17).is_err());
        assert!(RuntimeJournal::open_with_limits(root.path(), 256, 16).is_ok());
    }
}

#[cfg(test)]
mod rotation_and_status_tests {
    use super::*;

    /// Why: archive accounting must count every retained archive and rotation
    /// must shift history even when the live journal is absent (e.g. right
    /// after a crash), otherwise a stale archive could be double-counted or
    /// silently overwritten.
    #[test]
    fn status_counts_archives_and_rotation_shifts_history_without_a_current_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("runtime.1.jsonl"), b"aaa").unwrap();
        std::fs::write(dir.path().join("runtime.2.jsonl"), b"bbbb").unwrap();

        let status = status_for(dir.path(), 1024, 3).unwrap();
        assert_eq!(status.archive_count, 2);
        assert_eq!(status.archive_bytes, 7);
        assert_eq!(status.total_bytes, 7);
        assert!(!status.available, "no live journal exists");

        rotate(dir.path(), 3).unwrap();
        assert!(!dir.path().join("runtime.1.jsonl").exists());
        assert_eq!(
            std::fs::read(dir.path().join("runtime.2.jsonl")).unwrap(),
            b"aaa"
        );
        assert_eq!(
            std::fs::read(dir.path().join("runtime.3.jsonl")).unwrap(),
            b"bbbb"
        );

        std::fs::write(dir.path().join(CURRENT_FILE), b"ccccc").unwrap();
        rotate(dir.path(), 3).unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("runtime.1.jsonl")).unwrap(),
            b"ccccc"
        );
        assert!(
            !dir.path().join("runtime.2.jsonl").exists(),
            "the oldest archive must be dropped to honor max_archives"
        );
        assert_eq!(
            std::fs::read(dir.path().join("runtime.3.jsonl")).unwrap(),
            b"aaa"
        );
    }
}
