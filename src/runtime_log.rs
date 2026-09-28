use crate::{
    types::{OperationKind, OperationState},
    vault::private_dir,
};
use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

pub const DEFAULT_MAX_CURRENT_BYTES: u64 = 2 * 1024 * 1024;
pub const DEFAULT_MAX_ARCHIVES: usize = 3;
const LOG_SCHEMA_VERSION: u32 = 1;
const CURRENT_FILE: &str = "runtime.jsonl";

#[derive(Clone, Copy, Debug)]
pub enum RuntimeEvent {
    ProcessStarted,
    ProcessStopped,
    WorkerStartupFailed,
    WorkerPanicked,
    ApiListenerStarted,
    ApiListenerFailed,
}

impl RuntimeEvent {
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

    fn level(self) -> &'static str {
        match self {
            Self::WorkerStartupFailed | Self::WorkerPanicked | Self::ApiListenerFailed => "error",
            _ => "info",
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct RuntimeLogStatus {
    pub schema_version: u32,
    pub available: bool,
    pub current_bytes: u64,
    pub archive_bytes: u64,
    pub total_bytes: u64,
    pub archive_count: usize,
    pub max_current_bytes: u64,
    pub max_archives: usize,
}

#[derive(Serialize)]
struct RuntimeRecord {
    schema_version: u32,
    at: DateTime<Utc>,
    level: &'static str,
    event: &'static str,
    operation: Option<OperationKind>,
    state: Option<OperationState>,
    code: Option<&'static str>,
    retryable: bool,
}

struct Inner {
    directory: PathBuf,
    max_bytes: u64,
    max_archives: usize,
}

#[derive(Clone)]
pub struct RuntimeJournal {
    inner: Arc<Mutex<Inner>>,
}

impl RuntimeJournal {
    pub fn open(data_dir: &Path) -> Result<Self> {
        Self::open_with_limits(data_dir, DEFAULT_MAX_CURRENT_BYTES, DEFAULT_MAX_ARCHIVES)
    }

    fn open_with_limits(data_dir: &Path, max_bytes: u64, max_archives: usize) -> Result<Self> {
        ensure!(max_bytes >= 256, "Runtime log size limit is too small");
        ensure!((1..=16).contains(&max_archives), "Runtime log archive limit is invalid");
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

    pub fn record_event(&self, event: RuntimeEvent) -> Result<()> {
        self.write(RuntimeRecord {
            schema_version: LOG_SCHEMA_VERSION,
            at: Utc::now(),
            level: event.level(),
            event: event.code(),
            operation: None,
            state: None,
            code: None,
            retryable: false,
        })
    }

    pub fn record_operation(&self, kind: OperationKind, state: OperationState) -> Result<()> {
        let failed = state == OperationState::Failed;
        self.write(RuntimeRecord {
            schema_version: LOG_SCHEMA_VERSION,
            at: Utc::now(),
            level: if failed { "error" } else { "info" },
            event: "operation",
            operation: Some(kind),
            state: Some(state),
            code: failed.then(|| kind.failure_code()),
            retryable: failed && kind.retryable(),
        })
    }

    fn write(&self, record: RuntimeRecord) -> Result<()> {
        let mut line = serde_json::to_vec(&record)?;
        line.push(b'\n');
        let inner = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("Runtime log lock is poisoned"))?;
        let current = inner.directory.join(CURRENT_FILE);
        reject_symlink_if_present(&current)?;
        let current_bytes = fs::metadata(&current).map(|m| m.len()).unwrap_or(0);
        if current_bytes > 0 && current_bytes.saturating_add(line.len() as u64) > inner.max_bytes {
            rotate(&inner.directory, inner.max_archives)?;
        }
        append_private(&current, &line)?;
        Ok(())
    }

    pub fn status(&self) -> Result<RuntimeLogStatus> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("Runtime log lock is poisoned"))?;
        status_for(&inner.directory, inner.max_bytes, inner.max_archives)
    }
}

pub fn status(data_dir: &Path) -> Result<RuntimeLogStatus> {
    status_for(
        &data_dir.join("logs"),
        DEFAULT_MAX_CURRENT_BYTES,
        DEFAULT_MAX_ARCHIVES,
    )
}

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
    let current_bytes = fs::metadata(&current).map(|m| m.len()).unwrap_or(0);
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

fn archive_path(directory: &Path, index: usize) -> PathBuf {
    directory.join(format!("runtime.{index}.jsonl"))
}

fn reject_symlink_if_present(path: &Path) -> Result<()> {
    if path.exists() {
        ensure!(
            !fs::symlink_metadata(path)?.file_type().is_symlink(),
            "Runtime log files must not be symlinks"
        );
    }
    Ok(())
}

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
        assert_eq!(status.total_bytes, status.current_bytes + status.archive_bytes);
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
}
