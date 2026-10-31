//! Shared local-console startup: first-run credential pre-flight plus the
//! worker-backed loopback API server behind `rr web`, `rr run` and the
//! `rr-tray` system-tray shell.
//!
//! Every console shell brings up the identical engine/worker/API state
//! through `start_api_worker` and `console_base_url`, so no shell
//! duplicates the bring-up and none can drift from `rr web`. Nothing in this
//! module renders UI or touches tray code; the server state is testable on
//! its own.

use crate::{
    api_auth,
    engine::Engine,
    worker::{self, Worker},
};
use anyhow::{Result, bail};
use std::{
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

/// Open the workspace engine for one command-line action.
///
/// Inputs: `dir` — workspace directory; `demo` — seed synthetic data;
/// `paused` — start paused (command surfaces never dispatch). Output: the
/// opened engine; workspace or vault failures propagate.
pub fn open_engine(dir: PathBuf, demo: bool, paused: bool) -> Result<Engine> {
    Engine::open(
        dir,
        demo,
        Arc::new(AtomicBool::new(paused)),
        Arc::new(AtomicBool::new(false)),
    )
}

/// Display any first-run API credentials exactly once before a worker starts.
///
/// The worker's local listener mints verifier material on first load; the
/// minted plaintexts must reach the operator exactly once without passing
/// through logs, API responses, or UI state. Opening the workspace briefly
/// first guarantees the mint happens here, where the plaintexts print like
/// `rr rotate-api-token`, and the worker later loads nothing to display.
///
/// Inputs: `dir` — workspace directory. Output: `Result<()>` — prints
/// `read:`/`write:` lines when this call minted credentials.
pub fn display_first_run_credentials(dir: PathBuf) -> Result<()> {
    let mut e = open_engine(dir, false, true)?;
    let tokens = api_auth::load_or_create(&mut e.db)?;
    let read_once = tokens.plaintext_read_once;
    let write_once = tokens.plaintext_write_once;
    let minted = read_once.is_some() || write_once.is_some();
    if let Some(token) = read_once {
        println!("read: {}", token.as_str());
    }
    if let Some(token) = write_once {
        println!("write: {}", token.as_str());
    }
    if minted {
        eprintln!(
            "First-run API credentials were minted and printed once. The read credential is for machine integrations (query-only); the write credential is for the web console. Store both in the consuming application's OS-protected secret store. They cannot be revealed again; rotate if lost."
        );
    }
    Ok(())
}

/// Wait until the background worker reports its startup state.
///
/// Inputs: `worker` — spawned worker; `deadline` — startup deadline.
/// Output: the initialized `Snapshot`; `Err` when the workspace failed to
/// open or initialization exceeded the deadline.
pub fn wait_for_ready(worker: &Worker, deadline: std::time::Instant) -> Result<worker::Snapshot> {
    loop {
        let snapshot = worker.view();
        if snapshot.fatal {
            bail!("{}", snapshot.error);
        }
        if snapshot.initialized {
            return Ok(snapshot);
        }
        if std::time::Instant::now() >= deadline {
            bail!("The workspace did not initialize before the startup deadline");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Bring up the worker-backed local API server shared by the console shells.
///
/// Inputs: `dir` — workspace directory. Output: `Result<Worker>` — the
/// started worker once the first-run credential pre-flight has printed any
/// newly minted credentials exactly as `rr web` does; workspace failures
/// propagate.
pub fn start_api_worker(dir: PathBuf) -> Result<Worker> {
    display_first_run_credentials(dir.clone())?;
    Ok(Worker::spawn(dir, false))
}

/// Resolve the local web-console base URL from the running worker state.
///
/// Inputs: `worker` — started worker. Output: `Result<String>` — the
/// `http://127.0.0.1:<port>/` base URL once the worker is up and its
/// loopback API is listening; `Err` when the workspace fails to start or the
/// integration API is disabled (the console is served by that API).
pub fn console_base_url(worker: &Worker) -> Result<String> {
    wait_for_ready(worker, std::time::Instant::now() + Duration::from_secs(30))?;
    let snapshot = worker.view();
    if !snapshot.api_listening {
        bail!(
            "The local web console is served by the local integration API. Enable the API in Settings, save, and restart (enterprise policy may also prohibit the API)."
        );
    }
    Ok(format!("http://127.0.0.1:{}/", snapshot.settings.api_port))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bind an ephemeral loopback port and release it for reuse.
    ///
    /// Why: the smoke test needs a port that is free at configuration time;
    /// binding port zero asks the OS for one nobody else holds.
    fn free_loopback_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind an ephemeral loopback port")
            .local_addr()
            .expect("read the bound port")
            .port()
    }

    /// The shared console URL resolves only from an initialized worker whose
    /// loopback API is listening.
    ///
    /// Why: `rr web`, `rr run` and `rr-tray` share this gate — a console
    /// shell must never print a dead URL when the API is disabled or demo
    /// mode suppresses the listener, and the operator must get the same
    /// enable-the-API guidance from every shell.
    #[test]
    fn console_base_url_refuses_without_the_loopback_api() {
        let dir = tempfile::tempdir().unwrap();
        let worker = Worker::spawn(dir.path().to_path_buf(), true);
        assert!(
            worker.wait_for(|s| s.initialized, |s| s.fatal, Duration::from_secs(60)),
            "demo worker initializes"
        );
        let error = console_base_url(&worker).expect_err("no listening API means no console URL");
        assert!(
            error.to_string().contains("Enable the API in Settings"),
            "the operator gets the enable-the-API guidance"
        );
    }

    /// The startup deadline is enforced even when the worker never comes up.
    ///
    /// Why: a wedged startup must fail with the deadline error instead of
    /// waiting forever behind a load screen.
    #[test]
    fn wait_for_ready_enforces_the_startup_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let worker = Worker::spawn(dir.path().to_path_buf(), true);
        assert!(
            worker.wait_for(|s| s.initialized, |s| s.fatal, Duration::from_secs(60)),
            "demo worker initializes"
        );
        // Park the worker in "still starting" so the poll loop has to wait.
        worker.snapshot.lock().unwrap().initialized = false;
        let error = wait_for_ready(
            &worker,
            std::time::Instant::now() + std::time::Duration::from_millis(150),
        )
        .err()
        .expect("an expired deadline refuses to wait");
        assert!(error.to_string().contains("did not initialize"));
    }

    /// The shared startup builds the full worker + API server state without
    /// any tray code involved.
    ///
    /// Why: `rr web` and `rr-tray` must get identical server state from one
    /// bring-up function; this smoke runs that function against a real
    /// workspace (the supported target: an OS credential store is required
    /// to open one) and asserts the worker initializes, the loopback API
    /// listens on the configured port, the console URL matches that port,
    /// and the CLI bearer-token pre-flight minted the API verifiers.
    /// Inputs: none (temporary workspace fixture). Output: none.
    #[cfg(windows)]
    #[test]
    fn shared_startup_builds_the_server_state_without_the_tray() {
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("workspace");
        let port = free_loopback_port();
        {
            let mut e = open_engine(dir.clone(), false, true).expect("open the workspace");
            let mut settings = e.settings.clone();
            settings.api_enabled = true;
            settings.api_port = port;
            e.update_settings(settings)
                .expect("enable the loopback API");
        }
        let mut worker = start_api_worker(dir.clone()).expect("shared startup succeeds");
        assert!(
            worker.wait_for(|s| s.initialized, |s| s.fatal, Duration::from_secs(60)),
            "the worker initializes"
        );
        assert!(worker.view().api_listening, "the loopback API is listening");
        assert_eq!(
            console_base_url(&worker).expect("the console URL resolves"),
            format!("http://127.0.0.1:{port}/"),
            "the console URL is the configured loopback port"
        );
        assert!(
            worker.shutdown(Duration::from_secs(30)),
            "the worker drains cleanly"
        );
        let e = open_engine(dir.clone(), false, true).expect("reopen the workspace");
        assert!(
            e.db.meta::<String>(api_auth::TOKEN_WRITE_HASH_META)
                .expect("read the verifier metadata")
                .is_some(),
            "the bearer-token pre-flight minted the write-scope verifier"
        );
        drop(e);
        delete_vault_credential(&dir);
    }

    /// Delete the workspace's OS vault credential now.
    ///
    /// Why: every opened workspace mints one credential-store entry; test
    /// workspaces must not accumulate them (the Windows store has a quota).
    /// Inputs: `dir` — workspace directory. Output: none (best effort).
    #[cfg(windows)]
    fn delete_vault_credential(dir: &std::path::Path) {
        if let Ok(id) = std::fs::read_to_string(dir.join("vault-id"))
            && let Ok(entry) = keyring::Entry::new("rejection-rejector.v1", id.trim())
        {
            let _ = entry.delete_credential();
        }
    }
}
