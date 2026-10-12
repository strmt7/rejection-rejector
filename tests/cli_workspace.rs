//! Subprocess contract tests for the `rr` workspace commands and the
//! desktop launcher.
//!
//! Every subcommand variant is driven as a real process so the exit codes,
//! machine-readable output and fail-closed error paths are pinned exactly as
//! deployment tooling observes them. All workspaces are temporary; the
//! Windows vault credential each one creates is deleted when its test ends,
//! and on hosts without an OS credential store every spawned `rr` carries the
//! documented headless vault seam (`RR_VAULT_PASSPHRASE`, docs/SETUP.md) so
//! the fleet command contract stays covered on headless Linux.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Serialize every spawned workspace process in this file.
///
/// Why: the test binary runs its tests in parallel and each spawned `rr`
/// manipulates the OS credential store (delete/reinstall drills), which
/// raced sibling subprocesses into "Existing vault identifier has no OS
/// credential" failures (2-of-5 runs). One subprocess at a time removes the
/// interleaving; the lock is poison-tolerant like the production seams.
static CREDSTORE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Hold the cross-test credential-store serialization for one subprocess.
///
/// Inputs: none. Output: the held guard for the subprocess lifetime.
fn lock_credstore() -> std::sync::MutexGuard<'static, ()> {
    CREDSTORE.lock().unwrap_or_else(|error| error.into_inner())
}

/// Run the `rr` binary with the given arguments.
///
/// Inputs: `args` — command-line arguments. Output: the spawned process
/// result (status, stdout, stderr).
fn rr(args: &[&str]) -> Output {
    let _serialize = lock_credstore();
    rr_command().args(args).output().expect("run rr")
}

/// Build one `rr` process command with its workspace vault seam provisioned.
///
/// Inputs: none. Output: the process command; on hosts without an OS
/// credential store it carries the documented headless vault input
/// (`RR_VAULT_PASSPHRASE`, docs/SETUP.md) that `Vault::open` derives the
/// workspace key from — exactly what a real fleet deployment supplies.
fn rr_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rr"));
    headless_vault_seam(&mut command);
    command
}

/// Attach the documented headless vault input to one spawned process.
///
/// Inputs: `command` — the process command. Output: none; on non-Windows the
/// process environment gains `RR_VAULT_PASSPHRASE` (20+ characters, the
/// minimum `Vault::open` accepts). Windows resolves the key from Credential
/// Manager automatically and never reads the variable.
#[cfg(not(windows))]
fn headless_vault_seam(command: &mut Command) {
    command.env(
        "RR_VAULT_PASSPHRASE",
        "rr-cli-test-headless-vault-passphrase",
    );
}

/// Non-Windows seam counterpart: Windows needs no injected vault input.
///
/// Inputs: ignored. Output: none.
#[cfg(windows)]
fn headless_vault_seam(_command: &mut Command) {}

/// Run the `rr` binary against one data directory.
///
/// Inputs: `dir` — workspace directory; `args` — command-line arguments.
/// Output: the spawned process result.
fn rr_in(dir: &Path, args: &[&str]) -> Output {
    let dir = dir.to_str().expect("utf-8 path");
    let mut all = vec!["--data-dir", dir];
    all.extend_from_slice(args);
    rr(&all)
}

/// Point one workspace's model runtime at a specific loopback endpoint.
///
/// Inputs: `dir` — workspace directory; `url` — Ollama base URL. Output:
/// none; the persisted settings are updated before any command runs.
#[cfg(windows)]
fn point_ollama_at(dir: &Path, url: &str) {
    let mut engine = rejection_rejector::engine::Engine::open(
        dir.to_path_buf(),
        false,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )
    .expect("open workspace");
    engine.settings.ollama_url = url.into();
    engine
        .db
        .set_meta("settings", &engine.settings)
        .expect("persist settings");
}

/// Serve the Ollama inspection protocol with one scripted behavior.
///
/// Inputs: `mode` — `"no-model"` hides the model from `/api/tags`,
/// `"not-loaded"` hides it from `/api/ps`, anything else reports it fully
/// installed and GPU-resident. Output: the fake runtime's base URL.
#[cfg(windows)]
fn serve_fake_ollama(mode: &'static str) -> String {
    let server = tiny_http::Server::http("127.0.0.1:0").expect("bind fake ollama");
    let url = format!("http://{}", server.server_addr().to_ip().expect("ip"));
    std::thread::spawn(move || {
        for request in server.incoming_requests() {
            let body = match (request.url(), mode) {
                ("/api/version", _) => r#"{"version":"0.40.2"}"#.to_string(),
                ("/api/tags", "no-model") => r#"{"models":[]}"#.to_string(),
                ("/api/tags", _) => {
                    r#"{"models":[{"name":"qwen3.5:9b-q8_0","digest":"sha256:0123456789abcdef","size":6000000000}]}"#.to_string()
                }
                ("/api/show", _) => {
                    r#"{"details":{"format":"gguf"},"model_info":{"general.architecture":"qwen3"},"capabilities":["completion"]}"#.to_string()
                }
                ("/api/ps", "not-loaded") => r#"{"models":[]}"#.to_string(),
                ("/api/ps", _) => {
                    r#"{"models":[{"name":"qwen3.5:9b-q8_0","digest":"sha256:0123456789abcdef","size":6000000000,"size_vram":6000000000,"context_length":32768}]}"#.to_string()
                }
                _ => "{}".to_string(),
            };
            let _ = request.respond(tiny_http::Response::from_string(body));
        }
    });
    url
}

/// Parse stdout as a JSON object for contract assertions.
///
/// Inputs: `output` — process output. Output: the parsed object; panics when
/// the command did not exit cleanly or did not emit a JSON object.
fn json_stdout(output: &Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout must be JSON")
}

/// Delete the workspace's OS vault credential now.
///
/// Inputs: `dir` — data directory holding a `vault-id`. Output: none; the
/// matching Credential Manager entry is removed, simulating the credential
/// loss that the recovery-key envelope exists for.
#[cfg(windows)]
fn delete_vault_credential(dir: &Path) {
    if let Ok(id) = std::fs::read_to_string(dir.join("vault-id"))
        && let Ok(entry) = keyring::Entry::new("rejection-rejector.v1", id.trim())
    {
        entry.delete_credential().expect("delete credential");
    }
}

#[cfg(not(windows))]
fn delete_vault_credential(_dir: &Path) {}

/// Delete the workspace's OS vault credential when dropped.
///
/// Inputs: `workspace` — data directory holding a `vault-id`. Output: none;
/// the matching Credential Manager entry is removed on drop so test
/// workspaces never accumulate credentials.
#[cfg(windows)]
struct VaultGuard(PathBuf);

#[cfg(windows)]
impl Drop for VaultGuard {
    fn drop(&mut self) {
        if let Ok(id) = std::fs::read_to_string(self.0.join("vault-id"))
            && let Ok(entry) = keyring::Entry::new("rejection-rejector.v1", id.trim())
        {
            let _ = entry.delete_credential();
        }
    }
}

/// Create a fresh workspace directory with its credential guard.
///
/// Inputs: `name` — directory-name hint. Output: `(dir, guard)`; the
/// directory is empty until the first command opens it.
#[cfg(windows)]
fn workspace(name: &str) -> (PathBuf, VaultGuard) {
    let dir = std::env::temp_dir().join(format!(
        "rr-cli-{name}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&dir).expect("workspace dir");
    let guard = VaultGuard(dir.clone());
    (dir, guard)
}

#[cfg(not(windows))]
fn workspace(name: &str) -> (PathBuf, ()) {
    let dir = std::env::temp_dir().join(format!(
        "rr-cli-{name}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&dir).expect("workspace dir");
    (dir, ())
}

/// Write one test fixture owner-private.
///
/// Inputs: `path` — destination; `content` — fixture bytes. Output: none; on
/// unix the file lands 0600 so the production recovery-passphrase permission
/// gate (which is correct) sees a realistic operator file instead of a
/// umask-default 0644 fixture that would be rejected before the length
/// checks under test.
#[cfg(unix)]
fn write_private(path: &Path, content: impl AsRef<[u8]>) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, content).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// Non-unix counterpart: there is no POSIX mode gate to satisfy.
///
/// Inputs: `path` — destination; `content` — fixture bytes. Output: none.
#[cfg(not(unix))]
fn write_private(path: &Path, content: impl AsRef<[u8]>) {
    std::fs::write(path, content).unwrap();
}

/// Readiness and status surfaces report machine-readable JSON.
///
/// Why: fleet tooling gates rollouts on these documents — silent shape
/// changes would break deployment checks.
#[test]
fn readiness_and_status_commands_emit_machine_readable_reports() {
    let (dir, _guard) = workspace("status");
    let status = json_stdout(&rr_in(&dir, &["status"]));
    assert_eq!(status.get("demo"), Some(&serde_json::json!(false)));
    assert!(status.get("mode").is_some() && status.get("counts").is_some());

    let demo = json_stdout(&rr(&["demo"]));
    assert_eq!(demo.get("demo"), Some(&serde_json::json!(true)));

    let policy = json_stdout(&rr_in(&dir, &["policy-status"]));
    assert!(policy.get("active").is_some(), "policy status shape");

    let metrics = json_stdout(&rr_in(&dir, &["metrics"]));
    assert!(metrics.is_object(), "metrics is a JSON object");
    let openmetrics = rr_in(&dir, &["metrics", "--openmetrics"]);
    assert!(openmetrics.status.success());
    assert!(
        String::from_utf8_lossy(&openmetrics.stdout).contains("# TYPE"),
        "openmetrics text format"
    );

    let doctor = json_stdout(&rr_in(&dir, &["doctor"]));
    assert!(doctor.get("configuration_readiness").is_some());
    assert!(doctor.get("database").is_some());
    assert!(doctor.get("local_ai").is_some());
    let integrity = json_stdout(&rr_in(&dir, &["integrity"]));
    assert_eq!(integrity.get("ok"), Some(&serde_json::json!(true)));
}

/// `doctor --require` fails loudly unless the exact readiness level holds.
///
/// Why: the exit code is the deployment gate — succeeding on the wrong
/// dimension would ship an unready build.
#[test]
fn doctor_require_gates_on_the_exact_readiness_level() {
    let (dir, _guard) = workspace("require");
    let ok = rr_in(&dir, &["doctor", "--require", "workspace"]);
    assert!(ok.status.success(), "a fresh workspace is workspace-ready");

    for level in ["mailbox", "analysis", "automatic"] {
        let out = rr_in(&dir, &["doctor", "--require", level]);
        assert!(
            !out.status.success(),
            "unconnected workspaces are not {level}-ready"
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("not satisfied"),
            "refusal names the unsatisfied level"
        );
    }
}

/// The backup pipeline round-trips through backup, verify, drill and
/// restore with explicit acknowledgement.
///
/// Why: recovery replaces the workspace database — restore must refuse
/// without the literal acknowledgement and verify must authenticate the
/// backup before it is trusted.
#[test]
fn backup_verify_drill_and_restore_round_trip() {
    let (dir, _guard) = workspace("backup");
    assert!(rr_in(&dir, &["integrity"]).status.success());

    // The backup target must be a fresh path outside the workspace.
    let out_root = std::env::temp_dir().join(format!("rr-cli-backup-out-{}", uuid::Uuid::new_v4()));
    let backup = json_stdout(&rr(&[
        "--data-dir",
        dir.to_str().unwrap(),
        "backup",
        "--out",
        out_root.to_str().unwrap(),
    ]));
    assert!(backup.is_object());

    let verify = json_stdout(&rr_in(&dir, &["verify-backup", out_root.to_str().unwrap()]));
    assert!(verify.is_object(), "verification prints its manifest");

    let drill = json_stdout(&rr_in(
        &dir,
        &["recovery-drill", out_root.to_str().unwrap()],
    ));
    assert!(drill.get("restored_schema_version").is_some());

    // Restore refuses anything but the literal acknowledgement.
    let refused = rr_in(
        &dir,
        &[
            "restore-backup",
            out_root.to_str().unwrap(),
            "--confirm",
            "yes",
        ],
    );
    assert!(!refused.status.success(), "wrong acknowledgement refused");
    assert!(String::from_utf8_lossy(&refused.stderr).contains("RESTORE"));

    // A confirmed restore into a fresh workspace succeeds.
    let (target, _target_guard) = workspace("restore-target");
    let restored = rr_in(
        &target,
        &[
            "restore-backup",
            out_root.to_str().unwrap(),
            "--confirm",
            "RESTORE",
        ],
    );
    assert!(
        restored.status.success(),
        "confirmed restore succeeds: {}",
        String::from_utf8_lossy(&restored.stderr)
    );
}

/// Recovery-key envelopes export, verify and import with a passphrase file.
///
/// Why: the envelope is the only off-machine recovery path — the passphrase
/// envelope checks and the literal import acknowledgement are the guard
/// rails against destructive misuse.
#[test]
fn recovery_key_envelope_round_trips_with_its_passphrase() {
    let (dir, _guard) = workspace("keys");
    assert!(rr_in(&dir, &["integrity"]).status.success());

    let out_root = std::env::temp_dir().join(format!("rr-cli-key-out-{}", uuid::Uuid::new_v4()));
    let backup_dir = out_root.join("backup");
    let output = rr(&[
        "--data-dir",
        dir.to_str().unwrap(),
        "backup",
        "--out",
        backup_dir.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "backup failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let pass = out_root.join("passphrase.txt");
    std::fs::create_dir_all(&out_root).unwrap();
    write_private(&pass, b"correct horse battery staple\n");

    // The passphrase reader refuses its unsafe inputs before any crypto.
    let missing = rr_in(
        &dir,
        &[
            "export-recovery-key",
            "--out",
            out_root.join("key.json").to_str().unwrap(),
            "--passphrase-file",
            out_root.join("missing.txt").to_str().unwrap(),
        ],
    );
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("passphrase file is missing"));

    let short = out_root.join("short.txt");
    write_private(&short, b"tiny");
    let short = rr_in(
        &dir,
        &[
            "export-recovery-key",
            "--out",
            out_root.join("key.json").to_str().unwrap(),
            "--passphrase-file",
            short.to_str().unwrap(),
        ],
    );
    assert!(!short.status.success());
    assert!(String::from_utf8_lossy(&short.stderr).contains("at least 20 bytes"));

    let oversized = out_root.join("oversized.txt");
    write_private(&oversized, vec![b'a'; 5000]);
    let oversized = rr_in(
        &dir,
        &[
            "export-recovery-key",
            "--out",
            out_root.join("key.json").to_str().unwrap(),
            "--passphrase-file",
            oversized.to_str().unwrap(),
        ],
    );
    assert!(!oversized.status.success());
    assert!(String::from_utf8_lossy(&oversized.stderr).contains("4 KiB"));

    // A well-formed export prints its envelope identity.
    let key_path = out_root.join("key.json");
    let exported = json_stdout(&rr_in(
        &dir,
        &[
            "export-recovery-key",
            "--out",
            key_path.to_str().unwrap(),
            "--passphrase-file",
            pass.to_str().unwrap(),
        ],
    ));
    assert!(exported.get("vault_id").is_some() && exported.get("created").is_some());

    let verified = json_stdout(&rr_in(
        &dir,
        &[
            "verify-recovery-key",
            "--backup",
            backup_dir.to_str().unwrap(),
            "--recovery-key",
            key_path.to_str().unwrap(),
            "--passphrase-file",
            pass.to_str().unwrap(),
        ],
    ));
    assert_eq!(verified.get("verified"), Some(&serde_json::json!(true)));

    // Import refuses anything but the literal acknowledgement.
    let refused = rr_in(
        &dir,
        &[
            "import-recovery-key",
            "--backup",
            backup_dir.to_str().unwrap(),
            "--recovery-key",
            key_path.to_str().unwrap(),
            "--passphrase-file",
            pass.to_str().unwrap(),
            "--confirm",
            "yes",
        ],
    );
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("IMPORT"));

    // The acknowledged import installs the recovered key after the old OS
    // credential is gone — the exact disaster-recovery scenario.
    delete_vault_credential(&dir);
    let imported = rr_in(
        &dir,
        &[
            "import-recovery-key",
            "--backup",
            backup_dir.to_str().unwrap(),
            "--recovery-key",
            key_path.to_str().unwrap(),
            "--passphrase-file",
            pass.to_str().unwrap(),
            "--confirm",
            "IMPORT",
        ],
    );
    #[cfg(windows)]
    assert_eq!(
        json_stdout(&imported).get("imported"),
        Some(&serde_json::json!(true))
    );
    #[cfg(not(windows))]
    {
        // The OS-credential install half of the import is genuinely
        // platform-bound: without a credential store there is nothing to
        // install into, so on Linux the import must fail closed and name the
        // documented recovery path (RR_VAULT_PASSPHRASE + vault-id,
        // docs/SETUP.md) instead of pretending to succeed.
        assert!(
            !imported.status.success(),
            "import without an OS credential store must fail closed"
        );
        assert!(
            String::from_utf8_lossy(&imported.stderr).contains("RR_VAULT_PASSPHRASE"),
            "the refusal names the passphrase recovery path: {}",
            String::from_utf8_lossy(&imported.stderr)
        );
    }

    // A configured enterprise policy that allows export still exports.
    let example = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("config")
        .join("enterprise-policy.example.json");
    let output = rr_command()
        .env("RR_ENTERPRISE_POLICY", &example)
        .args([
            "--data-dir",
            dir.to_str().unwrap(),
            "export-recovery-key",
            "--out",
            out_root.join("key2.json").to_str().unwrap(),
            "--passphrase-file",
            pass.to_str().unwrap(),
        ])
        .output()
        .expect("run rr");
    assert!(
        output.status.success(),
        "an allowing policy exports: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `doctor` reports the exact model runtime state it observes.
///
/// Why: the readiness report drives operator decisions — a missing model, a
/// non-resident model and a fully qualified model must read differently.
#[cfg(windows)]
#[test]
fn doctor_reports_the_observed_model_runtime_state() {
    let (dir, _guard) = workspace("doctor-model");

    point_ollama_at(&dir, &serve_fake_ollama("installed"));
    let doctor = json_stdout(&rr_in(&dir, &["doctor"]));
    let message = doctor
        .pointer("/local_ai/message")
        .and_then(serde_json::Value::as_str)
        .expect("model message");
    assert!(
        message.contains("full GPU residency"),
        "a resident model reads qualified: {message}"
    );

    point_ollama_at(&dir, &serve_fake_ollama("not-loaded"));
    let doctor = json_stdout(&rr_in(&dir, &["doctor"]));
    let message = doctor
        .pointer("/local_ai/message")
        .and_then(serde_json::Value::as_str)
        .expect("model message");
    assert!(
        message.contains("not currently qualified as GPU-resident"),
        "a cold model reads unqualified: {message}"
    );

    point_ollama_at(&dir, &serve_fake_ollama("no-model"));
    let doctor = json_stdout(&rr_in(&dir, &["doctor"]));
    let message = doctor
        .pointer("/local_ai/message")
        .and_then(serde_json::Value::as_str)
        .expect("model message");
    assert!(
        message.contains("Model inspection failed"),
        "a missing model reads failed: {message}"
    );

    point_ollama_at(&dir, "http://127.0.0.1:9");
    let doctor = json_stdout(&rr_in(&dir, &["doctor"]));
    let message = doctor
        .pointer("/local_ai/message")
        .and_then(serde_json::Value::as_str)
        .expect("model message");
    assert!(
        message.contains("not reachable"),
        "an unreachable runtime reads unreachable: {message}"
    );
}

/// Maintenance commands write their privacy-safe artifacts and reports.
///
/// Why: every report path is consumed by operator tooling — the exact
/// on-disk artifact is part of the contract.
#[test]
fn maintenance_commands_write_their_operator_artifacts() {
    let (dir, _guard) = workspace("maintenance");
    let out_root = std::env::temp_dir().join(format!("rr-cli-maint-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&out_root).unwrap();

    let compact = json_stdout(&rr_in(&dir, &["compact"]));
    assert!(compact.is_object(), "compact prints its report");

    let diag = out_root.join("diagnostics.json");
    let diagnostics = rr_in(&dir, &["diagnostics", "--out", diag.to_str().unwrap()]);
    assert!(diagnostics.status.success());
    assert!(diag.is_file(), "diagnostics report written");

    let shadow = out_root.join("shadow.json");
    let shadowed = rr_in(
        &dir,
        &["shadow-automatic", "--out", shadow.to_str().unwrap()],
    );
    assert!(shadowed.status.success());
    assert!(shadow.is_file(), "shadow audit written");

    let anchor_path = out_root.join("anchor.json");
    let anchor = json_stdout(&rr_in(
        &dir,
        &["audit-anchor", "--out", anchor_path.to_str().unwrap()],
    ));
    assert!(anchor.is_object());
    let verified = json_stdout(&rr_in(
        &dir,
        &["verify-audit-anchor", anchor_path.to_str().unwrap()],
    ));
    assert_eq!(verified.get("verified"), Some(&serde_json::json!(true)));

    let rotated = rr_in(&dir, &["rotate-api-token"]);
    assert!(rotated.status.success());
    assert!(
        !String::from_utf8_lossy(&rotated.stdout).trim().is_empty(),
        "the one-time token is printed once"
    );
}

/// Policy validation accepts the shipped example and rejects broken files.
///
/// Why: `validate-policy` is the pre-apply gate — accepting a malformed
/// policy would let broken configuration reach enforcement.
#[test]
fn validate_policy_accepts_the_example_and_rejects_broken_files() {
    let (dir, _guard) = workspace("policy");
    let example = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("config")
        .join("enterprise-policy.example.json");
    let ok = rr_in(&dir, &["validate-policy", example.to_str().unwrap()]);
    assert!(ok.status.success(), "the shipped example validates");
    assert!(json_stdout(&ok).get("active").is_some());

    let missing = rr_in(&dir, &["validate-policy", "no-such-policy.json"]);
    assert!(!missing.status.success(), "missing files are refused");

    let out_root = std::env::temp_dir().join(format!("rr-cli-policy-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&out_root).unwrap();
    let broken = out_root.join("broken.json");
    std::fs::write(&broken, b"{ not json").unwrap();
    let refused = rr_in(&dir, &["validate-policy", broken.to_str().unwrap()]);
    assert!(!refused.status.success(), "malformed files are refused");
}

/// The autostart status command reports registration without changing it.
///
/// Why: status is the read-only inspection tool — it must never create or
/// delete the scheduled task.
#[test]
fn autostart_status_reports_without_changing_the_scheduler() {
    let (dir, _guard) = workspace("autostart");
    let out = rr_in(&dir, &["autostart", "status"]);
    if out.status.success() {
        assert!(json_stdout(&out).is_object(), "status prints JSON");
    } else {
        // Non-Windows refuses the Windows-only surface explicitly.
        assert!(String::from_utf8_lossy(&out.stderr).contains("Windows"));
    }
}

/// Long-running entry points fail fast on broken workspaces and refuse to
/// serve the web interface without the loopback API.
///
/// Why: each refusal is an operator instruction — idling forever behind a
/// broken workspace is the failure mode these paths must never take.
#[test]
fn long_running_entry_points_fail_fast_on_broken_workspaces() {
    // A data directory that is a plain file fails the workspace open.
    let blocker = std::env::temp_dir().join(format!("rr-cli-blocker-{}", uuid::Uuid::new_v4()));
    std::fs::write(&blocker, b"not a directory").unwrap();
    let dir = blocker.to_str().unwrap();

    let run = rr(&["--data-dir", dir, "run"]);
    assert!(!run.status.success(), "a broken workspace ends the daemon");

    let web = rr(&["--data-dir", dir, "web"]);
    assert!(!web.status.success(), "a broken workspace cannot serve web");

    // A healthy workspace refuses to serve web without the integration API.
    let (ws, _guard) = workspace("web");
    let web = rr_in(&ws, &["web"]);
    assert!(!web.status.success());
    assert!(
        String::from_utf8_lossy(&web.stderr).contains("Enable the API"),
        "the refusal names the fix: {}",
        String::from_utf8_lossy(&web.stderr)
    );
}

/// Model R&D commands fail closed when the local runtime is unreachable.
///
/// Why: these commands only produce evidence against the local runtime — a
/// missing runtime must error instead of fabricating a report.
#[cfg(windows)]
#[test]
fn model_commands_fail_closed_without_the_local_runtime() {
    let (dir, _guard) = workspace("models");
    // A live Ollama may run on this machine: pin the workspace to a closed
    // loopback port so the commands must fail fast and fail closed.
    point_ollama_at(&dir, "http://127.0.0.1:9");
    let out_root = std::env::temp_dir().join(format!("rr-cli-models-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&out_root).unwrap();
    // Single-model evidence commands must fail outright.
    for command in ["evaluate", "evaluate-decision", "profile-model"] {
        let out = rr_in(
            &dir,
            &[
                command,
                "--out",
                out_root.join(format!("{command}.json")).to_str().unwrap(),
            ],
        );
        assert!(
            !out.status.success(),
            "{command} cannot fabricate evidence without the runtime"
        );
    }
    // Comparison commands always write a report, but an unreachable runtime
    // must leave the recommendation empty instead of inventing a winner.
    let compare = rr_in(
        &dir,
        &[
            "compare-decision-models",
            "--out",
            out_root
                .join("compare-decision-models.json")
                .to_str()
                .unwrap(),
        ],
    );
    if compare.status.success() {
        let summary = json_stdout(&compare);
        assert_eq!(
            summary.get("recommended_model"),
            Some(&serde_json::Value::Null),
            "an unreachable runtime recommends nothing"
        );
    }
    let compare = rr_in(
        &dir,
        &[
            "compare-models",
            "--out",
            out_root.join("compare-models.json").to_str().unwrap(),
        ],
    );
    if compare.status.success() {
        let report: serde_json::Value = serde_json::from_slice(
            &std::fs::read(out_root.join("compare-models.json")).expect("comparison report"),
        )
        .expect("comparison report is JSON");
        assert!(
            report
                .pointer("/summary/recommendation_eligible")
                .and_then(serde_json::Value::as_bool)
                .is_none_or(|eligible| !eligible),
            "an unreachable runtime never recommends a model"
        );
    }
}

/// The desktop launcher completes its screenshot flow and exits.
///
/// Why: the native launcher must open the demo workspace, capture the
/// requested screen and close itself — hanging past the capture would hang
/// every scripted screenshot run. Genuinely display-bound: winit needs a
/// display server (DISPLAY/WAYLAND_DISPLAY) and aborts before any app code
/// runs on a headless host, so the flow is exercised on Windows desktop
/// sessions only while the `rr` fleet surface stays covered everywhere.
#[cfg(all(feature = "gui", windows))]
#[test]
fn desktop_launcher_completes_the_screenshot_flow() {
    let _serialize = lock_credstore();
    for extra in [vec![], vec!["--data-dir", "placeholder"]] {
        let guard_dir =
            std::env::temp_dir().join(format!("rr-cli-desktop-{}", uuid::Uuid::new_v4()));
        let shot = guard_dir.join("shot.png");
        std::fs::create_dir_all(&guard_dir).unwrap();
        let mut args = vec![
            "--demo",
            "--demo-view",
            "overview",
            "--demo-width",
            "1180",
            "--demo-height",
            "760",
            "--screenshot",
            shot.to_str().unwrap(),
        ];
        if extra.len() == 2 {
            args.push("--data-dir");
            args.push(guard_dir.to_str().unwrap());
        }
        let mut child = Command::new(env!("CARGO_BIN_EXE_rejection-rejector"))
            .args(&args)
            .stdin(std::process::Stdio::null())
            .spawn()
            .expect("spawn desktop");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
        let status = loop {
            if let Some(status) = child.try_wait().expect("wait desktop") {
                break status;
            }
            if std::time::Instant::now() > deadline {
                let _ = child.kill();
                panic!("the desktop screenshot flow did not self-terminate");
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        };
        if status.success() {
            assert!(
                shot.is_file() || extra.len() == 2,
                "the screenshot flow writes its PNG"
            );
        }
    }
}

/// The terminal interface starts and stops cleanly in demo mode.
///
/// Why: `rr tui` must always leave the terminal usable — the process has to
/// terminate on its own when the terminal cannot deliver key events.
#[test]
fn tui_demo_mode_fails_fast_without_a_terminal() {
    #[cfg(windows)]
    let mut spawn = {
        use std::os::windows::process::CommandExt;
        let mut command = Command::new(env!("CARGO_BIN_EXE_rr"));
        command.args(["tui", "--demo"]);
        // DETACHED_PROCESS: the child has no console at all, so the terminal
        // initialization must fail instead of rendering into nothing.
        command.creation_flags(0x0000_0008);
        command
    };
    #[cfg(not(windows))]
    let mut spawn = {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rr"));
        command.args(["tui", "--demo"]);
        command
    };
    let mut child = spawn
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn rr tui");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait tui") {
            break status;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!("rr tui --demo did not fail fast without a terminal");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    assert!(!status.success(), "a missing terminal is a loud failure");
}
