use anyhow::Result;
#[cfg(any(windows, test))]
use anyhow::{Context, ensure};
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Scheduled-task name of the worker autostart registration.
///
/// Inputs: none (constant). Output: `&str` — the task name installed and
/// queried.
pub const TASK_NAME: &str = "Rejection Rejector Worker";

/// Report of the OS autostart registration for the worker.
///
/// Inputs: none (plain struct). Output: platform support, installation
/// state, installed-definition drift and the registered paths.
#[derive(Clone, Debug, Serialize)]
pub struct AutostartStatus {
    pub supported: bool,
    pub installed: bool,
    pub definition_matches_expected: Option<bool>,
    pub task_name: &'static str,
    pub mode: &'static str,
    pub executable: PathBuf,
    pub data_dir: PathBuf,
    pub note: String,
}

#[cfg(any(windows, test))]
/// Escape the five XML metacharacters for embedding text in task XML.
///
/// Inputs: `value` — raw text destined for an XML element or attribute.
/// Output: `String` — the text with `&`, `<`, `>`, `"` and `'` replaced by
/// entities.
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(any(windows, test))]
/// Quote one argument for a Windows CreateProcess command line.
///
/// Inputs: `value` — raw argument text. Output: `String` — the argument,
/// returned unchanged when it needs no quoting, otherwise double-quoted with
/// CommandLineToArgvW-compatible backslash escaping.
fn quote_windows_argument(value: &str) -> String {
    const QUOTE: char = '\u{22}';
    const BACKSLASH: char = '\u{5c}';

    if !value.is_empty()
        && !value
            .chars()
            .any(|ch| ch.is_whitespace() || ch == QUOTE || ch.is_control())
    {
        return value.to_owned();
    }

    // Windows CreateProcess receives one command-line string. Quote using the
    // CommandLineToArgvW-compatible rule: backslashes preceding a quote are
    // doubled, and trailing backslashes are doubled before the closing quote.
    let mut out = String::with_capacity(value.len().saturating_add(2));
    out.push(QUOTE);
    let mut backslashes = 0usize;
    for ch in value.chars() {
        if ch == BACKSLASH {
            backslashes = backslashes.saturating_add(1);
            continue;
        }
        if ch == QUOTE {
            for _ in 0..backslashes.saturating_mul(2).saturating_add(1) {
                out.push(BACKSLASH);
            }
            out.push(QUOTE);
            backslashes = 0;
            continue;
        }
        for _ in 0..backslashes {
            out.push(BACKSLASH);
        }
        backslashes = 0;
        out.push(ch);
    }
    for _ in 0..backslashes.saturating_mul(2) {
        out.push(BACKSLASH);
    }
    out.push(QUOTE);
    out
}

#[cfg(any(windows, test))]
/// Render the worker task's command-line arguments.
///
/// Inputs: `data_dir` — workspace data directory. Output: `Result<String>` —
/// the `--data-dir <quoted path> run` argument string; error when the path is
/// not valid Unicode or contains control characters.
fn expected_arguments(data_dir: &Path) -> Result<String> {
    let value = data_dir
        .to_str()
        .context("Data directory is not valid Unicode")?;
    ensure!(
        !value.chars().any(char::is_control),
        "Data directory contains control characters"
    );
    Ok(format!("--data-dir {} run", quote_windows_argument(value)))
}

#[cfg(any(windows, test))]
/// Render the Task Scheduler XML definition for the worker task.
///
/// Inputs: `user` — current Windows identity; `executable` — worker
/// executable path; `data_dir` — workspace data directory. Output:
/// `Result<String>` — the task XML document; error when any input is invalid
/// or unusable.
fn render_task_xml(user: &str, executable: &Path, data_dir: &Path) -> Result<String> {
    ensure!(
        !user.trim().is_empty() && !user.chars().any(char::is_control),
        "Current Windows user identity is invalid"
    );
    let executable = executable
        .to_str()
        .context("Executable path is not valid Unicode")?;
    ensure!(
        !executable.chars().any(char::is_control),
        "Executable path contains control characters"
    );
    let working_directory = Path::new(executable)
        .parent()
        .context("Executable has no parent directory")?
        .to_str()
        .context("Executable parent is not valid Unicode")?;
    let arguments = expected_arguments(data_dir)?;

    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Rejection Rejector local mailbox worker. Runs only in the signed-in user's session.</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user}</UserId>
      <Delay>PT30S</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
      <WorkingDirectory>{working_directory}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"#,
        user = xml_escape(user.trim()),
        command = xml_escape(executable),
        arguments = xml_escape(&arguments),
        working_directory = xml_escape(working_directory),
    ))
}

#[cfg(windows)]
/// Resolve one System32 binary under `SystemRoot`.
///
/// Inputs: `name` — binary file name (e.g. `whoami.exe`). Output:
/// `Result<PathBuf>` — the absolute path; error when `SystemRoot` is unusable
/// or the binary is missing.
fn system32_binary(name: &str) -> Result<PathBuf> {
    let root = std::env::var_os("SystemRoot").context("SystemRoot is unavailable")?;
    let root = PathBuf::from(root);
    ensure!(root.is_absolute(), "SystemRoot must be absolute");
    let path = root.join("System32").join(name);
    ensure!(path.is_file(), "{} is unavailable", path.display());
    Ok(path)
}

#[cfg(windows)]
/// Query the current Windows identity.
///
/// Inputs: none. Output: `Result<String>` — the trimmed `whoami` result; error
/// when the query fails or returns empty.
fn current_user() -> Result<String> {
    let output = std::process::Command::new(system32_binary("whoami.exe")?)
        .output()
        .context("Unable to query current Windows identity")?;
    ensure!(output.status.success(), "whoami.exe failed");
    let user = String::from_utf8(output.stdout)?.trim().to_owned();
    ensure!(
        !user.is_empty() && user.len() <= 512 && !user.chars().any(char::is_control),
        "Current Windows identity is invalid"
    );
    Ok(user)
}

#[cfg(any(windows, test))]
/// MSIX physical paths can change on update; registering them as Task Scheduler
/// executables would silently break the background worker after installation.
/// Inputs: `executable` — path to classify. Output: `bool` — `true` when any
/// path segment is the MSIX `WindowsApps` install directory.
fn is_msix_managed_path(executable: &Path) -> bool {
    executable
        .to_string_lossy()
        .replace('\\', "/")
        .split('/')
        .any(|part| part.eq_ignore_ascii_case("WindowsApps"))
}

#[cfg(windows)]
/// Canonicalize the autostart task inputs.
///
/// Inputs: `executable` — rr executable path (MSIX-managed paths refused);
/// `data_dir` — workspace data directory (created as needed). Output:
/// `Result<(PathBuf, PathBuf)>` — the canonical (executable, data directory)
/// pair.
fn canonical_inputs(executable: &Path, data_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    ensure!(
        !is_msix_managed_path(executable),
        "MSIX-managed executable paths are not supported for Task Scheduler autostart; use an unpackaged, stable rr.exe path"
    );
    std::fs::create_dir_all(data_dir)?;
    let executable = std::fs::canonicalize(executable)
        .with_context(|| format!("Cannot resolve {}", executable.display()))?;
    ensure!(
        !is_msix_managed_path(&executable),
        "Executable resolves into MSIX-managed WindowsApps; Task Scheduler would break after a package update"
    );
    let data_dir = std::fs::canonicalize(data_dir)
        .with_context(|| format!("Cannot resolve {}", data_dir.display()))?;
    ensure!(executable.is_file(), "Worker executable is not a file");
    ensure!(data_dir.is_dir(), "Data directory is not a directory");
    Ok((executable, data_dir))
}

#[cfg(windows)]
/// Write one task XML document as a private UTF-16 file.
///
/// Inputs: `data_dir` — directory to write into; `xml` — task XML text. Output:
/// `Result<PathBuf>` — the written file path (BOM-prefixed UTF-16LE).
fn write_task_xml(data_dir: &Path, xml: &str) -> Result<PathBuf> {
    let path = data_dir.join(format!(".autostart-task-{}.xml", uuid::Uuid::new_v4()));
    let utf16: Vec<u16> = xml.encode_utf16().collect();
    let mut bytes = Vec::with_capacity(2 + utf16.len() * 2);
    bytes.extend_from_slice(&[0xff, 0xfe]);
    for unit in utf16 {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    crate::vault::write_new_private(&path, &bytes)?;
    Ok(path)
}

#[cfg(windows)]
/// Run one Windows Task Scheduler command with the real `schtasks.exe`.
///
/// Inputs: `args` — exact `schtasks` argument vector. Output: the process
/// output, or an error when the command cannot be spawned. This is the
/// production [`CommandRunner`]; tests inject fakes so registration flows
/// never touch the real scheduler.
pub fn schtasks(args: &[&str]) -> Result<std::process::Output> {
    std::process::Command::new(system32_binary("schtasks.exe")?)
        .args(args)
        .output()
        .context("Unable to execute Windows Task Scheduler command")
}

#[cfg(not(windows))]
/// Non-Windows stand-in for [`schtasks`]: the autostart entry points refuse
/// before any command runs, so the runner only satisfies the shared API.
///
/// Inputs: `args` — ignored. Output: always the unsupported-platform error.
pub fn schtasks(_args: &[&str]) -> Result<std::process::Output> {
    Err(anyhow::anyhow!(
        "Windows Task Scheduler autostart is supported only on Windows"
    ))
}

/// Runner for one Task Scheduler invocation: takes the exact `schtasks`
/// argument vector and returns the process output or a spawn failure.
pub type CommandRunner = fn(&[&str]) -> Result<std::process::Output>;

#[cfg(windows)]
/// Register the worker as a per-user logon task and report the resulting
/// registration state.
///
/// Inputs: `executable` — worker executable; `data_dir` — worker data
/// directory; `run` — Task Scheduler command runner (production passes
/// [`schtasks`], tests inject a fake so registration flows never touch the
/// real scheduler). Output: the [`AutostartStatus`] observed after
/// submission; input validation failures, a rejected definition and spawn
/// failures propagate as errors, and the temporary definition file is
/// removed on every path.
pub fn install(executable: &Path, data_dir: &Path, run: CommandRunner) -> Result<AutostartStatus> {
    let (executable, data_dir) = canonical_inputs(executable, data_dir)?;
    let user = current_user()?;
    let xml = render_task_xml(&user, &executable, &data_dir)?;
    let xml_path = write_task_xml(&data_dir, &xml)?;
    let xml_arg = xml_path
        .to_str()
        .context("Temporary task definition path is not valid Unicode");
    let xml_arg = xml_arg?;
    let result = run(&["/Create", "/TN", TASK_NAME, "/XML", xml_arg, "/F"]);
    let _ = std::fs::remove_file(&xml_path);
    let output = result?;
    ensure!(
        output.status.success(),
        "Task Scheduler rejected worker registration (exit code {:?})",
        output.status.code()
    );
    status(&executable, &data_dir, run)
}

#[cfg(not(windows))]
/// Non-Windows [`install`] stub: Task Scheduler autostart is Windows-only.
///
/// Inputs: ignored. Output: always the unsupported-platform error.
pub fn install(
    _executable: &Path,
    _data_dir: &Path,
    _run: CommandRunner,
) -> Result<AutostartStatus> {
    Err(anyhow::anyhow!(
        "Windows Task Scheduler autostart is supported only on Windows"
    ))
}

#[cfg(windows)]
/// Remove the registered worker task.
///
/// Inputs: `run` — Task Scheduler command runner (production passes
/// [`schtasks`], tests inject a fake). Output: `Ok(())` when the scheduler
/// confirms removal; a refused removal or spawn failure propagates as an
/// error.
pub fn remove(run: CommandRunner) -> Result<()> {
    let output = run(&["/Delete", "/TN", TASK_NAME, "/F"])?;
    ensure!(
        output.status.success(),
        "Task Scheduler could not remove the worker task (exit code {:?})",
        output.status.code()
    );
    Ok(())
}

#[cfg(not(windows))]
/// Non-Windows [`remove`] stub: Task Scheduler autostart is Windows-only.
///
/// Inputs: ignored. Output: always the unsupported-platform error.
pub fn remove(_run: CommandRunner) -> Result<()> {
    Err(anyhow::anyhow!(
        "Windows Task Scheduler autostart is supported only on Windows"
    ))
}

#[cfg(windows)]
/// Compare a registered Task Scheduler definition against the required one.
///
/// Inputs: `actual_xml` — raw XML returned by `schtasks /Query /XML`;
/// `executable` — worker executable; `data_dir` — worker data directory.
/// Output: `Ok(true)` only when the registered definition carries the exact
/// `<Command>`, `<Arguments>` and least-privilege settings contract; a stale,
/// rewritten or partially matching registration reports `Ok(false)`.
fn task_definition_matches(actual_xml: &str, executable: &Path, data_dir: &Path) -> Result<bool> {
    let expected_command = format!(
        "<Command>{}</Command>",
        xml_escape(
            executable
                .to_str()
                .context("Executable path is invalid Unicode")?
        )
    );
    let expected_arguments = format!(
        "<Arguments>{}</Arguments>",
        xml_escape(&expected_arguments(data_dir)?)
    );
    let required = [
        expected_command.as_str(),
        expected_arguments.as_str(),
        "<LogonType>InteractiveToken</LogonType>",
        "<RunLevel>LeastPrivilege</RunLevel>",
        "<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>",
        "<Interval>PT1M</Interval>",
        "<Count>3</Count>",
    ];
    Ok(required.iter().all(|needle| actual_xml.contains(needle)))
}

#[cfg(windows)]
/// Report the worker's Task Scheduler registration state.
///
/// Inputs: `executable` — worker executable; `data_dir` — worker data
/// directory; `run` — Task Scheduler command runner (production passes
/// [`schtasks`], tests inject a fake). Output: the [`AutostartStatus`] —
/// `installed: false` when the task is not registered, otherwise the
/// registered definition compared against the required worker contract;
/// invalid query output or input failures propagate as errors.
pub fn status(executable: &Path, data_dir: &Path, run: CommandRunner) -> Result<AutostartStatus> {
    let (executable, data_dir) = canonical_inputs(executable, data_dir)?;
    let output = run(&["/Query", "/TN", TASK_NAME, "/XML"])?;
    if !output.status.success() {
        return Ok(AutostartStatus {
            supported: true,
            installed: false,
            definition_matches_expected: None,
            task_name: TASK_NAME,
            mode: "per-user-on-logon",
            executable,
            data_dir,
            note: "Task is not registered for the current machine/user context".into(),
        });
    }
    let actual = String::from_utf8(output.stdout)?;
    let matches = task_definition_matches(&actual, &executable, &data_dir)?;
    Ok(AutostartStatus {
        supported: true,
        installed: true,
        definition_matches_expected: Some(matches),
        task_name: TASK_NAME,
        mode: "per-user-on-logon",
        executable,
        data_dir,
        note: if matches {
            "Registered task matches the required least-privilege worker contract".into()
        } else {
            "Registered task exists but differs from the required worker contract; reinstall it before relying on background operation".into()
        },
    })
}

#[cfg(not(windows))]
/// Non-Windows [`status`] stub: Task Scheduler autostart is Windows-only.
///
/// Inputs: ignored except for echoing `executable` and `data_dir`. Output:
/// an unsupported [`AutostartStatus`] describing the platform limitation.
pub fn status(executable: &Path, data_dir: &Path, _run: CommandRunner) -> Result<AutostartStatus> {
    Ok(AutostartStatus {
        supported: false,
        installed: false,
        definition_matches_expected: None,
        task_name: TASK_NAME,
        mode: "unsupported",
        executable: executable.to_path_buf(),
        data_dir: data_dir.to_path_buf(),
        note: "Per-user Task Scheduler autostart is a Windows-only capability".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msix_managed_paths_are_not_stable_worker_task_targets() {
        assert!(is_msix_managed_path(Path::new(
            r"C:\Program Files\WindowsApps\Example_1.0.0.0_x64__abc\rr.exe"
        )));
        assert!(is_msix_managed_path(Path::new(
            r"C:\Users\Tester\AppData\Local\Microsoft\WindowsApps\rr.exe"
        )));
        assert!(!is_msix_managed_path(Path::new(
            r"C:\Program Files\RejectionRejector\rr.exe"
        )));
        assert!(!is_msix_managed_path(Path::new(
            r"C:\Program Files\WindowsAppsBackup\rr.exe"
        )));
    }

    #[test]
    fn windows_argument_quoting_handles_spaces_quotes_and_trailing_backslashes() {
        assert_eq!(quote_windows_argument("plain"), "plain");
        assert_eq!(quote_windows_argument("two words"), "\"two words\"");
        assert_eq!(
            quote_windows_argument("C:\\Program Files\\RR\\"),
            "\"C:\\Program Files\\RR\\\\\""
        );
        assert_eq!(quote_windows_argument("a\\\"b"), "\"a\\\\\\\"b\"");
    }

    #[test]
    fn task_xml_escapes_paths_and_enforces_enterprise_worker_settings() {
        let exe = Path::new(r"C:\Program Files\RR & Tools\rr.exe");
        let data = Path::new(r"C:\Users\Test User\RR");
        let xml = render_task_xml(r"DOMAIN\User & Ops", exe, data).unwrap();
        assert!(xml.contains("DOMAIN\\User &amp; Ops"));
        assert!(xml.contains(r"C:\Program Files\RR &amp; Tools\rr.exe"));
        assert!(xml.contains("<LogonType>InteractiveToken</LogonType>"));
        assert!(xml.contains("<RunLevel>LeastPrivilege</RunLevel>"));
        assert!(xml.contains("<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"));
        assert!(xml.contains("<Delay>PT30S</Delay>"));
        assert!(xml.contains("<Interval>PT1M</Interval>"));
        assert!(xml.contains("<Count>3</Count>"));
        assert!(xml.contains(r"--data-dir &quot;C:\Users\Test User\RR&quot; run"));
    }

    /// Guards XML escaping order and single-pass semantics: & must be escaped
    /// before any other entity (or entities would double-escape), and escaping
    /// must not be idempotent (a pre-escaped value is data, not markup).
    #[test]
    fn xml_escape_is_single_pass_and_escapes_ampersand_first() {
        assert_eq!(xml_escape(r#"<a&b>"c'd"#), "&lt;a&amp;b&gt;&quot;c&apos;d");
        assert_eq!(xml_escape("&amp;"), "&amp;amp;");
        assert_eq!(xml_escape("&lt;"), "&amp;lt;");
        assert_eq!(xml_escape("plain"), "plain");
    }

    /// Guards CreateProcess quoting rules: empty strings must become explicit
    /// empty arguments (never dropped), control characters force quoting even
    /// without spaces, and plain backslash runs stay unquoted.
    #[test]
    fn windows_argument_quoting_edge_cases() {
        assert_eq!(quote_windows_argument(""), "\"\"");
        assert_eq!(quote_windows_argument("tab\there"), "\"tab\there\"");
        assert_eq!(quote_windows_argument(r"back\slash"), r"back\slash");
        assert_eq!(quote_windows_argument(r"trail\\"), r"trail\\");
        assert_eq!(quote_windows_argument(r"with space\"), "\"with space\\\\\"");
        assert_eq!(quote_windows_argument("\"lead"), "\"\\\"lead\"");
    }

    /// Guards argument-string assembly order and quoting: --data-dir, the
    /// quoted path and the literal run verb must appear in exactly that order,
    /// so a reordered or unquoted invocation would be caught before install.
    #[test]
    fn expected_arguments_have_exact_order_and_quoting() {
        assert_eq!(
            expected_arguments(Path::new(r"C:\Program Files\RR")).unwrap(),
            "--data-dir \"C:\\Program Files\\RR\" run"
        );
        assert_eq!(
            expected_arguments(Path::new("plain")).unwrap(),
            "--data-dir plain run"
        );
    }

    /// Guards data-dir input validation: control characters (newline, tab,
    /// carriage return, bell) must be refused before any XML is generated —
    /// a smuggled control byte could forge or truncate the task definition.
    #[test]
    fn data_directory_with_control_characters_is_rejected() {
        for bad in [
            "with\nnewline",
            "with\ttab",
            "with\rreturn",
            "bell\u{7}here",
        ] {
            assert!(expected_arguments(Path::new(bad)).is_err(), "{bad:?}");
        }
    }

    /// Guards task-name/user binding: the user identity is trimmed of padding
    /// but not altered otherwise, and must appear in both UserId slots (trigger
    /// and principal) exactly twice so a mismatch cannot run as another user.
    #[test]
    fn render_task_xml_trims_the_user_identity_into_both_slots() {
        let exe = Path::new(r"C:\RR\rr.exe");
        let data = Path::new(r"C:\RR\data");
        let xml = render_task_xml("  DOMAIN\\User  ", exe, data).unwrap();
        assert_eq!(xml.matches("<UserId>DOMAIN\\User</UserId>").count(), 2);
        assert!(!xml.contains("  DOMAIN"));
    }

    /// Guards render_task_xml input validation: blank/control users, control
    /// characters in the executable path and parent-less executables must all
    /// fail before any task definition file touches the disk.
    #[test]
    fn render_task_xml_rejects_invalid_user_and_executable_inputs() {
        let exe = Path::new(r"C:\RR\rr.exe");
        let data = Path::new(r"C:\RR\data");
        for user in ["", "   ", "DOMAIN\nUser", "DOM\u{7}AIN"] {
            assert!(render_task_xml(user, exe, data).is_err(), "{user:?}");
        }
        for bad_exe in [Path::new("/"), Path::new("C:\\RR\\rr.ex\u{1}e")] {
            assert!(render_task_xml("DOMAIN\\User", bad_exe, data).is_err());
        }
    }

    /// Guards working-directory derivation: the task must run from the
    /// executable's parent directory, XML-escaped, or relative-path resolution
    /// could launch a different binary after a working-directory change.
    ///
    /// Windows-only: these assertions pin `Path::parent` semantics for
    /// backslash paths, which are not path separators on Unix.
    #[cfg(windows)]
    #[test]
    fn task_working_directory_is_the_executable_parent() {
        let exe = Path::new(r"C:\Program Files\RR & Co\rr.exe");
        let data = Path::new(r"C:\RR\data");
        let xml = render_task_xml("DOMAIN\\User", exe, data).unwrap();
        assert!(
            xml.contains("<WorkingDirectory>C:\\Program Files\\RR &amp; Co</WorkingDirectory>")
        );
        assert!(xml.contains(r"C:\Program Files\RR &amp; Co\rr.exe"));
    }

    /// Guards the full task-settings contract: restart policy, execution
    /// limits, priority and battery/network policy must all be present, since
    /// a missing RestartOnFailure would silently stop the worker after crashes.
    #[test]
    fn task_xml_holds_the_full_restart_and_scheduling_contract() {
        let xml = render_task_xml(
            "DOMAIN\\User",
            Path::new(r"C:\RR\rr.exe"),
            Path::new(r"C:\RR\data"),
        )
        .unwrap();
        for needle in [
            "<RestartOnFailure>",
            "<Interval>PT1M</Interval>",
            "<Count>3</Count>",
            "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>",
            "<Priority>7</Priority>",
            "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
            "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>",
            "<StartWhenAvailable>true</StartWhenAvailable>",
            "<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>",
            "<LogonTrigger>",
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?>",
        ] {
            assert!(xml.contains(needle), "missing {needle}");
        }
        assert_eq!(xml.matches("<Task version=\"1.4\"").count(), 1);
        assert_eq!(xml.matches("</Task>").count(), 1);
    }

    /// Guards MSIX path detection anchoring and case folding: only a full
    /// WindowsApps path segment counts (any case, either separator), so
    /// similarly named directories are not over-refused.
    #[test]
    fn msix_detection_is_segment_anchored_and_case_insensitive() {
        assert!(is_msix_managed_path(Path::new(
            r"c:\program files\WINDOWSAPPS\Pack\rr.exe"
        )));
        assert!(is_msix_managed_path(Path::new(
            "C:/Users/x/AppData/Local/Microsoft/WindowsApps/rr.exe"
        )));
        assert!(!is_msix_managed_path(Path::new(
            r"C:\tools\windowsapps_backup\rr.exe"
        )));
        assert!(!is_msix_managed_path(Path::new(r"C:\tools\winapps\rr.exe")));
    }

    /// Guards System32 resolution: only binaries that really exist in
    /// System32 resolve, and a missing one fails before any process spawn.
    #[cfg(windows)]
    #[test]
    fn system32_resolution_rejects_missing_binaries() {
        assert!(system32_binary("whoami.exe").unwrap().is_file());
        assert!(system32_binary("definitely-not-a-real-binary.exe").is_err());
    }

    /// Guards identity validation: the queried Windows identity must be a
    /// non-empty, bounded, control-character-free string, since it is later
    /// XML-escaped into the task definition's two UserId slots.
    #[cfg(windows)]
    #[test]
    fn current_user_is_a_valid_windows_identity() {
        let user = current_user().unwrap();
        assert!(!user.is_empty());
        assert!(user.len() <= 512);
        assert!(!user.chars().any(char::is_control));
    }

    /// Guards input canonicalization: MSIX-managed or unresolvable
    /// executables and non-file "executables" are refused before any task
    /// definition is generated, and the happy path creates the data directory
    /// and returns canonical paths.
    #[cfg(windows)]
    #[test]
    fn canonical_inputs_reject_msix_missing_and_non_file_executables() {
        let root = tempfile::tempdir().unwrap();
        let error = canonical_inputs(
            Path::new(r"C:\Program Files\WindowsApps\Pack\rr.exe"),
            root.path(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("MSIX"), "{error}");
        assert!(canonical_inputs(&root.path().join("missing.exe"), root.path()).is_err());
        let dir_exe = root.path().join("a-directory");
        std::fs::create_dir_all(&dir_exe).unwrap();
        let error = canonical_inputs(&dir_exe, root.path())
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a file"), "{error}");
        let exe = std::env::current_exe().unwrap();
        let data = root.path().join("data").join("nested");
        let (canon_exe, canon_data) = canonical_inputs(&exe, &data).unwrap();
        assert!(canon_exe.is_file());
        assert!(canon_data.is_dir());
    }

    /// Guards the on-disk task definition format: Task Scheduler reads only
    /// UTF-16LE with a BOM, so the writer must emit exactly that byte layout
    /// (including the non-ASCII round trip) or registration silently fails.
    #[cfg(windows)]
    #[test]
    fn write_task_xml_emits_utf16le_with_bom() {
        let root = tempfile::tempdir().unwrap();
        let path = write_task_xml(root.path(), "<Task>Ä</Task>").unwrap();
        assert!(
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".autostart-task-")
        );
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(&bytes[..2], &[0xff, 0xfe], "Task Scheduler needs a BOM");
        let decoded: Vec<u16> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|unit| u16::from_le_bytes(*unit))
            .collect();
        assert_eq!(String::from_utf16(&decoded).unwrap(), "<Task>Ä</Task>");
    }

    /// Guards schtasks plumbing: querying an unregistered task must come back
    /// as a non-zero exit the caller can distinguish from a real definition.
    #[cfg(windows)]
    #[test]
    fn schtasks_reports_unregistered_tasks_as_failed_queries() {
        let output = schtasks(&[
            "/Query",
            "/TN",
            "Rejection Rejector Unregistered Probe",
            "/XML",
        ])
        .unwrap();
        assert!(!output.status.success());
    }

    /// Guards status invariants: `status` must never claim a definition match
    /// for a task it did not find, and it must echo the canonicalized inputs
    /// back to the caller. (Whether the worker task is registered depends on
    /// the host; only the invariants are pinned here.)
    #[cfg(windows)]
    #[test]
    fn status_reports_consistent_registration_state() {
        let root = tempfile::tempdir().unwrap();
        let exe = std::env::current_exe().unwrap();
        let state = status(&exe, root.path(), schtasks).unwrap();
        assert!(state.supported);
        assert_eq!(state.task_name, TASK_NAME);
        assert_eq!(
            state.definition_matches_expected.is_some(),
            state.installed,
            "a match verdict exists only for a registered task"
        );
        assert_eq!(state.executable, std::fs::canonicalize(&exe).unwrap());
    }

    /// Guards the registered-definition comparison: only the exact command,
    /// arguments and least-privilege settings bundle counts as installed —
    /// a rewritten executable, a different data dir, a weakened run level or
    /// a changed restart count must all fail the comparison. Very long paths
    /// must round-trip through Windows quoting and XML escaping intact.
    #[cfg(windows)]
    #[test]
    fn task_definition_matching_is_exact_and_quoting_aware() {
        let exe = Path::new(r"C:\Program Files\RR & Co\rr.exe");
        let data = Path::new(r"C:\Users\Test User\RR");
        let xml = render_task_xml("DOMAIN\\User", exe, data).unwrap();
        assert!(task_definition_matches(&xml, exe, data).unwrap());
        assert!(
            !task_definition_matches(&xml, Path::new(r"C:\Program Files\Other\rr.exe"), data)
                .unwrap()
        );
        assert!(!task_definition_matches(&xml, exe, Path::new(r"C:\Users\Other\RR")).unwrap());
        for tampered in [
            xml.replace("<Count>3</Count>", "<Count>5</Count>"),
            xml.replace(
                "<RunLevel>LeastPrivilege</RunLevel>",
                "<RunLevel>HighestAvailable</RunLevel>",
            ),
            xml.replace("<Interval>PT1M</Interval>", "<Interval>PT5M</Interval>"),
        ] {
            assert!(
                !task_definition_matches(&tampered, exe, data).unwrap(),
                "weakened settings must never count as a match"
            );
        }

        let long_exe = format!(
            "C:\\{}\\rr.exe",
            "a very long program directory ".repeat(10)
        );
        let long_data = format!("C:\\{}\\data", "a very long data directory ".repeat(10));
        let xml =
            render_task_xml("DOMAIN\\User", Path::new(&long_exe), Path::new(&long_data)).unwrap();
        assert!(
            task_definition_matches(&xml, Path::new(&long_exe), Path::new(&long_data)).unwrap(),
            "very long names must survive quoting and escaping unchanged"
        );
        let long_data_plus = format!("{long_data}x");
        assert!(
            !task_definition_matches(&xml, Path::new(&long_exe), Path::new(&long_data_plus))
                .unwrap()
        );
    }

    /// Fake Task Scheduler runner: records every argument vector and replays
    /// scripted responses. State is isolated per test thread so parallel
    /// tests never touch the real Windows Task Scheduler or each other.
    #[cfg(windows)]
    mod fake_scheduler {
        use std::cell::RefCell;
        use std::collections::VecDeque;

        thread_local! {
            static CALLS: RefCell<Vec<Vec<String>>> = const { RefCell::new(Vec::new()) };
            static SCRIPT: RefCell<VecDeque<(u32, Vec<u8>)>> =
                const { RefCell::new(VecDeque::new()) };
            static SPAWN_FAIL: RefCell<bool> = const { RefCell::new(false) };
        }

        /// Clear recorded calls and load `script` as the ordered exit-code /
        /// stdout answers for upcoming invocations.
        ///
        /// Inputs: `script` — ordered `(exit code, stdout)` answers for upcoming
        /// calls. Output: none.
        pub(super) fn reset(script: Vec<(u32, Vec<u8>)>) {
            CALLS.with(|calls| calls.borrow_mut().clear());
            SCRIPT.with(|s| *s.borrow_mut() = script.into());
            SPAWN_FAIL.with(|f| *f.borrow_mut() = false);
        }

        /// Arm the fake so every invocation fails like an unspawnable
        /// `schtasks.exe`.
        ///
        /// Inputs: none. Output: none; every later invocation fails as if `schtasks.exe`
        /// could not spawn.
        pub(super) fn fail_spawn() {
            reset(Vec::new());
            SPAWN_FAIL.with(|f| *f.borrow_mut() = true);
        }

        /// Fake [`super::CommandRunner`]: record `args`, then replay the next
        /// scripted response or the armed spawn failure.
        ///
        /// Inputs: `args` — argument vector of the faked invocation. Output: `Result<std::process::Output>`
        /// — the next scripted response, or a spawn failure once armed.
        pub(super) fn run(args: &[&str]) -> super::Result<std::process::Output> {
            CALLS.with(|calls| {
                calls
                    .borrow_mut()
                    .push(args.iter().map(|arg| (*arg).to_owned()).collect())
            });
            if SPAWN_FAIL.with(|f| *f.borrow()) {
                return Err(anyhow::anyhow!("injected spawn failure"));
            }
            let (code, stdout) = SCRIPT
                .with(|s| s.borrow_mut().pop_front())
                .unwrap_or_else(|| (0, Vec::new()));
            Ok(output(code, stdout))
        }

        /// Every recorded argument vector since [`reset`].
        ///
        /// Inputs: none. Output: `Vec<Vec<String>>` of every recorded argument vector
        /// since [`reset`].
        pub(super) fn calls() -> Vec<Vec<String>> {
            CALLS.with(|calls| calls.borrow().clone())
        }

        /// Build one synthetic `schtasks` process result.
        ///
        /// Inputs: `code` — process exit code; `stdout` — captured standard
        /// output. Output: the matching [`std::process::Output`].
        pub(super) fn output(code: u32, stdout: Vec<u8>) -> std::process::Output {
            use std::os::windows::process::ExitStatusExt;
            std::process::Output {
                status: std::process::ExitStatus::from_raw(code),
                stdout,
                stderr: Vec::new(),
            }
        }
    }

    /// Fresh stub workspace for registration-flow tests: a worker executable
    /// file plus an existing data directory inside one tempdir.
    ///
    /// Inputs: none. Output: `(guard, executable, data_dir)` where `guard`
    /// keeps the tempdir alive.
    #[cfg(windows)]
    fn stub_workspace() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let exe = root.path().join("rr.exe");
        std::fs::write(&exe, b"stub-worker").unwrap();
        let data = root.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        (root, exe, data)
    }

    /// The exact task definition `install` submits for this workspace.
    ///
    /// Inputs: `exe` / `data` — pre-canonicalization workspace paths.
    /// Output: the rendered task XML built from the canonicalized paths.
    #[cfg(windows)]
    fn expected_definition(exe: &Path, data: &Path) -> String {
        render_task_xml(
            &current_user().unwrap(),
            &std::fs::canonicalize(exe).unwrap(),
            &std::fs::canonicalize(data).unwrap(),
        )
        .unwrap()
    }

    /// Leftover temporary task-definition files in the data directory.
    ///
    /// Inputs: `data` — worker data directory. Output: every entry named
    /// like the private `write_task_xml` temporaries.
    #[cfg(windows)]
    fn leftover_definitions(data: &Path) -> Vec<String> {
        std::fs::read_dir(data)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".autostart-task-"))
            .collect()
    }

    // why: registration must drive the scheduler with exactly the fixed task
    // name and the `/Create /TN <task> /XML <path> /F` contract, submit a
    // definition file inside the data directory that is deleted afterwards,
    // then answer the caller from a `/Query` — including a positive match
    // verdict for the definition just submitted. Any drift in argument
    // construction, ordering, cleanup or the reported state fails this test,
    // and the fake runner keeps the real scheduler untouched.
    #[cfg(windows)]
    #[test]
    fn install_registration_uses_exact_commands_and_cleans_up() {
        let (_root, exe, data) = stub_workspace();
        let definition = expected_definition(&exe, &data);
        fake_scheduler::reset(vec![(0, Vec::new()), (0, definition.into_bytes())]);
        let state = install(&exe, &data, fake_scheduler::run).unwrap();

        let calls = fake_scheduler::calls();
        assert_eq!(calls.len(), 2, "install must submit once, then query once");
        assert_eq!(calls[0][0], "/Create");
        assert_eq!(calls[0][1], "/TN");
        assert_eq!(calls[0][2], TASK_NAME);
        assert_eq!(calls[0][3], "/XML");
        assert_eq!(calls[0][5], "/F");
        let xml_arg = Path::new(&calls[0][4]);
        assert!(
            xml_arg.starts_with(std::fs::canonicalize(&data).unwrap()),
            "the definition file must live in the data directory: {}",
            xml_arg.display()
        );
        assert!(
            !xml_arg.exists(),
            "the temporary definition file must be removed after submission"
        );
        assert_eq!(calls[1][0], "/Query");
        assert_eq!(calls[1][1], "/TN");
        assert_eq!(calls[1][2], TASK_NAME);
        assert_eq!(calls[1][3], "/XML");
        assert!(state.installed);
        assert_eq!(state.definition_matches_expected, Some(true));
        assert!(
            state.note.contains("matches the required"),
            "{}",
            state.note
        );
    }

    // why: a scheduler-side rejection must surface as an error carrying the
    // exit code, must never fall through to a status query for a task that
    // was never registered, and must still remove the temporary definition
    // file. Silent success here would report an autostart that does not
    // exist.
    #[cfg(windows)]
    #[test]
    fn install_rejection_is_an_error_and_still_cleans_up() {
        let (_root, exe, data) = stub_workspace();
        fake_scheduler::reset(vec![(1, Vec::new())]);
        let error = install(&exe, &data, fake_scheduler::run)
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(error.contains("rejected worker registration"), "{error}");
        assert!(error.contains("exit code Some(1)"), "{error}");
        let calls = fake_scheduler::calls();
        assert_eq!(
            calls.len(),
            1,
            "a rejected registration must not be queried"
        );
        assert!(
            leftover_definitions(&data).is_empty(),
            "the definition file must be removed even on rejection"
        );
    }

    // why: a spawn failure must propagate as the runner's own error instead
    // of masquerading as a scheduler rejection, and the temporary definition
    // file must still be removed so failed attempts leave no task XML behind.
    #[cfg(windows)]
    #[test]
    fn install_spawn_failures_propagate_and_still_clean_up() {
        let (_root, exe, data) = stub_workspace();
        fake_scheduler::fail_spawn();
        let error = install(&exe, &data, fake_scheduler::run)
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(error.contains("injected spawn failure"), "{error}");
        assert!(
            leftover_definitions(&data).is_empty(),
            "the definition file must be removed even when the spawn fails"
        );
    }

    // why: removal must target exactly the fixed task name with
    // `/Delete /TN <task> /F` and must not report success when the scheduler
    // refuses — removing the wrong name would orphan the worker task
    // forever, and a swallowed refusal would leave a stale registration.
    #[cfg(windows)]
    #[test]
    fn remove_targets_the_fixed_task_name_and_reports_refusals() {
        fake_scheduler::reset(vec![(0, Vec::new())]);
        remove(fake_scheduler::run).unwrap();
        assert_eq!(
            fake_scheduler::calls(),
            vec![vec![
                "/Delete".to_string(),
                "/TN".to_string(),
                TASK_NAME.to_string(),
                "/F".to_string()
            ]]
        );

        fake_scheduler::reset(vec![(1, Vec::new())]);
        let error = remove(fake_scheduler::run)
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("could not remove the worker task"),
            "{error}"
        );
        assert!(error.contains("exit code Some(1)"), "{error}");
    }

    // why: the registered-task branch must map the queried definition onto
    // `definition_matches_expected` and the matching note, flag a drifted
    // definition as `Some(false)` with the reinstall warning, and reject a
    // non-UTF-8 query answer as an error instead of guessing a state — a
    // fabricated "matches" verdict would let a stale or tampered
    // registration masquerade as healthy.
    #[cfg(windows)]
    #[test]
    fn status_registered_branch_maps_query_answers_faithfully() {
        let (_root, exe, data) = stub_workspace();
        let definition = expected_definition(&exe, &data);

        fake_scheduler::reset(vec![(0, definition.clone().into_bytes())]);
        let state = status(&exe, &data, fake_scheduler::run).unwrap();
        assert!(state.installed);
        assert_eq!(state.definition_matches_expected, Some(true));
        assert!(
            state.note.contains("matches the required"),
            "{}",
            state.note
        );

        fake_scheduler::reset(vec![(
            0,
            definition
                .replace("<Count>3</Count>", "<Count>9</Count>")
                .into_bytes(),
        )]);
        let state = status(&exe, &data, fake_scheduler::run).unwrap();
        assert!(state.installed);
        assert_eq!(state.definition_matches_expected, Some(false));
        assert!(
            state.note.contains("differs from the required"),
            "{}",
            state.note
        );

        fake_scheduler::reset(vec![(0, vec![0xff, 0xfe, 0xff])]);
        let error = status(&exe, &data, fake_scheduler::run)
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(error.contains("utf-8"), "{error}");
    }

    /// Why: on non-Windows hosts the scheduler stub is the production
    /// runner for autostart; it must refuse loudly with the platform named
    /// and never touch anything — silent success would make autostart look
    /// installed on machines where the Task Scheduler cannot exist.
    #[cfg(not(windows))]
    #[test]
    fn schtasks_stub_refuses_on_non_windows_hosts() {
        assert!(
            schtasks(&["/query"])
                .unwrap_err()
                .to_string()
                .contains("supported only on Windows")
        );
    }
}
