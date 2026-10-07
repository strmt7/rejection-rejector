use anyhow::Result;
#[cfg(any(windows, test))]
use anyhow::{Context, ensure};
use serde::Serialize;
use std::path::{Path, PathBuf};

pub const TASK_NAME: &str = "Rejection Rejector Worker";

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
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(any(windows, test))]
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
fn system32_binary(name: &str) -> Result<PathBuf> {
    let root = std::env::var_os("SystemRoot").context("SystemRoot is unavailable")?;
    let root = PathBuf::from(root);
    ensure!(root.is_absolute(), "SystemRoot must be absolute");
    let path = root.join("System32").join(name);
    ensure!(path.is_file(), "{} is unavailable", path.display());
    Ok(path)
}

#[cfg(windows)]
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

/// MSIX physical paths can change on update; registering them as Task Scheduler
/// executables would silently break the background worker after installation.
#[cfg(any(windows, test))]
fn is_msix_managed_path(executable: &Path) -> bool {
    executable
        .to_string_lossy()
        .replace('\\', "/")
        .split('/')
        .any(|part| part.eq_ignore_ascii_case("WindowsApps"))
}

#[cfg(windows)]
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
fn schtasks(args: &[&str]) -> Result<std::process::Output> {
    std::process::Command::new(system32_binary("schtasks.exe")?)
        .args(args)
        .output()
        .context("Unable to execute Windows Task Scheduler command")
}

#[cfg(windows)]
pub fn install(executable: &Path, data_dir: &Path) -> Result<AutostartStatus> {
    let (executable, data_dir) = canonical_inputs(executable, data_dir)?;
    let user = current_user()?;
    let xml = render_task_xml(&user, &executable, &data_dir)?;
    let xml_path = write_task_xml(&data_dir, &xml)?;
    let xml_arg = xml_path
        .to_str()
        .context("Temporary task definition path is not valid Unicode")?;
    let result = schtasks(&["/Create", "/TN", TASK_NAME, "/XML", xml_arg, "/F"]);
    let _ = std::fs::remove_file(&xml_path);
    let output = result?;
    ensure!(
        output.status.success(),
        "Task Scheduler rejected worker registration (exit code {:?})",
        output.status.code()
    );
    status(&executable, &data_dir)
}

#[cfg(not(windows))]
pub fn install(_executable: &Path, _data_dir: &Path) -> Result<AutostartStatus> {
    Err(anyhow::anyhow!(
        "Windows Task Scheduler autostart is supported only on Windows"
    ))
}

#[cfg(windows)]
pub fn remove() -> Result<()> {
    let output = schtasks(&["/Delete", "/TN", TASK_NAME, "/F"])?;
    ensure!(
        output.status.success(),
        "Task Scheduler could not remove the worker task (exit code {:?})",
        output.status.code()
    );
    Ok(())
}

#[cfg(not(windows))]
pub fn remove() -> Result<()> {
    Err(anyhow::anyhow!(
        "Windows Task Scheduler autostart is supported only on Windows"
    ))
}

#[cfg(windows)]
pub fn status(executable: &Path, data_dir: &Path) -> Result<AutostartStatus> {
    let (executable, data_dir) = canonical_inputs(executable, data_dir)?;
    let output = schtasks(&["/Query", "/TN", TASK_NAME, "/XML"])?;
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
        xml_escape(&expected_arguments(&data_dir)?)
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
    let matches = required.iter().all(|needle| actual.contains(needle));
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
pub fn status(executable: &Path, data_dir: &Path) -> Result<AutostartStatus> {
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
}
