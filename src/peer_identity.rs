//! Loopback listener peer identity for the local model runtime.
//!
//! why (security review finding 7): literal loopback location is not
//! runtime identity. A distinct local user can prebind the configured
//! model port before the real runtime starts; the application must never
//! send private mailbox or candidate content to a listener it cannot
//! attribute. Identity is established from OS socket ownership: the
//! listening socket's owning process must be this process, the runtime
//! process this application launched, or a process whose executable is the
//! configured runtime binary. Anything else — including an uninspectable
//! socket — fails closed and disables private inference.
//!
//! Inputs: module functions take a loopback port or process id. Output:
//! `PeerVerifier` bundles the injectable inspection functions;
//! production uses `production`, tests inject fakes. No `unsafe` is used;
//! inspection shells out to documented OS interfaces (`netstat`, CIM) on
//! Windows and reads procfs on Linux.

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::Command;

/// Resolve the process id owning the listening socket on `port`.
///
/// Inputs: `port` — loopback TCP port. Output: `Result<Option<u32>>` — the
/// owning process id, or `None` when nothing listens there; inspection
/// failures are errors so callers can fail closed.
pub(crate) type PeerOwnerFn = fn(u16) -> Result<Option<u32>>;

/// Resolve the executable image path of a process.
///
/// Inputs: `pid` — process id. Output: `Result<Option<PathBuf>>` — the
/// executable path, or `None` when the process is gone or its image is not
/// resolvable.
pub(crate) type PeerImageFn = fn(u32) -> Result<Option<PathBuf>>;

/// Injectable loopback peer-identity inspector.
#[derive(Clone, Copy)]
pub(crate) struct PeerVerifier {
    /// Socket-ownership lookup.
    pub owner: PeerOwnerFn,
    /// Process-image lookup.
    pub image: PeerImageFn,
}

/// Loopback ports this process itself is listening on.
///
/// why (security review finding 7): a listener bound by this process needs
/// no OS inspection to be attributable — the knowledge is direct and exact.
/// Registration is only ever advisory for THIS process's own sockets; a
/// distinct local user's process cannot register into it, so it can never
/// widen the trust set beyond "we bound this port ourselves".
static LOCAL_LISTENERS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<u16>>> =
    std::sync::OnceLock::new();

/// Record that this process itself listens on a loopback port.
///
/// Inputs: `port` — the loopback port bound by this process. Output: none.
/// Safe by construction: the registry is per-process state describing this
/// process's own sockets only.
pub fn register_local_listener(port: u16) {
    if let Ok(mut listeners) = LOCAL_LISTENERS
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
        .lock()
    {
        listeners.insert(port);
    }
}

/// Drop a port from the in-process listener registry.
///
/// why (security review finding 7): tests that simulate a foreign-owned
/// port need the OS-inspection path to run instead of the in-process
/// short-circuit. Safe by construction: forgetting a port can only remove
/// trust, never widen it.
///
/// Inputs: `port` — the loopback port to forget. Output: none.
pub fn forget_local_listener(port: u16) {
    if let Ok(mut listeners) = LOCAL_LISTENERS
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
        .lock()
    {
        listeners.remove(&port);
    }
}

/// Whether this process itself listens on `port`.
///
/// Inputs: `port` — loopback port. Output: `bool` — true only for ports
/// this process registered as its own.
fn is_local_listener(port: u16) -> bool {
    LOCAL_LISTENERS
        .get()
        .and_then(|set| set.lock().ok())
        .is_some_and(|set| set.contains(&port))
}

/// The production inspector for the current platform.
///
/// Inputs: none. Output: `PeerVerifier` — OS-backed inspection functions.
pub(crate) fn production() -> PeerVerifier {
    PeerVerifier {
        owner: listener_owner_pid,
        image: process_image,
    }
}

/// Whether a loopback listener is attributable to a trusted principal.
///
/// Inputs: `port` — the listener port; `verifier` — inspector; `self_pid` —
/// the current process id; `child_pid` — runtime pid when this application
/// launched it (0 otherwise); `runtime_exe` — configured runtime executable
/// for external daemons. Output: `Result<()>` — `Ok` only when the owner is
/// this process, the launched child, or the configured runtime image;
/// every unknown or uninspectable state is an error (fail closed).
pub(crate) fn ensure_trusted_listener(
    port: u16,
    verifier: &PeerVerifier,
    self_pid: u32,
    child_pid: u32,
    runtime_exe: &std::path::Path,
) -> Result<()> {
    if is_local_listener(port) {
        return Ok(());
    }
    let owner = (verifier.owner)(port)?
        .with_context(|| format!("no attributable listener owns port {port}"))?;
    if owner == self_pid || (child_pid != 0 && owner == child_pid) {
        return Ok(());
    }
    let image = (verifier.image)(owner)?
        .with_context(|| format!("listener owner {owner} has no resolvable executable"))?;
    let Ok(actual) = image.canonicalize() else {
        anyhow::bail!(
            "loopback listener on the model port has an unresolvable image; refusing private inference"
        )
    };
    let Ok(expected) = runtime_exe.canonicalize() else {
        anyhow::bail!("configured runtime executable is unresolvable; refusing private inference")
    };
    ensure_same_image(&actual, &expected, owner)
}

/// Compare a listener owner's image against the configured runtime image.
///
/// Inputs: `actual` — canonicalized owner image; `expected` — canonicalized
/// configured image; `owner` — owner pid for the error message. Output:
/// `Result<()>` — `Ok` on an exact match (case-insensitive on Windows);
/// error otherwise.
fn ensure_same_image(
    actual: &std::path::Path,
    expected: &std::path::Path,
    owner: u32,
) -> Result<()> {
    #[cfg(windows)]
    let matched = actual
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected.to_string_lossy());
    #[cfg(not(windows))]
    let matched = actual == expected;
    anyhow::ensure!(
        matched,
        "loopback listener on the model port is owned by pid {owner} with a foreign executable; refusing private inference"
    );
    Ok(())
}

/// Resolve the owner of the listening socket on a loopback port.
///
/// Inputs: `port` — loopback TCP port. Output: `Result<Option<u32>>` — the
/// owning pid, `None` when nothing listens; errors when inspection is not
/// possible on this platform (callers fail closed).
pub(crate) fn listener_owner_pid(port: u16) -> Result<Option<u32>> {
    #[cfg(windows)]
    {
        let output = Command::new("netstat")
            .args(["-ano", "-p", "tcp"])
            .output()
            .context("cannot inspect TCP listeners (netstat)")?;
        let text = String::from_utf8_lossy(&output.stdout);
        Ok(parse_netstat_owner(&text, port))
    }
    #[cfg(target_os = "linux")]
    {
        let tcp = std::fs::read_to_string("/proc/net/tcp").context("cannot read /proc/net/tcp")?;
        let tcp6 =
            std::fs::read_to_string("/proc/net/tcp6").context("cannot read /proc/net/tcp6")?;
        let inode = parse_proc_inode(&tcp, port)
            .or_else(|| parse_proc_inode(&tcp6, port))
            .context("no listening socket on the model port")?;
        proc_owner_by_inode(inode).context("cannot attribute the listening socket")
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = port;
        anyhow::bail!("loopback peer identity is not inspectable on this platform")
    }
}

/// Resolve a process id to its executable image path.
///
/// Inputs: `pid` — process id. Output: `Result<Option<PathBuf>>` — the
/// executable path or `None` when unresolvable; errors when inspection is
/// not possible (callers fail closed).
pub(crate) fn process_image(pid: u32) -> Result<Option<PathBuf>> {
    #[cfg(windows)]
    {
        let filter = format!("ProcessId={pid}");
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-CimInstance Win32_Process -Filter $args[0]).ExecutablePath",
                &filter,
            ])
            .output()
            .context("cannot inspect process image (CIM)")?;
        let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        Ok(if text.is_empty() {
            None
        } else {
            Some(PathBuf::from(text))
        })
    }
    #[cfg(target_os = "linux")]
    {
        match std::fs::read_link(format!("/proc/{pid}/exe")) {
            Ok(path) => Ok(Some(path)),
            Err(_) => Ok(None),
        }
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = pid;
        anyhow::bail!("loopback peer identity is not inspectable on this platform")
    }
}

/// Parse `netstat -ano -p tcp` output for a listening loopback port.
///
/// Inputs: `text` — netstat output; `port` — loopback port. Output:
/// `Option<u32>` — the owning pid of the LISTENING row for 127.0.0.1 or
/// [::1] on `port`.
fn parse_netstat_owner(text: &str, port: u16) -> Option<u32> {
    let v4 = format!("127.0.0.1:{port}");
    let v6 = format!("[::1]:{port}");
    text.lines().find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 {
            return None;
        }
        let local = fields[1].trim_start_matches("0.0.0.0:");
        if (fields[1] == v4 || fields[1] == v6 || local == format!("{port}"))
            && fields[3] == "LISTENING"
        {
            fields[4].parse::<u32>().ok()
        } else {
            None
        }
    })
}

/// Parse `/proc/net/tcp{,6}` for the listening socket's inode on `port`.
///
/// Inputs: `text` — procfs table text; `port` — loopback port. Output:
/// `Option<u64>` — the socket inode of the LISTEN (0A) row.
#[cfg(target_os = "linux")]
fn parse_proc_inode(text: &str, port: u16) -> Option<u64> {
    let suffix = format!(":{port:04X}");
    text.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            return None;
        }
        let local = fields[1];
        let is_loopback = local.starts_with("0100007F:")
            || local.starts_with("00000000000000000000000001000000:");
        if is_loopback && local.ends_with(&suffix) && fields[3] == "0A" {
            fields[9].parse::<u64>().ok()
        } else {
            None
        }
    })
}

/// Find the process holding a socket inode through procfs.
///
/// Inputs: `inode` — socket inode. Output: `Result<Option<u32>>` — the
/// owning pid.
#[cfg(target_os = "linux")]
fn proc_owner_by_inode(inode: u64) -> Result<Option<u32>> {
    let want = format!("socket:[{inode}]");
    for entry in std::fs::read_dir("/proc").context("cannot read /proc")? {
        let Ok(entry) = entry else { continue };
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if std::fs::read_link(fd.path()).is_ok_and(|link| link.to_string_lossy() == want) {
                return Ok(Some(pid));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_owner(_port: u16) -> Result<Option<u32>> {
        Ok(Some(4242))
    }

    fn fake_image(_pid: u32) -> Result<Option<PathBuf>> {
        Ok(Some(PathBuf::from("/opt/ollama/ollama")))
    }

    // why (security review finding 7): an unrelated listener owner must be
    // refused; these tests pin the decision table of ensure_trusted_listener.
    #[test]
    fn owner_is_trusted_when_it_is_this_process() {
        let verifier = PeerVerifier {
            owner: fake_owner,
            image: fake_image,
        };
        assert!(
            ensure_trusted_listener(11434, &verifier, 4242, 0, std::path::Path::new("x")).is_ok()
        );
    }

    #[test]
    fn owner_is_trusted_when_it_is_the_launched_child() {
        let verifier = PeerVerifier {
            owner: fake_owner,
            image: fake_image,
        };
        assert!(
            ensure_trusted_listener(11434, &verifier, 1, 4242, std::path::Path::new("x")).is_ok()
        );
    }

    #[test]
    fn foreign_owner_without_matching_image_is_refused() {
        let verifier = PeerVerifier {
            owner: fake_owner,
            image: |_| Ok(Some(PathBuf::from("/tmp/impostor"))),
        };
        let error = ensure_trusted_listener(
            11434,
            &verifier,
            1,
            0,
            std::path::Path::new("/opt/ollama/ollama"),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("refusing private inference"), "{error}");
    }

    #[test]
    fn unattributable_listener_fails_closed() {
        let verifier = PeerVerifier {
            owner: |_| Ok(None),
            image: fake_image,
        };
        assert!(
            ensure_trusted_listener(11434, &verifier, 1, 0, std::path::Path::new("x")).is_err()
        );
        let verifier = PeerVerifier {
            owner: |_| anyhow::bail!("inspection unavailable"),
            image: fake_image,
        };
        assert!(
            ensure_trusted_listener(11434, &verifier, 1, 0, std::path::Path::new("x")).is_err()
        );
    }

    #[test]
    fn netstat_parsing_finds_the_listening_row() {
        let text = concat!(
            "Active Connections\n",
            "  Proto  Local Address          Foreign Address        State           PID\n",
            "  TCP    127.0.0.1:11434       0.0.0.0:0              LISTENING       4242\n",
            "  TCP    127.0.0.1:11434       10.0.0.5:52222         ESTABLISHED     9999\n",
        );
        assert_eq!(parse_netstat_owner(text, 11434), Some(4242));
        assert_eq!(parse_netstat_owner(text, 9999), None);
    }
}
