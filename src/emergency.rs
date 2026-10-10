use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};

pub const EMERGENCY_STOP_FILE_ENV: &str = "RR_EMERGENCY_STOP_FILE";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct EmergencyStopStatus {
    pub configured: bool,
    pub active: bool,
    pub reason: String,
}

/// Inspect the externally managed emergency-stop sentinel.
///
/// The configured path is intentionally not returned: absolute workstation paths
/// can contain usernames or deployment topology and do not belong in health output.
pub fn status() -> Result<EmergencyStopStatus> {
    evaluate(std::env::var_os(EMERGENCY_STOP_FILE_ENV))
}

/// Privacy-safe status for health/readiness surfaces. A malformed or unreadable
/// configured sentinel is treated as active so monitoring agrees with the
/// fail-closed dispatch boundary without disclosing the configured path.
///
/// This fail-closed approach ensures that any uncertainty about the emergency-stop
/// sentinel state results in blocking automatic sends, prioritizing safety over
/// availability in accordance with the system's security objectives.
pub fn status_fail_closed() -> EmergencyStopStatus {
    fail_closed_from(status())
}

/// Map a sentinel inspection outcome onto the privacy-safe health state.
///
/// Inputs: the inspection result produced by [`evaluate`]/[`status`]. Output:
/// the health state; every inspection error is reported as configured+active so
/// monitoring agrees with the fail-closed dispatch boundary.
fn fail_closed_from(result: Result<EmergencyStopStatus>) -> EmergencyStopStatus {
    match result {
        Ok(status) => status,
        Err(_) => EmergencyStopStatus {
            configured: true,
            active: true,
            reason: "configuration_error".into(),
        },
    }
}

pub fn ensure_dispatch_allowed() -> Result<()> {
    ensure_dispatch_allowed_for(std::env::var_os(EMERGENCY_STOP_FILE_ENV))
}

/// Re-evaluate the sentinel at call time and block dispatch while it is active.
///
/// Inputs: the raw environment value naming the sentinel path. Output: `Ok(())`
/// only when the sentinel is a regular file that is currently absent; an active
/// sentinel or an uninspectable configuration returns `Err` (fail closed), and
/// the state is never cached between calls.
fn ensure_dispatch_allowed_for(value: Option<OsString>) -> Result<()> {
    let status = evaluate(value)?;
    ensure!(
        !status.active,
        "Enterprise emergency stop is active; no Gmail request was attempted"
    );
    Ok(())
}

fn evaluate(value: Option<OsString>) -> Result<EmergencyStopStatus> {
    let Some(value) = value else {
        return Ok(EmergencyStopStatus {
            configured: false,
            active: false,
            reason: "not_configured".into(),
        });
    };
    ensure!(
        !value.is_empty(),
        "{EMERGENCY_STOP_FILE_ENV} must not be empty"
    );
    let path = PathBuf::from(value);
    ensure!(
        path.is_absolute(),
        "{EMERGENCY_STOP_FILE_ENV} must be an absolute path"
    );
    status_for_path(&path)
}

fn status_for_path(path: &Path) -> Result<EmergencyStopStatus> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                !metadata.file_type().is_symlink(),
                "Emergency-stop sentinel must not be a symlink"
            );
            ensure!(
                metadata.is_file(),
                "Emergency-stop sentinel exists but is not a regular file"
            );
            Ok(EmergencyStopStatus {
                configured: true,
                active: true,
                reason: "sentinel_present".into(),
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(EmergencyStopStatus {
            configured: true,
            active: false,
            reason: "sentinel_absent".into(),
        }),
        Err(error) => Err(anyhow::anyhow!(
            "Emergency-stop sentinel could not be inspected safely: {error}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unconfigured_is_inactive() {
        assert_eq!(
            evaluate(None).unwrap(),
            EmergencyStopStatus {
                configured: false,
                active: false,
                reason: "not_configured".into(),
            }
        );
    }

    #[test]
    fn configured_file_activates_and_removal_clears() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("stop");
        assert!(!status_for_path(&path).unwrap().active);
        fs::write(&path, b"incident").unwrap();
        let active = status_for_path(&path).unwrap();
        assert!(active.configured);
        assert!(active.active);
        fs::remove_file(&path).unwrap();
        assert!(!status_for_path(&path).unwrap().active);
    }

    #[test]
    fn invalid_or_non_regular_sentinels_fail_closed() {
        assert!(evaluate(Some(OsString::from("relative.stop"))).is_err());
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("stop-directory");
        fs::create_dir(&directory).unwrap();
        assert!(status_for_path(&directory).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let target = root.path().join("target");
            fs::write(&target, b"stop").unwrap();
            let link = root.path().join("link");
            symlink(&target, &link).unwrap();
            assert!(status_for_path(&link).is_err());
        }
    }

    #[test]
    fn environment_value_is_not_disclosed_by_status() {
        let root = tempfile::tempdir().unwrap();
        let sensitive = root.path().join("sensitive-user-path-stop");
        let status = evaluate(Some(sensitive.as_os_str().to_os_string())).unwrap();
        let serialized = serde_json::to_string(&status).unwrap();
        assert!(!serialized.contains("sensitive-user-path-stop"));
    }

    #[test]
    fn malformed_configuration_maps_to_fail_closed_health_state() {
        // Why: any inspection failure must map to a configured+active health
        // state so monitoring agrees with the dispatch gate; an unconfigured
        // workspace maps to its inspected state instead. Both mapping arms run
        // so a swapped mapping (fail-open on errors) breaks the assertions.
        for (value, expect_active, expect_reason) in [
            (
                Some(OsString::from("relative.stop")),
                true,
                "configuration_error",
            ),
            (None, false, "not_configured"),
        ] {
            let status = fail_closed_from(evaluate(value.clone()));
            assert_eq!(status.active, expect_active);
            assert_eq!(status.reason, expect_reason);
        }
    }

    /// Why: the dispatch gate must consult the sentinel at each call; caching
    /// the state would let an emergency stop raised between calls go unheard and
    /// an emergency stop cleared between calls stay stuck. Both transitions are
    /// asserted so a stale snapshot fails the test.
    /// Inputs: sentinel path inside a temporary directory. Output: gate passes
    /// while the sentinel is absent, blocks with a no-network message while it
    /// exists, and passes again after removal.
    #[test]
    fn dispatch_gate_rechecks_the_sentinel_immediately_before_each_dispatch() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("stop");
        let value = Some(path.as_os_str().to_os_string());

        ensure_dispatch_allowed_for(value.clone()).unwrap();

        fs::write(&path, b"incident").unwrap();
        let blocked = ensure_dispatch_allowed_for(value.clone())
            .expect_err("active sentinel must block dispatch");
        assert!(
            blocked
                .to_string()
                .contains("no Gmail request was attempted"),
            "unexpected error: {blocked}"
        );
        assert!(status_for_path(&path).unwrap().active);

        fs::remove_file(&path).unwrap();
        ensure_dispatch_allowed_for(value).unwrap();
    }

    /// Why: a sentinel path that cannot be inspected safely must surface as an
    /// error (and therefore fail closed) rather than being mistaken for an
    /// absent sentinel; silently allowing dispatch after a failed inspection
    /// would invert the emergency-stop guarantee.
    /// Inputs: absolute paths that the OS refuses to stat. Output: inspection
    /// errors, the fail-closed mapping reports active, and the dispatch gate
    /// propagates the error instead of allowing the send.
    #[test]
    fn uninspectable_sentinel_paths_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        #[cfg(windows)]
        let broken = root.path().join("in<valid-name");
        #[cfg(unix)]
        let broken = {
            // A parent component that is a regular file yields ENOTDIR, which is
            // deliberately not the NotFound case handled as "absent".
            let file = root.path().join("plain-file");
            fs::write(&file, b"x").unwrap();
            file.join("stop")
        };
        let value = Some(broken.as_os_str().to_os_string());

        assert!(evaluate(value.clone()).is_err());
        let status = fail_closed_from(evaluate(value.clone()));
        assert!(status.active);
        assert_eq!(status.reason, "configuration_error");
        assert!(ensure_dispatch_allowed_for(value).is_err());
    }

    /// Why: with no sentinel configured the public gate must allow dispatch and
    /// report an inactive status; an inverted default would silently disable
    /// every automatic send. Relies on the suite never setting the environment
    /// variable (the same assumption as the diagnostics health test).
    /// Inputs: ambient environment without `RR_EMERGENCY_STOP_FILE`.
    /// Output: gate passes; status reports configured=false, active=false.
    #[test]
    fn unconfigured_gate_allows_dispatch_and_reports_inactive() {
        if std::env::var_os(EMERGENCY_STOP_FILE_ENV).is_some() {
            return;
        }
        ensure_dispatch_allowed().unwrap();
        let status = status_fail_closed();
        assert!(!status.configured);
        assert!(!status.active);
        assert_eq!(status.reason, "not_configured");
    }
}
