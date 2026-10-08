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
    match status() {
        Ok(status) => status,
        Err(_) => EmergencyStopStatus {
            configured: true,
            active: true,
            reason: "configuration_error".into(),
        },
    }
}

pub fn ensure_dispatch_allowed() -> Result<()> {
    let status = status()?;
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
        let status = match evaluate(Some(OsString::from("relative.stop"))) {
            Ok(value) => value,
            Err(_) => EmergencyStopStatus {
                configured: true,
                active: true,
                reason: "configuration_error".into(),
            },
        };
        assert!(status.active);
        assert_eq!(status.reason, "configuration_error");
    }
}
