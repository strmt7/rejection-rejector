#[cfg(any(windows, target_os = "macos"))]
use crate::vault::vault_id;
use crate::{store::Store, vault::write_new_private};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

const MAX_ANCHOR_BYTES: u64 = 64 * 1024;
pub const AUDIT_ANCHOR_ENV: &str = "RR_AUDIT_ANCHOR_FILE";
pub const OS_AUDIT_ANCHOR_ENV: &str = "RR_OS_AUDIT_ANCHOR";
const OS_AUDIT_ANCHOR_REQUIRED: &str = "required";
#[cfg(any(windows, target_os = "macos"))]
const OS_AUDIT_ANCHOR_SERVICE: &str = "rejection-rejector.audit-anchor.v1";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditAnchor {
    pub format_version: u32,
    pub application_version: String,
    pub created_at: DateTime<Utc>,
    pub workspace_fingerprint: String,
    pub audit_sequence: i64,
    pub audit_head: String,
}

fn sha256_domain(domain: &[u8], value: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update((value.len() as u64).to_le_bytes());
    digest.update(value);
    crate::hex_lower(digest.finalize())
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn read_small_regular_file(path: &Path) -> Result<Vec<u8>> {
    ensure!(path.is_file(), "{} is missing", path.display());
    ensure!(
        !fs::symlink_metadata(path)?.file_type().is_symlink(),
        "{} must not be a symlink",
        path.display()
    );
    let metadata = fs::metadata(path)?;
    ensure!(
        metadata.len() <= MAX_ANCHOR_BYTES,
        "{} exceeds the audit-anchor size limit",
        path.display()
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    fs::File::open(path)?
        .take(MAX_ANCHOR_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_ANCHOR_BYTES,
        "{} exceeds the audit-anchor size limit",
        path.display()
    );
    Ok(bytes)
}

pub fn workspace_fingerprint(data_dir: &Path) -> Result<String> {
    let path = data_dir.join("vault-id");
    let bytes = read_small_regular_file(&path)?;
    let id = std::str::from_utf8(&bytes)?.trim();
    ensure!(
        uuid::Uuid::parse_str(id).is_ok(),
        "Workspace vault identifier is invalid"
    );
    Ok(sha256_domain(
        b"rejection-rejector-workspace-v1\0",
        id.as_bytes(),
    ))
}

pub fn current(store: &Store, data_dir: &Path) -> Result<AuditAnchor> {
    let (audit_sequence, audit_head) = store.audit_point()?;
    Ok(AuditAnchor {
        format_version: 1,
        application_version: env!("CARGO_PKG_VERSION").into(),
        created_at: Utc::now(),
        workspace_fingerprint: workspace_fingerprint(data_dir)?,
        audit_sequence,
        audit_head,
    })
}

pub fn write_anchor(store: &Store, data_dir: &Path, out: &Path) -> Result<AuditAnchor> {
    ensure!(!out.exists(), "Audit-anchor destination already exists");
    if let Some(parent) = out.parent().filter(|path| !path.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
        ensure!(
            !fs::symlink_metadata(parent)?.file_type().is_symlink(),
            "Audit-anchor parent directory must not be a symlink"
        );
    }
    let anchor = current(store, data_dir)?;
    write_new_private(out, &serde_json::to_vec_pretty(&anchor)?)?;
    Ok(anchor)
}

fn parse_anchor(bytes: &[u8]) -> Result<AuditAnchor> {
    ensure!(
        bytes.len() as u64 <= MAX_ANCHOR_BYTES,
        "Audit anchor exceeds the size limit"
    );
    let anchor: AuditAnchor =
        serde_json::from_slice(bytes).context("Audit-anchor JSON is invalid")?;
    ensure!(
        anchor.format_version == 1,
        "Unsupported audit-anchor format"
    );
    ensure!(
        anchor.audit_sequence >= 0,
        "Audit-anchor sequence must be non-negative"
    );
    ensure!(
        valid_hash(&anchor.workspace_fingerprint),
        "Audit-anchor workspace fingerprint is invalid"
    );
    ensure!(
        valid_hash(&anchor.audit_head),
        "Audit-anchor journal hash is invalid"
    );
    ensure!(
        !anchor.application_version.trim().is_empty() && anchor.application_version.len() <= 128,
        "Audit-anchor application version is invalid"
    );
    Ok(anchor)
}

pub fn read_anchor(path: &Path) -> Result<AuditAnchor> {
    parse_anchor(&read_small_regular_file(path)?)
}

fn verify_anchor_value(store: &Store, data_dir: &Path, anchor: &AuditAnchor) -> Result<()> {
    ensure!(
        anchor.workspace_fingerprint == workspace_fingerprint(data_dir)?,
        "Audit anchor belongs to another workspace"
    );
    store
        .verify_audit_extension(anchor.audit_sequence, &anchor.audit_head)
        .map(|_| ())
}

pub fn verify_anchor(store: &Store, data_dir: &Path, path: &Path) -> Result<AuditAnchor> {
    let anchor = read_anchor(path)?;
    verify_anchor_value(store, data_dir, &anchor)?;
    Ok(anchor)
}

/// Interpret the OS audit-anchor requirement from its raw environment value.
///
/// Inputs: `raw` — `None` when unset (not required), otherwise the exact
/// value read from the environment. Output: `Ok(true)` only for the exact
/// required literal; any other value fails closed with an error rather than
/// silently disabling rollback protection.
fn interpret_os_anchor_required(raw: Option<&str>) -> Result<bool> {
    match raw {
        Some(OS_AUDIT_ANCHOR_REQUIRED) => Ok(true),
        Some(value) => anyhow::bail!(
            "{OS_AUDIT_ANCHOR_ENV} must be exactly '{OS_AUDIT_ANCHOR_REQUIRED}' when set, not {value:?}"
        ),
        None => Ok(false),
    }
}

pub fn os_anchor_required() -> Result<bool> {
    match std::env::var(OS_AUDIT_ANCHOR_ENV) {
        Ok(value) => interpret_os_anchor_required(Some(&value)),
        Err(std::env::VarError::NotPresent) => interpret_os_anchor_required(None),
        Err(error) => Err(anyhow::anyhow!(
            "Could not read {OS_AUDIT_ANCHOR_ENV}: {error}"
        )),
    }
}

#[cfg(any(windows, target_os = "macos"))]
fn os_anchor_entry(data_dir: &Path) -> Result<keyring::Entry> {
    let id = vault_id(data_dir)?;
    keyring::Entry::new(OS_AUDIT_ANCHOR_SERVICE, &id)
        .context("Cannot access the OS credential-store audit anchor")
}

#[cfg(any(windows, target_os = "macos"))]
fn read_os_anchor(data_dir: &Path) -> Result<Option<AuditAnchor>> {
    let entry = os_anchor_entry(data_dir)?;
    match entry.get_password() {
        Ok(serialized) => parse_anchor(serialized.as_bytes()).map(Some),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(anyhow::anyhow!(
            "OS credential-store audit anchor is unavailable: {error}"
        )),
    }
}

#[cfg(any(windows, target_os = "macos"))]
fn write_os_anchor(data_dir: &Path, anchor: &AuditAnchor) -> Result<()> {
    let serialized = serde_json::to_string(anchor)?;
    ensure!(
        serialized.len() as u64 <= MAX_ANCHOR_BYTES,
        "OS audit anchor exceeds the size limit"
    );
    os_anchor_entry(data_dir)?
        .set_password(&serialized)
        .context("Could not persist the OS-protected audit anchor")
}

/// Verify the OS credential-store anchor when enterprise rollback protection is
/// explicitly required. An empty credential is allowed only for first-time
/// bootstrap; unsupported platforms fail closed rather than claiming coverage.
pub fn verify_os_anchor_if_required(store: &Store, data_dir: &Path) -> Result<Option<AuditAnchor>> {
    if !os_anchor_required()? {
        return Ok(None);
    }

    #[cfg(any(windows, target_os = "macos"))]
    {
        let anchor = read_os_anchor(data_dir)?;
        if let Some(anchor) = &anchor {
            verify_anchor_value(store, data_dir, anchor)?;
        }
        Ok(anchor)
    }

    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = (store, data_dir);
        anyhow::bail!(
            "{OS_AUDIT_ANCHOR_ENV}=required is supported only with the Windows/macOS OS credential store"
        )
    }
}

/// Advance the OS-protected anchor monotonically. Existing anchors are treated
/// as trust roots: the database must prove that its current audit head extends
/// the prior sequence/hash before the credential may be updated.
pub fn checkpoint_os_anchor_if_required(
    store: &Store,
    data_dir: &Path,
) -> Result<Option<AuditAnchor>> {
    if !os_anchor_required()? {
        return Ok(None);
    }

    #[cfg(any(windows, target_os = "macos"))]
    {
        let workspace_fingerprint = workspace_fingerprint(data_dir)?;
        let current_anchor = match read_os_anchor(data_dir)? {
            Some(previous) => {
                ensure!(
                    previous.workspace_fingerprint == workspace_fingerprint,
                    "OS audit anchor belongs to another workspace"
                );
                let (audit_sequence, audit_head) =
                    store.verify_audit_extension(previous.audit_sequence, &previous.audit_head)?;
                if audit_sequence == previous.audit_sequence {
                    ensure!(
                        audit_head == previous.audit_head,
                        "Audit head changed without advancing the trusted sequence"
                    );
                    return Ok(Some(previous));
                }
                AuditAnchor {
                    format_version: 1,
                    application_version: env!("CARGO_PKG_VERSION").into(),
                    created_at: Utc::now(),
                    workspace_fingerprint,
                    audit_sequence,
                    audit_head,
                }
            }
            None => current(store, data_dir)?,
        };
        write_os_anchor(data_dir, &current_anchor)?;
        Ok(Some(current_anchor))
    }

    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = (store, data_dir);
        anyhow::bail!(
            "{OS_AUDIT_ANCHOR_ENV}=required is supported only with the Windows/macOS OS credential store"
        )
    }
}

/// Verify the externally persisted anchor configured for startup rollback
/// detection. The anchor must be stored outside the rollback domain for this to
/// provide meaningful protection.
pub fn verify_configured_anchor(store: &Store, data_dir: &Path) -> Result<Option<AuditAnchor>> {
    let Some(value) = std::env::var_os(AUDIT_ANCHOR_ENV) else {
        return Ok(None);
    };
    let path = PathBuf::from(value);
    ensure!(
        path.is_absolute(),
        "{AUDIT_ANCHOR_ENV} must be an absolute path"
    );
    verify_anchor(store, data_dir, &path)
        .with_context(|| {
            format!(
                "Configured external audit anchor failed: {}",
                path.display()
            )
        })
        .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        types::{Source, Stub},
        vault::{Vault, private_dir, write_new_private},
    };

    fn workspace(root: &Path) -> (Store, PathBuf) {
        let dir = root.join("workspace");
        private_dir(&dir).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        write_new_private(&dir.join("vault-id"), id.as_bytes()).unwrap();
        let store = Store::open(&dir.join("state.sqlite3"), Vault::random()).unwrap();
        (store, dir)
    }

    #[test]
    fn anchor_parser_rejects_invalid_or_oversized_records() {
        assert!(parse_anchor(b"{}").is_err());
        let oversized = vec![b'x'; MAX_ANCHOR_BYTES as usize + 1];
        assert!(parse_anchor(&oversized).is_err());
    }

    #[test]
    fn external_anchor_accepts_extension_and_rejects_substitution() {
        let root = tempfile::tempdir().unwrap();
        let (mut store, dir) = workspace(root.path());
        store
            .insert_stub(
                Stub {
                    account: "me@example.com".into(),
                    provider_id: "one".into(),
                    thread_id: "thread".into(),
                    source: Source::Gmail,
                },
                Utc::now(),
            )
            .unwrap();
        let anchor_path = root.path().join("external-anchor.json");
        let first = write_anchor(&store, &dir, &anchor_path).unwrap();
        verify_anchor(&store, &dir, &anchor_path).unwrap();

        store.log("test.extension", None, "newer event").unwrap();
        let later = current(&store, &dir).unwrap();
        assert!(later.audit_sequence > first.audit_sequence);
        assert_ne!(later.audit_head, first.audit_head);
        verify_anchor(&store, &dir, &anchor_path).unwrap();

        let mut forged = first;
        forged.audit_sequence = later.audit_sequence;
        let forged_path = root.path().join("forged.json");
        write_new_private(&forged_path, &serde_json::to_vec_pretty(&forged).unwrap()).unwrap();
        assert!(verify_anchor(&store, &dir, &forged_path).is_err());
    }

    #[test]
    fn another_workspace_cannot_reuse_an_anchor() {
        let root = tempfile::tempdir().unwrap();
        let (store_a, dir_a) = workspace(root.path());
        let anchor = root.path().join("anchor.json");
        write_anchor(&store_a, &dir_a, &anchor).unwrap();

        let other_root = tempfile::tempdir().unwrap();
        let (store_b, dir_b) = workspace(other_root.path());
        assert!(verify_anchor(&store_b, &dir_b, &anchor).is_err());
    }
}

#[cfg(test)]
mod anchor_boundary_tests {
    use super::*;
    use std::io::Write as _;

    /// The environment requirement must fail closed: only the exact literal
    /// enables enforcement, anything else errors instead of disabling it.
    #[test]
    fn os_anchor_requirement_fails_closed_on_any_other_value() {
        assert!(!interpret_os_anchor_required(None).unwrap());
        assert!(interpret_os_anchor_required(Some(OS_AUDIT_ANCHOR_REQUIRED)).unwrap());
        assert!(interpret_os_anchor_required(Some("REQUIRED")).is_err());
        assert!(interpret_os_anchor_required(Some("")).is_err());
        assert!(interpret_os_anchor_required(Some("required ")).is_err());
        assert!(interpret_os_anchor_required(Some(" required")).is_err());
        assert!(interpret_os_anchor_required(Some("1")).is_err());
    }

    /// Anchor files are a security boundary: missing, non-regular and
    /// oversized files must be rejected; exact-limit files round-trip.
    #[test]
    fn anchor_file_reader_rejects_missing_oversized_and_non_regular_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("missing");
        assert!(read_small_regular_file(&missing).is_err());

        let as_dir = dir.path().join("dir");
        std::fs::create_dir(&as_dir).unwrap();
        assert!(read_small_regular_file(&as_dir).is_err());

        let oversized = dir.path().join("big");
        let mut f = std::fs::File::create(&oversized).unwrap();
        f.write_all(&vec![0u8; (MAX_ANCHOR_BYTES + 1) as usize])
            .unwrap();
        drop(f);
        assert!(read_small_regular_file(&oversized).is_err());

        let exact = dir.path().join("exact");
        let payload = vec![7u8; MAX_ANCHOR_BYTES as usize];
        std::fs::write(&exact, &payload).unwrap();
        assert_eq!(read_small_regular_file(&exact).unwrap(), payload);
    }

    /// Symlinked anchors must be rejected outright: a link could redirect
    /// the trust root to attacker-controlled content.
    #[cfg(unix)]
    #[test]
    fn anchor_file_reader_rejects_symlinks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target");
        std::fs::write(&target, b"trusted").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_small_regular_file(&link).is_err());
    }
}
