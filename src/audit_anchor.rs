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
/// Environment variable naming the external audit-anchor file.
///
/// Inputs: none (constant). Output: `&str` — the variable name read by the
/// anchor checks.
pub const AUDIT_ANCHOR_ENV: &str = "RR_AUDIT_ANCHOR_FILE";
/// Environment variable selecting the OS-level audit anchor.
///
/// Inputs: none (constant). Output: `&str` — the variable name for the
/// platform anchor.
pub const OS_AUDIT_ANCHOR_ENV: &str = "RR_OS_AUDIT_ANCHOR";
const OS_AUDIT_ANCHOR_REQUIRED: &str = "required";
#[cfg(any(windows, target_os = "macos"))]
pub(crate) const OS_AUDIT_ANCHOR_SERVICE: &str = "rejection-rejector.audit-anchor.v1";

/// External anchor document bound to the workspace audit chain.
///
/// Inputs: none (plain struct). Output: the anchor format version,
/// application version, creation time, workspace fingerprint and the
/// anchored audit sequence and head.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditAnchor {
    /// Schema version of the anchor record.
    pub format_version: u32,
    /// Application version that wrote the anchor.
    pub application_version: String,
    /// Timestamp of anchor creation.
    pub created_at: DateTime<Utc>,
    /// Fingerprint of the workspace the anchor protects.
    pub workspace_fingerprint: String,
    /// Audit sequence the anchor pins.
    pub audit_sequence: i64,
    /// Audit head hash the anchor pins.
    pub audit_head: String,
}

/// Hash one value under a domain tag.
///
/// Inputs: `domain` — domain-separation tag; `value` — bytes to hash. Output:
/// `String` — the lowercase hex SHA-256 of the tagged, length-prefixed value.
fn sha256_domain(domain: &[u8], value: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update((value.len() as u64).to_le_bytes());
    digest.update(value);
    crate::hex_lower(digest.finalize())
}

/// Whether a string is a well-formed audit hash.
///
/// Inputs: `value` — candidate hash. Output: `true` only for exactly 64 ASCII
/// hex characters.
fn valid_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Read one small regular file, refusing symlinks.
///
/// Inputs: `path` — file to read (must exist, be regular, and not be a
/// symlink). Output: `Result<Vec<u8>>` — the file bytes within the size limit;
/// error otherwise.
fn read_small_regular_file(path: &Path) -> Result<Vec<u8>> {
    ensure!(path.is_file(), "{} is missing", path.display());
    ensure!(
        !fs::symlink_metadata(path)?.file_type().is_symlink(),
        "{} must not be a symlink",
        path.display()
    );
    // The authoritative size gate runs on the bytes actually read (at most one
    // byte over the limit), so growth between metadata and read can never slip
    // past the check.
    let mut bytes = Vec::new();
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

/// Read the workspace fingerprint from the vault identifier file.
///
/// Inputs: `data_dir` — workspace directory containing `vault-id`. Output: `Result<String>`
/// — the trimmed UUID fingerprint; errors when the file is missing or the
/// identifier is invalid.
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

/// Build the current audit anchor from live workspace state.
///
/// Inputs: `store` — open store supplying the audit point; `data_dir` —
/// workspace directory for the fingerprint. Output: `Result<AuditAnchor>`
/// binding sequence, head hash, versions, timestamp and workspace fingerprint.
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

/// Write the current audit anchor to a new file.
///
/// Inputs: `store` — open store supplying the audit point; `data_dir` —
/// workspace directory; `out` — destination file to create. Output: `Result<AuditAnchor>`
/// — the anchor that was written; errors when the destination exists or any
/// safety check fails.
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

/// Parse and validate one serialized audit anchor.
///
/// Inputs: `bytes` — anchor JSON bytes within the size limit. Output:
/// `Result<AuditAnchor>` — the parsed anchor; error for oversized, invalid, or
/// out-of-range anchors.
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

/// Parse an audit anchor file from disk.
///
/// Inputs: `path` — anchor file to read. Output: `Result<AuditAnchor>`; errors
/// on unreadable or malformed files.
pub fn read_anchor(path: &Path) -> Result<AuditAnchor> {
    parse_anchor(&read_small_regular_file(path)?)
}

/// Verify one anchor against the workspace and audit journal.
///
/// Inputs: `store` — store whose journal is checked; `data_dir` — workspace
/// directory fingerprinted; `anchor` — anchor to verify. Output: `Result<()>` —
/// `Ok` when the anchor belongs to this workspace and extends the journal;
/// error otherwise (fail closed).
fn verify_anchor_value(store: &Store, data_dir: &Path, anchor: &AuditAnchor) -> Result<()> {
    ensure!(
        anchor.workspace_fingerprint == workspace_fingerprint(data_dir)?,
        "Audit anchor belongs to another workspace"
    );
    store
        .verify_audit_extension(anchor.audit_sequence, &anchor.audit_head)
        .map(|_| ())
}

/// Read an anchor file and check it against live workspace state.
///
/// Inputs: `store` — open store to verify against; `data_dir` — workspace
/// directory; `path` — anchor file. Output: `Result<AuditAnchor>` when the
/// anchor matches the current audit point.
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

/// Whether enterprise rollback protection requires the OS credential-store
/// anchor.
///
/// Inputs: none; reads the OS-audit-anchor requirement from the environment.
/// Output: `Result<bool>`; errors on invalid configured values.
pub fn os_anchor_required() -> Result<bool> {
    os_anchor_required_from(std::env::var(OS_AUDIT_ANCHOR_ENV))
}

/// Interpret the raw OS audit-anchor environment lookup.
///
/// Inputs: `value` — the raw `RR_OS_AUDIT_ANCHOR` lookup result. Output:
/// `Ok(true)` only for the exact required literal, `Ok(false)` when unset, and
/// an error for invalid values or an unreadable environment. Test seam: the
/// raw lookup is injected so non-Unicode environment values are exercised
/// deterministically.
fn os_anchor_required_from(value: std::result::Result<String, std::env::VarError>) -> Result<bool> {
    match value {
        Ok(value) => interpret_os_anchor_required(Some(&value)),
        Err(std::env::VarError::NotPresent) => interpret_os_anchor_required(None),
        Err(error) => Err(anyhow::anyhow!(
            "Could not read {OS_AUDIT_ANCHOR_ENV}: {error}"
        )),
    }
}

// Windows/macOS only, and intentionally so: the OS audit anchor lives in the
// OS credential store (the keyring crate is a target-scoped dependency and
// Linux has no credential store). Every `cfg(any(windows, ...))` site in this
// module is OS-store product code, not a test gate; the `cfg(not(...))` arms
// below fail closed with the documented wording on other platforms.
#[cfg(any(windows, target_os = "macos"))]
/// Open the OS credential-store entry for the audit anchor.
///
/// Inputs: `data_dir` — workspace directory supplying the vault id. Output:
/// `Result<keyring::Entry>` — the service entry; error when the credential
/// store is unreachable.
fn os_anchor_entry(data_dir: &Path) -> Result<keyring::Entry> {
    let id = vault_id(data_dir)?;
    keyring::Entry::new(OS_AUDIT_ANCHOR_SERVICE, &id)
        .context("Cannot access the OS credential-store audit anchor")
}

#[cfg(any(windows, target_os = "macos"))]
/// Read the OS-protected audit anchor.
///
/// Inputs: `data_dir` — workspace directory. Output:
/// `Result<Option<AuditAnchor>>` — the stored anchor, `None` when absent; error
/// when the credential store fails (fail closed).
fn read_os_anchor(data_dir: &Path) -> Result<Option<AuditAnchor>> {
    let entry = os_anchor_entry(data_dir)?;
    parse_os_credential(entry.get_password())
}

#[cfg(any(windows, target_os = "macos"))]
/// Parse the OS credential-store audit-anchor lookup result.
///
/// Inputs: `lookup` — the raw credential-store read result. Output: the stored
/// anchor, `None` when no anchor has been bootstrapped yet, or an error for a
/// store outage (an unavailable store must never look like "not required").
/// Test seam: the lookup result is injected so the store-outage arm is
/// exercised deterministically.
fn parse_os_credential(
    lookup: std::result::Result<String, keyring::Error>,
) -> Result<Option<AuditAnchor>> {
    match lookup {
        Ok(serialized) => parse_anchor(serialized.as_bytes()).map(Some),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(anyhow::anyhow!(
            "OS credential-store audit anchor is unavailable: {error}"
        )),
    }
}

#[cfg(any(windows, target_os = "macos"))]
/// Write the OS-protected audit anchor.
///
/// Inputs: `data_dir` — workspace directory; `anchor` — anchor to store.
/// Output: `Result<()>` — `Ok` once the serialized anchor is written within the
/// size limit.
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
///
/// Inputs: `store` — open store to verify against; `data_dir` — workspace
/// directory. Output: `Result<Option<AuditAnchor>>` — the verified anchor when
/// required, `None` when the requirement is off.
pub fn verify_os_anchor_if_required(store: &Store, data_dir: &Path) -> Result<Option<AuditAnchor>> {
    verify_os_anchor(store, data_dir, os_anchor_required()?)
}

/// Verify the OS credential-store anchor when `required`.
///
/// Inputs: `store` — open workspace store; `data_dir` — workspace directory;
/// `required` — whether protected rollback anchoring is explicitly required.
/// Output: the verified anchor, `None` when not required or not yet
/// bootstrapped. Test seam: the requirement decision is injected because the
/// process environment cannot be mutated from tests.
fn verify_os_anchor(store: &Store, data_dir: &Path, required: bool) -> Result<Option<AuditAnchor>> {
    if !required {
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
///
/// Inputs: `store` — open store proving the audit extension; `data_dir` —
/// workspace directory. Output: `Result<Option<AuditAnchor>>` — the advanced
/// anchor when required, `None` otherwise.
pub fn checkpoint_os_anchor_if_required(
    store: &Store,
    data_dir: &Path,
) -> Result<Option<AuditAnchor>> {
    // Test seam: threads under test arm a scripted checkpoint in
    // `crate::test_support`, so protected-checkpoint failure handling is
    // exercised deterministically without OS credential mutation.
    #[cfg(test)]
    if let Some(gate) = crate::test_support::audit_gate() {
        gate()?;
        return Ok(None);
    }
    checkpoint_os_anchor(store, data_dir, os_anchor_required()?)
}

/// Advance the OS-protected anchor when `required`.
///
/// Inputs: `store` — open workspace store; `data_dir` — workspace directory;
/// `required` — whether protected rollback anchoring is explicitly required.
/// Output: the current trusted anchor. Test seam: the requirement decision is
/// injected because the process environment cannot be mutated from tests.
fn checkpoint_os_anchor(
    store: &Store,
    data_dir: &Path,
    required: bool,
) -> Result<Option<AuditAnchor>> {
    if !required {
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
///
/// Inputs: `store` — open store to verify against; `data_dir` — workspace
/// directory. Output: `Result<Option<AuditAnchor>>` — the verified anchor when
/// one is configured, `None` when the environment sets none.
pub fn verify_configured_anchor(store: &Store, data_dir: &Path) -> Result<Option<AuditAnchor>> {
    verify_configured_anchor_from(store, data_dir, std::env::var_os(AUDIT_ANCHOR_ENV))
}

/// Verify the configured external anchor from an injected environment value.
///
/// Inputs: `store` — open workspace store; `data_dir` — workspace directory;
/// `value` — the raw `RR_AUDIT_ANCHOR_FILE` value. Output: the verified anchor,
/// `None` when no external anchor is configured. Test seam: the raw value is
/// injected so relative-path rejection is exercised deterministically.
fn verify_configured_anchor_from(
    store: &Store,
    data_dir: &Path,
    value: Option<std::ffi::OsString>,
) -> Result<Option<AuditAnchor>> {
    let Some(value) = value else {
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

    /// Why: `rr anchor write anchor.json` resolves a bare filename against the
    /// current directory, which has no parent directory to create or harden.
    /// The parent gate must pass such destinations through untouched — an
    /// unfiltered parent lookup errors on the empty parent and would make
    /// relative anchor paths unusable — and the anchor must still round-trip.
    #[test]
    fn write_anchor_accepts_a_bare_filename_destination() {
        let root = tempfile::tempdir().unwrap();
        let (store, dir) = workspace(root.path());
        let name = format!("rr-audit-anchor-test-{}.json", uuid::Uuid::new_v4());
        let anchor = write_anchor(&store, &dir, Path::new(&name)).unwrap();
        let stored = read_anchor(Path::new(&name)).unwrap();
        std::fs::remove_file(&name).unwrap();
        assert_eq!(stored, anchor);
    }

    /// Why: the environment requirement is read through an injected lookup
    /// so every raw shape is deterministic — the exact literal enables
    /// enforcement, an unset variable keeps it off, a non-Unicode value
    /// must error (never silently disable the control), and the raw-set
    /// arm must interpret the same grammar as the parsed arm.
    #[test]
    fn os_anchor_required_from_reads_the_injected_lookup() {
        assert!(os_anchor_required_from(Ok(OS_AUDIT_ANCHOR_REQUIRED.to_owned())).unwrap());
        assert!(!os_anchor_required_from(Err(std::env::VarError::NotPresent)).unwrap());
        assert!(
            os_anchor_required_from(Err(std::env::VarError::NotUnicode(
                std::ffi::OsString::from("unpaired")
            )))
            .expect_err("a non-Unicode value must fail closed")
            .to_string()
            .contains("Could not read")
        );
        assert!(os_anchor_required_from(Ok("REQUIRED".to_owned())).is_err());
    }

    /// Why: `RR_AUDIT_ANCHOR_FILE` verification must run the full anchor
    /// check through the injected value — identity, workspace binding and
    /// audit extension — abort with the configured path named when the
    /// anchor does not match, and refuse relative paths before any file
    /// access (the path is resolved from a service context).
    #[test]
    fn configured_external_anchor_is_verified_through_the_injected_value() {
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
        let written = write_anchor(&store, &dir, &anchor_path).unwrap();
        let verified =
            verify_configured_anchor_from(&store, &dir, Some(anchor_path.clone().into_os_string()))
                .unwrap();
        assert_eq!(verified, Some(written));

        // A forged anchor must abort startup with the configured path named.
        let mut forged = read_anchor(&anchor_path).unwrap();
        forged.audit_sequence += 1;
        let forged_path = root.path().join("forged.json");
        write_new_private(&forged_path, &serde_json::to_vec_pretty(&forged).unwrap()).unwrap();
        let error =
            verify_configured_anchor_from(&store, &dir, Some(forged_path.clone().into_os_string()))
                .expect_err("a forged configured anchor must abort startup");
        assert!(
            error
                .to_string()
                .contains("Configured external audit anchor failed"),
            "the failure must name the configured path: {error}"
        );
        assert!(
            verify_configured_anchor_from(&store, &dir, Some("relative.json".into())).is_err(),
            "relative anchor paths must be refused before any file access"
        );
    }

    /// Why: with `RR_AUDIT_ANCHOR_ENV=required` and no OS credential store,
    /// both anchored paths must fail closed naming the platform — silently
    /// skipping rollback anchoring would defeat the control. (On credential
    /// stores the required read is satisfied by the bootstrapped anchor,
    /// pinned by the platform-keyring suites; the checkpoint half mutates
    /// the OS store and stays there.)
    #[test]
    fn required_os_anchoring_fails_closed_without_a_credential_store() {
        let root = tempfile::tempdir().unwrap();
        let (store, dir) = workspace(root.path());
        let result = verify_os_anchor(&store, &dir, true);
        #[cfg(any(windows, target_os = "macos"))]
        assert_eq!(
            result.unwrap(),
            None,
            "an unbootstrapped anchor verifies as absent"
        );
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            let error = result.expect_err("headless hosts cannot anchor");
            assert!(
                error
                    .to_string()
                    .contains("supported only with the Windows/macOS"),
                "the refusal names the platform: {error}"
            );
            let error =
                checkpoint_os_anchor(&store, &dir, true).expect_err("headless hosts cannot anchor");
            assert!(
                error
                    .to_string()
                    .contains("supported only with the Windows/macOS"),
                "the refusal names the platform: {error}"
            );
        }
    }

    /// Why: every invalid anchor field must be rejected with its own error so
    /// a corrupted or forged anchor can be told apart from an unsupported
    /// format; parsing is the first gate on the rollback trust root.
    #[test]
    fn anchor_parser_rejects_each_invalid_field_with_its_own_reason() {
        let anchor = AuditAnchor {
            format_version: 1,
            application_version: "1.2.3".into(),
            created_at: Utc::now(),
            workspace_fingerprint: "a".repeat(64),
            audit_sequence: 0,
            audit_head: "b".repeat(64),
        };
        parse_anchor(&serde_json::to_vec(&anchor).unwrap()).unwrap();

        let cases = [
            (
                AuditAnchor {
                    format_version: 2,
                    ..anchor.clone()
                },
                "Unsupported audit-anchor format",
            ),
            (
                AuditAnchor {
                    audit_sequence: -1,
                    ..anchor.clone()
                },
                "Audit-anchor sequence must be non-negative",
            ),
            (
                AuditAnchor {
                    workspace_fingerprint: "zz".into(),
                    ..anchor.clone()
                },
                "Audit-anchor workspace fingerprint is invalid",
            ),
            (
                AuditAnchor {
                    audit_head: "nothex".into(),
                    ..anchor.clone()
                },
                "Audit-anchor journal hash is invalid",
            ),
            (
                AuditAnchor {
                    application_version: "  ".into(),
                    ..anchor.clone()
                },
                "Audit-anchor application version is invalid",
            ),
            (
                AuditAnchor {
                    application_version: "x".repeat(129),
                    ..anchor.clone()
                },
                "Audit-anchor application version is invalid",
            ),
        ];
        for (invalid, reason) in cases {
            let error = parse_anchor(&serde_json::to_vec(&invalid).unwrap()).unwrap_err();
            assert_eq!(error.to_string(), reason, "anchor: {invalid:?}");
        }
        assert_eq!(
            parse_anchor(b"not json").unwrap_err().to_string(),
            "Audit-anchor JSON is invalid"
        );
    }

    /// Why: the workspace fingerprint is the binding between an anchor and its
    /// workspace; it must hash the trimmed vault identifier exactly (whitespace
    /// in the file is incidental) and refuse missing, non-UTF-8 or non-UUID
    /// identifiers instead of fingerprinting garbage.
    #[test]
    fn workspace_fingerprint_binds_the_vault_identifier_and_rejects_bad_ones() {
        let dir = tempfile::tempdir().unwrap();
        let error = workspace_fingerprint(dir.path()).unwrap_err();
        assert!(
            error.to_string().contains("vault-id is missing"),
            "unexpected error: {error}"
        );

        std::fs::write(dir.path().join("vault-id"), b"\xff\xfe").unwrap();
        let error = workspace_fingerprint(dir.path()).unwrap_err();
        assert!(
            error.to_string().contains("utf-8"),
            "non-UTF-8 identifiers must be refused: {error}"
        );

        std::fs::write(dir.path().join("vault-id"), b"not-a-uuid").unwrap();
        assert_eq!(
            workspace_fingerprint(dir.path()).unwrap_err().to_string(),
            "Workspace vault identifier is invalid"
        );

        let id = uuid::Uuid::new_v4().to_string();
        std::fs::write(dir.path().join("vault-id"), format!("  {id}\n")).unwrap();
        assert_eq!(
            workspace_fingerprint(dir.path()).unwrap(),
            sha256_domain(b"rejection-rejector-workspace-v1\0", id.as_bytes())
        );
    }

    /// Why: `anchor write` must be create-only — silently replacing an
    /// existing anchor would destroy the trust root an operator pinned.
    #[test]
    fn write_anchor_never_overwrites_an_existing_destination() {
        let root = tempfile::tempdir().unwrap();
        let (store, dir) = workspace(root.path());
        let path = root.path().join("anchor.json");
        write_anchor(&store, &dir, &path).unwrap();
        let pinned = std::fs::read(&path).unwrap();
        let error = write_anchor(&store, &dir, &path).unwrap_err();
        assert_eq!(error.to_string(), "Audit-anchor destination already exists");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            pinned,
            "a refused write must leave the pinned anchor untouched"
        );
    }

    /// Why: protected checkpoint failures must propagate through the wrapper
    /// (a swallowed error would let the anchor silently go stale, defeating
    /// rollback detection), and a passing gate short-circuits without touching
    /// the OS store.
    #[test]
    fn checkpoint_gate_failures_propagate_through_the_wrapper() {
        let root = tempfile::tempdir().unwrap();
        let (store, dir) = workspace(root.path());
        let failing: crate::test_support::Gate =
            std::sync::Arc::new(|| Err(anyhow::anyhow!("protected checkpoint unavailable")));
        let error = crate::test_support::with_audit_gate(failing, || {
            checkpoint_os_anchor_if_required(&store, &dir)
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "protected checkpoint unavailable");

        let passing: crate::test_support::Gate = std::sync::Arc::new(|| Ok(()));
        assert!(
            crate::test_support::with_audit_gate(passing, || {
                checkpoint_os_anchor_if_required(&store, &dir)
            })
            .unwrap()
            .is_none(),
            "a passing gate must short-circuit without checkpointing"
        );
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
        std::fs::create_dir_all(&as_dir).unwrap();
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

#[cfg(all(test, any(windows, target_os = "macos")))]
mod os_anchor_tests {
    use super::*;
    use crate::store::Store;
    use crate::vault::{
        Vault, private_dir, test_support::lock_credential_store, vault_id, write_new_private,
    };

    fn workspace() -> (
        tempfile::TempDir,
        Store,
        PathBuf,
        crate::vault::test_support::OsCredentialCleanup,
    ) {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("workspace");
        private_dir(&dir).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        write_new_private(&dir.join("vault-id"), id.as_bytes()).unwrap();
        let store = Store::open(&dir.join("state.sqlite3"), Vault::random()).unwrap();
        let cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(id);
        (root, store, dir, cleanup)
    }

    fn anchor_fixture() -> AuditAnchor {
        AuditAnchor {
            format_version: 1,
            application_version: "0.0.0-test".into(),
            created_at: Utc::now(),
            workspace_fingerprint: "a".repeat(64),
            audit_sequence: 0,
            audit_head: "b".repeat(64),
        }
    }

    /// Why: the credential entry is bound to the workspace vault identifier;
    /// without one, no OS-protected anchor may be created or read.
    #[test]
    fn os_anchor_entry_requires_a_workspace_identifier() {
        let bare = tempfile::tempdir().unwrap();
        assert!(os_anchor_entry(bare.path()).is_err());
        let (_root, _store, dir, _cleanup) = workspace();
        assert!(os_anchor_entry(&dir).is_ok());
    }

    /// Why: a credential-store outage must never be interpreted as "no anchor
    /// required" — only a genuine empty store bootstraps, and malformed anchor
    /// content is rejected instead of silently resetting trust.
    #[test]
    fn credential_lookup_outcomes_fail_closed_except_bootstrap_and_valid_reads() {
        let anchor = anchor_fixture();
        let serialized = serde_json::to_string(&anchor).unwrap();
        assert_eq!(
            parse_os_credential(Ok(serialized)).unwrap().unwrap(),
            anchor
        );
        assert!(parse_os_credential(Ok("{}".to_owned())).is_err());
        assert!(
            parse_os_credential(Err(keyring::Error::NoEntry))
                .unwrap()
                .is_none()
        );
        let error = parse_os_credential(Err(keyring::Error::BadEncoding(vec![]))).unwrap_err();
        assert!(
            error.to_string().contains("unavailable"),
            "unexpected error: {error}"
        );
    }

    /// Why: the OS-protected anchor must round-trip through the real credential
    /// store and reject tampered (unparseable) content on read.
    #[test]
    fn os_anchor_round_trips_through_the_credential_store() {
        let _lock = lock_credential_store();
        let (_root, store, dir, _cleanup) = workspace();
        assert!(read_os_anchor(&dir).unwrap().is_none());
        let anchor = current(&store, &dir).unwrap();
        write_os_anchor(&dir, &anchor).unwrap();
        assert_eq!(read_os_anchor(&dir).unwrap().unwrap(), anchor);

        keyring::Entry::new(OS_AUDIT_ANCHOR_SERVICE, &vault_id(&dir).unwrap())
            .unwrap()
            .set_password("garbage")
            .unwrap();
        assert!(
            read_os_anchor(&dir).is_err(),
            "malformed stored anchors must be rejected, not treated as empty"
        );
    }

    /// Why: the protected anchor is a monotonic trust root — checkpoints may
    /// only advance it, verification must catch both journal tampering and
    /// anchors from another workspace, and an unchanged journal keeps the
    /// trusted anchor untouched.
    #[test]
    fn verify_and_checkpoint_track_the_trusted_head_monotonically() {
        let _lock = lock_credential_store();
        let (_root, mut store, dir, _cleanup) = workspace();
        assert!(verify_os_anchor(&store, &dir, false).unwrap().is_none());
        assert!(
            verify_os_anchor_if_required(&store, &dir)
                .unwrap()
                .is_none()
        );
        // Why: a workspace that has never checkpointed an OS anchor must
        // verify as "not yet bootstrapped" (None) instead of failing — that is
        // the only state allowed to lack a protected anchor.
        assert_eq!(
            verify_os_anchor(&store, &dir, true).unwrap(),
            None,
            "an unbootstrapped workspace must verify as None"
        );
        // Why: the environment-driven wrapper must forward the requirement
        // decision unchanged — a no-op without `RR_OS_AUDIT_ANCHOR=required`,
        // and exactly the seeded checkpoint when it is required.
        match os_anchor_required() {
            Ok(required) => assert_eq!(
                checkpoint_os_anchor_if_required(&store, &dir)
                    .unwrap()
                    .is_some(),
                required,
                "the env wrapper must apply the requirement decision verbatim"
            ),
            Err(_) => assert!(
                checkpoint_os_anchor_if_required(&store, &dir).is_err(),
                "an invalid requirement value must fail closed through the wrapper"
            ),
        }
        assert!(checkpoint_os_anchor(&store, &dir, false).unwrap().is_none());

        let first = checkpoint_os_anchor(&store, &dir, true)
            .unwrap()
            .expect("first checkpoint bootstraps the anchor");
        assert_eq!(
            verify_os_anchor(&store, &dir, true).unwrap().unwrap(),
            first
        );

        let unchanged = checkpoint_os_anchor(&store, &dir, true).unwrap().unwrap();
        assert_eq!(
            unchanged.audit_sequence, first.audit_sequence,
            "an unchanged journal must not rewrite the trusted anchor"
        );

        store.log("test.extension", None, "later event").unwrap();
        let advanced = checkpoint_os_anchor(&store, &dir, true).unwrap().unwrap();
        assert!(advanced.audit_sequence > first.audit_sequence);
        assert_eq!(
            verify_os_anchor(&store, &dir, true).unwrap().unwrap(),
            advanced
        );

        let forged = AuditAnchor {
            workspace_fingerprint: workspace_fingerprint(&dir).unwrap(),
            audit_head: "c".repeat(64),
            audit_sequence: advanced.audit_sequence + 5,
            ..anchor_fixture()
        };
        write_os_anchor(&dir, &forged).unwrap();
        assert!(
            verify_os_anchor(&store, &dir, true).is_err(),
            "a forged anchor must fail verification"
        );

        let foreign = AuditAnchor {
            workspace_fingerprint: "f".repeat(64),
            ..first
        };
        write_os_anchor(&dir, &foreign).unwrap();
        assert!(
            checkpoint_os_anchor(&store, &dir, true).is_err(),
            "an anchor from another workspace must be rejected"
        );
    }

    /// Why: the external anchor path must be absolute, must match the live
    /// journal, and failures must carry the configured-path context so
    /// operators can find the broken trust root.
    #[test]
    fn configured_external_anchor_resolution_is_fail_closed() {
        let (_root, store, dir, _cleanup) = workspace();
        assert!(
            verify_configured_anchor_from(&store, &dir, None)
                .unwrap()
                .is_none()
        );

        let error =
            verify_configured_anchor_from(&store, &dir, Some("relative.json".into())).unwrap_err();
        assert!(
            error.to_string().contains("absolute"),
            "unexpected error: {error}"
        );

        let anchor_path = dir.join("external-anchor.json");
        write_anchor(&store, &dir, &anchor_path).unwrap();
        let verified =
            verify_configured_anchor_from(&store, &dir, Some(anchor_path.clone().into_os_string()))
                .unwrap()
                .expect("valid anchor must verify");
        assert_eq!(
            verified.workspace_fingerprint,
            workspace_fingerprint(&dir).unwrap()
        );

        let broken = dir.join("broken-anchor.json");
        std::fs::write(&broken, b"not json").unwrap();
        let error =
            verify_configured_anchor_from(&store, &dir, Some(broken.into_os_string())).unwrap_err();
        assert!(
            format!("{error:#}").contains("Configured external audit anchor failed"),
            "unexpected error: {error:#}"
        );
        assert!(verify_configured_anchor(&store, &dir).is_ok());
    }

    /// Why: the environment lookup must fail closed on unreadable values and
    /// accept only the exact required literal.
    #[test]
    fn os_anchor_environment_lookup_fails_closed() {
        assert!(!os_anchor_required_from(Err(std::env::VarError::NotPresent)).unwrap());
        assert!(os_anchor_required_from(Ok("required".to_owned())).unwrap());
        assert!(os_anchor_required_from(Ok("REQUIRED".to_owned())).is_err());
        let error = os_anchor_required_from(Err(std::env::VarError::NotUnicode(
            std::ffi::OsString::from("x"),
        )))
        .unwrap_err();
        assert!(
            error.to_string().contains("Could not read"),
            "unexpected error: {error}"
        );
        assert!(os_anchor_required().is_ok());
    }

    /// Why: symlinked anchors can redirect the trust root to attacker-controlled
    /// content and must be rejected outright on Windows as well.
    #[cfg(windows)]
    #[test]
    fn anchor_file_reader_rejects_symlinks_on_windows() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target");
        std::fs::write(&target, b"trusted").unwrap();
        let link = dir.path().join("link");
        if std::os::windows::fs::symlink_file(&target, &link).is_err() {
            // The platform forbids symlink creation without elevation; the
            // unix variant of this test covers the same guard there.
            return;
        }
        assert!(read_small_regular_file(&link).is_err());
    }
}
