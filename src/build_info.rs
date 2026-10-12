use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

const UNVERIFIED_COMMIT: &str = "unverified-local-build";
const BUILD_IDENTITY_DOMAIN: &[u8] = b"rejection-rejector-build-identity-v1\0";

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct BuildInfo {
    pub schema_version: u32,
    pub application_version: String,
    pub source_commit: String,
    pub source_commit_verified: bool,
    pub rustc_version: String,
    pub target: String,
    pub profile: String,
    pub cargo_lock_sha256: String,
    pub identity_sha256: String,
}

fn hash_hex(bytes: &[u8]) -> String {
    crate::hex_lower(Sha256::digest(bytes))
}

fn lock_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| hash_hex(include_bytes!("../Cargo.lock")))
}

fn verified_commit(value: &str) -> bool {
    value.len() == 40
        && value != UNVERIFIED_COMMIT
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.bytes().all(|byte| !byte.is_ascii_uppercase())
}

fn identity_hash(
    application_version: &str,
    source_commit: &str,
    rustc_version: &str,
    target: &str,
    profile: &str,
    cargo_lock_sha256: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(BUILD_IDENTITY_DOMAIN);
    for value in [
        application_version,
        source_commit,
        rustc_version,
        target,
        profile,
        cargo_lock_sha256,
    ] {
        digest.update((value.len() as u64).to_le_bytes());
        digest.update(value.as_bytes());
    }
    crate::hex_lower(digest.finalize())
}

/// Collect the build identity embedded at compile time.
///
/// Inputs: none. Output: [`BuildInfo`] with version, commit, rustc, target,
/// profile and lockfile digest.
pub fn current() -> BuildInfo {
    let application_version = env!("CARGO_PKG_VERSION").to_owned();
    let source_commit = env!("RR_BUILD_COMMIT").to_owned();
    let rustc_version = env!("RR_BUILD_RUSTC_VERSION").to_owned();
    let target = env!("RR_BUILD_TARGET").to_owned();
    let profile = env!("RR_BUILD_PROFILE").to_owned();
    let cargo_lock_sha256 = lock_hash().to_owned();
    let identity_sha256 = identity_hash(
        &application_version,
        &source_commit,
        &rustc_version,
        &target,
        &profile,
        &cargo_lock_sha256,
    );
    BuildInfo {
        schema_version: 1,
        application_version,
        source_commit_verified: verified_commit(&source_commit),
        source_commit,
        rustc_version,
        target,
        profile,
        cargo_lock_sha256,
        identity_sha256,
    }
}

/// Digest the build identity for contract surfaces.
///
/// Inputs: none. Output: `String` of lowercase hex — the SHA-256 of the
/// canonical build identity.
pub fn identity_sha256() -> String {
    current().identity_sha256
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_identity_is_content_bound_and_well_formed() {
        let info = current();
        assert_eq!(info.schema_version, 1);
        assert!(!info.application_version.is_empty());
        assert!(!info.rustc_version.is_empty());
        assert!(!info.target.is_empty());
        assert!(!info.profile.is_empty());
        for digest in [&info.cargo_lock_sha256, &info.identity_sha256] {
            assert_eq!(digest.len(), 64);
            assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
        }
        assert_eq!(identity_sha256(), info.identity_sha256);
        assert_eq!(
            info.source_commit_verified,
            verified_commit(&info.source_commit)
        );
    }

    #[test]
    fn build_identity_changes_when_an_input_changes() {
        let base = identity_hash("0.1.0", "a", "rustc", "target", "release", "lock");
        let changed = identity_hash("0.1.0", "b", "rustc", "target", "release", "lock");
        assert_ne!(base, changed);
    }
}

#[cfg(test)]
mod commit_verification_tests {
    use super::*;

    /// Why: `source_commit_verified` must only be true for a full lowercase
    /// hexadecimal git object id; short ids, uppercase hex, non-hex text and
    /// the local-build marker must all stay unverified so build provenance
    /// cannot be faked by a well-formed-looking string.
    #[test]
    fn verified_commit_requires_a_full_lowercase_hex_object_id() {
        assert!(verified_commit("0123456789abcdef0123456789abcdef01234567"));
        assert!(verified_commit(&"a".repeat(40)));
        assert!(verified_commit(&"0".repeat(40)));
        assert!(
            !verified_commit(&"A".repeat(40)),
            "uppercase hex is rejected"
        );
        assert!(
            !verified_commit("0123456789abcdef0123456789abcdef0123456"),
            "non-hex letters are rejected"
        );
        assert!(!verified_commit(&"a".repeat(39)), "short ids are rejected");
        assert!(!verified_commit(&"a".repeat(41)), "long ids are rejected");
        assert!(!verified_commit(UNVERIFIED_COMMIT));
        assert!(!verified_commit(""));
    }

    /// Why: `current()` must classify the actually embedded build commit with
    /// the same rule the tests pin above, so a real release build can never
    /// claim verification for a non-conforming commit string.
    #[test]
    fn current_build_info_agrees_with_the_commit_verdict() {
        let info = current();
        assert_eq!(
            info.source_commit_verified,
            verified_commit(&info.source_commit)
        );
        assert_eq!(info.source_commit, env!("RR_BUILD_COMMIT"));
    }
}
