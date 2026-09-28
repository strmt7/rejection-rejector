//! Application-layer authenticated encryption. Indexes/counts/timestamps are not encrypted.
use anyhow::{Context, Result, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::RngCore;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{fs, io::Write, path::Path, sync::Arc};
use zeroize::Zeroizing;

const RECOVERY_KEY_FORMAT: u32 = 1;
const RECOVERY_MEMORY_KIB: u32 = 64 * 1024;
const RECOVERY_TIME_COST: u32 = 3;
const RECOVERY_LANES: u32 = 1;
const RECOVERY_MIN_PASSPHRASE_BYTES: usize = 20;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryKeyEnvelope {
    pub format_version: u32,
    pub app_version: String,
    pub created_at: DateTime<Utc>,
    pub vault_id: String,
    pub kdf: String,
    pub memory_kib: u32,
    pub time_cost: u32,
    pub lanes: u32,
    pub salt_b64: String,
    pub nonce_b64: String,
    pub wrapped_key_b64: String,
}

fn recovery_aad(vault_id: &str) -> Vec<u8> {
    let mut aad = b"rejection-rejector/recovery-key/v1\0".to_vec();
    aad.extend_from_slice(vault_id.as_bytes());
    aad
}

fn validate_vault_id(value: &str) -> Result<()> {
    ensure!(
        uuid::Uuid::parse_str(value).is_ok(),
        "Invalid vault identifier"
    );
    Ok(())
}

fn recovery_argon2(memory_kib: u32, time_cost: u32, lanes: u32) -> Result<Argon2<'static>> {
    ensure!(
        (19 * 1024..=512 * 1024).contains(&memory_kib),
        "Recovery KDF memory cost is outside the supported safety range"
    );
    ensure!(
        (1..=10).contains(&time_cost),
        "Recovery KDF time cost is outside the supported safety range"
    );
    ensure!(
        (1..=8).contains(&lanes),
        "Recovery KDF parallelism is outside the supported safety range"
    );
    let params = Params::new(memory_kib, time_cost, lanes, Some(32))
        .map_err(|_| anyhow::anyhow!("Invalid recovery KDF parameters"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

pub fn vault_id(dir: &Path) -> Result<String> {
    let id = fs::read_to_string(dir.join("vault-id"))
        .context("Vault identifier is missing")?;
    let id = id.trim().to_owned();
    validate_vault_id(&id)?;
    Ok(id)
}

#[derive(Clone)]
pub struct Vault {
    key: Arc<Zeroizing<[u8; 32]>>,
}
impl Vault {
    pub fn from_key(key: [u8; 32]) -> Self {
        Self {
            key: Arc::new(Zeroizing::new(key)),
        }
    }
    pub fn random() -> Self {
        let mut k = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut k);
        Self::from_key(k)
    }
    pub fn open(dir: &Path) -> Result<Self> {
        private_dir(dir)?;
        let id_path = dir.join("vault-id");
        let is_new = !id_path.exists();
        if is_new {
            ensure!(
                !dir.join("state.sqlite3").exists(),
                "Vault identifier is missing while a database exists. Restore the original key; refusing to create a replacement"
            );
            write_new_private(&id_path, uuid::Uuid::new_v4().to_string().as_bytes())?;
        }
        let id = fs::read_to_string(&id_path)?;
        ensure!(
            uuid::Uuid::parse_str(id.trim()).is_ok(),
            "Invalid vault identifier"
        );
        #[cfg(any(windows, target_os = "macos"))]
        {
            let entry = keyring::Entry::new("rejection-rejector.v1", id.trim())?;
            match entry.get_password() {
                Ok(encoded) => {
                    let bytes = Zeroizing::new(STANDARD.decode(encoded)?);
                    ensure!(bytes.len() == 32, "Invalid OS credential-store key");
                    let mut k = [0; 32];
                    k.copy_from_slice(&bytes);
                    Ok(Self::from_key(k))
                }
                Err(keyring::Error::NoEntry) if is_new || !dir.join("state.sqlite3").exists() => {
                    let mut k = [0; 32];
                    rand::rngs::OsRng.fill_bytes(&mut k);
                    entry.set_password(&STANDARD.encode(k)).context("Cannot save encryption key to the OS credential store; no plaintext fallback exists")?;
                    Ok(Self::from_key(k))
                }
                Err(e) => Err(anyhow::anyhow!(
                    "OS credential store unavailable or original key missing: {e}"
                )),
            }
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            // Linux fallback is explicit and requires a user-supplied passphrase on every run.
            let pass=Zeroizing::new(std::env::var("RR_VAULT_PASSPHRASE").context("On Linux, set RR_VAULT_PASSPHRASE to a strong passphrase (20+ characters). Windows uses Credential Manager automatically")?);
            ensure!(
                pass.len() >= 20,
                "Vault passphrase must be at least 20 characters"
            );
            let salt = uuid::Uuid::parse_str(id.trim())?;
            let mut k = [0; 32];
            argon2::Argon2::default()
                .hash_password_into(pass.as_bytes(), salt.as_bytes(), &mut k)
                .map_err(|_| anyhow::anyhow!("Key derivation failed"))?;
            Ok(Self::from_key(k))
        }
    }
    /// Wrap this vault's master key for offline disaster recovery.
    ///
    /// The passphrase is never serialized. The envelope contains only an
    /// Argon2id salt/parameters and an AEAD-wrapped 256-bit key bound to the
    /// vault UUID as associated data.
    pub fn recovery_envelope(
        &self,
        vault_id: &str,
        passphrase: &[u8],
    ) -> Result<RecoveryKeyEnvelope> {
        validate_vault_id(vault_id)?;
        ensure!(
            passphrase.len() >= RECOVERY_MIN_PASSPHRASE_BYTES,
            "Recovery passphrase must be at least {RECOVERY_MIN_PASSPHRASE_BYTES} bytes"
        );

        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        let mut wrapping_key = Zeroizing::new([0u8; 32]);
        recovery_argon2(
            RECOVERY_MEMORY_KIB,
            RECOVERY_TIME_COST,
            RECOVERY_LANES,
        )?
        .hash_password_into(passphrase, &salt, wrapping_key.as_mut())
        .map_err(|_| anyhow::anyhow!("Recovery key derivation failed"))?;

        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
            .map_err(|_| anyhow::anyhow!("Invalid recovery wrapping key"))?;
        let wrapped = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: self.key.as_ref().as_ref(),
                    aad: &recovery_aad(vault_id),
                },
            )
            .map_err(|_| anyhow::anyhow!("Recovery key wrapping failed"))?;

        Ok(RecoveryKeyEnvelope {
            format_version: RECOVERY_KEY_FORMAT,
            app_version: env!("CARGO_PKG_VERSION").into(),
            created_at: Utc::now(),
            vault_id: vault_id.into(),
            kdf: "argon2id-v1.3".into(),
            memory_kib: RECOVERY_MEMORY_KIB,
            time_cost: RECOVERY_TIME_COST,
            lanes: RECOVERY_LANES,
            salt_b64: STANDARD.encode(salt),
            nonce_b64: STANDARD.encode(nonce),
            wrapped_key_b64: STANDARD.encode(wrapped),
        })
    }

    /// Recover a Vault from a passphrase-wrapped recovery envelope.
    ///
    /// This does not write to the OS credential store. Callers must first
    /// authenticate the recovered key against the backup database.
    pub fn from_recovery_envelope(
        envelope: &RecoveryKeyEnvelope,
        passphrase: &[u8],
    ) -> Result<Self> {
        ensure!(
            envelope.format_version == RECOVERY_KEY_FORMAT,
            "Unsupported recovery-key format"
        );
        ensure!(
            envelope.kdf == "argon2id-v1.3",
            "Unsupported recovery-key KDF"
        );
        validate_vault_id(&envelope.vault_id)?;
        ensure!(
            passphrase.len() >= RECOVERY_MIN_PASSPHRASE_BYTES,
            "Recovery passphrase must be at least {RECOVERY_MIN_PASSPHRASE_BYTES} bytes"
        );

        let salt = STANDARD
            .decode(&envelope.salt_b64)
            .context("Invalid recovery salt encoding")?;
        let nonce = STANDARD
            .decode(&envelope.nonce_b64)
            .context("Invalid recovery nonce encoding")?;
        let wrapped = STANDARD
            .decode(&envelope.wrapped_key_b64)
            .context("Invalid wrapped recovery key encoding")?;
        ensure!(salt.len() == 16, "Invalid recovery salt length");
        ensure!(nonce.len() == 24, "Invalid recovery nonce length");
        ensure!(wrapped.len() == 48, "Invalid wrapped recovery key length");

        let mut wrapping_key = Zeroizing::new([0u8; 32]);
        recovery_argon2(
            envelope.memory_kib,
            envelope.time_cost,
            envelope.lanes,
        )?
        .hash_password_into(passphrase, &salt, wrapping_key.as_mut())
        .map_err(|_| anyhow::anyhow!("Recovery key derivation failed"))?;
        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
            .map_err(|_| anyhow::anyhow!("Invalid recovery wrapping key"))?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &wrapped,
                        aad: &recovery_aad(&envelope.vault_id),
                    },
                )
                .map_err(|_| {
                    anyhow::anyhow!(
                        "Recovery envelope authentication failed: wrong passphrase or damaged file"
                    )
                })?,
        );
        ensure!(plain.len() == 32, "Invalid recovered vault-key length");
        let mut key = [0u8; 32];
        key.copy_from_slice(&plain);
        Ok(Self::from_key(key))
    }

    #[cfg(any(windows, target_os = "macos"))]
    pub fn install_os_key_if_missing(&self, dir: &Path) -> Result<()> {
        let id = vault_id(dir)?;
        let entry = keyring::Entry::new("rejection-rejector.v1", &id)?;
        match entry.get_password() {
            Ok(_) => anyhow::bail!(
                "An OS credential already exists for this vault; refusing to overwrite it"
            ),
            Err(keyring::Error::NoEntry) => {}
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "Cannot inspect the OS credential store: {error}"
                ));
            }
        }
        entry
            .set_password(&STANDARD.encode(self.key.as_ref().as_ref()))
            .context("Cannot install the recovered vault key in the OS credential store")?;
        Ok(())
    }

    #[cfg(not(any(windows, target_os = "macos")))]
    pub fn install_os_key_if_missing(&self, _dir: &Path) -> Result<()> {
        anyhow::bail!(
            "Portable recovery-key import targets Windows Credential Manager or macOS Keychain; Linux recovery uses the original RR_VAULT_PASSPHRASE plus vault-id"
        )
    }

    pub fn seal<T: Serialize>(&self, context: &str, value: &T) -> Result<Vec<u8>> {
        let plain = Zeroizing::new(serde_json::to_vec(value)?);
        let mut nonce = [0; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref().as_ref())
            .map_err(|_| anyhow::anyhow!("Invalid encryption key"))?;
        let encrypted = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: context.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("Encryption failed"))?;
        let mut out = Vec::with_capacity(25 + encrypted.len());
        out.push(1);
        out.extend_from_slice(&nonce);
        out.extend(encrypted);
        Ok(out)
    }
    pub fn open_value<T: DeserializeOwned>(&self, context: &str, bytes: &[u8]) -> Result<T> {
        ensure!(
            bytes.len() >= 41 && bytes[0] == 1,
            "Invalid encrypted record"
        );
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref().as_ref())
            .map_err(|_| anyhow::anyhow!("Invalid encryption key"))?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&bytes[1..25]),
                    Payload {
                        msg: &bytes[25..],
                        aad: context.as_bytes(),
                    },
                )
                .map_err(|_| {
                    anyhow::anyhow!(
                        "Cannot decrypt record: wrong key, damaged data or authentication failure"
                    )
                })?,
        );
        Ok(serde_json::from_slice(&plain)?)
    }
}
pub fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    ensure!(
        !fs::symlink_metadata(path)?.file_type().is_symlink(),
        "Data directory must not be a symlink"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
pub fn write_new_private(path: &Path, data: &[u8]) -> Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}
pub struct InstanceLock {
    _file: fs::File,
}
impl InstanceLock {
    pub fn acquire(dir: &Path) -> Result<Self> {
        private_dir(dir)?;
        let path = dir.join("instance.lock");
        if path.exists() {
            ensure!(
                !fs::symlink_metadata(&path)?.file_type().is_symlink(),
                "Lock must not be a symlink"
            );
        }
        let mut opts = fs::OpenOptions::new();
        opts.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let f = opts.open(path)?;
        fs2::FileExt::try_lock_exclusive(&f).context("Another Rejection Rejector process is already using this data directory. Close the GUI before starting the background worker")?;
        Ok(Self { _file: f })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypts_authenticates_and_binds_context() {
        let v = Vault::random();
        let a = v.seal("job:1", &"private email").unwrap();
        let b = v.seal("job:1", &"private email").unwrap();
        assert_ne!(a, b);
        assert!(!a.windows(13).any(|w| w == b"private email"));
        assert_eq!(
            v.open_value::<String>("job:1", &a).unwrap(),
            "private email"
        );
        assert!(v.open_value::<String>("job:2", &a).is_err());
        assert!(Vault::random().open_value::<String>("job:1", &a).is_err());
        let mut damaged = a;
        damaged[30] ^= 1;
        assert!(v.open_value::<String>("job:1", &damaged).is_err());
    }
    #[test]
    fn recovery_envelope_roundtrips_and_rejects_tampering() {
        let vault = Vault::random();
        let id = uuid::Uuid::new_v4().to_string();
        let passphrase = b"correct horse battery staple";
        let envelope = vault.recovery_envelope(&id, passphrase).unwrap();
        assert_eq!(envelope.format_version, 1);
        assert_eq!(envelope.vault_id, id);
        assert!(!envelope.wrapped_key_b64.is_empty());

        let recovered = Vault::from_recovery_envelope(&envelope, passphrase).unwrap();
        let sealed = vault.seal("test", &"secret").unwrap();
        assert_eq!(
            recovered.open_value::<String>("test", &sealed).unwrap(),
            "secret"
        );
        assert!(
            Vault::from_recovery_envelope(&envelope, b"this passphrase is definitely wrong")
                .is_err()
        );

        let mut damaged = envelope.clone();
        damaged.vault_id = uuid::Uuid::new_v4().to_string();
        assert!(Vault::from_recovery_envelope(&damaged, passphrase).is_err());

        let mut expensive = envelope;
        expensive.memory_kib = 1024 * 1024;
        assert!(Vault::from_recovery_envelope(&expensive, passphrase).is_err());
    }

    #[test]
    fn only_one_instance() {
        let d = tempfile::tempdir().unwrap();
        let _a = InstanceLock::acquire(d.path()).unwrap();
        assert!(InstanceLock::acquire(d.path()).is_err());
    }
}
