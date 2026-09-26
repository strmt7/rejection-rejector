//! Application-layer authenticated encryption. Indexes/counts/timestamps are not encrypted.
use anyhow::{ensure, Context, Result};
#[cfg(any(windows, target_os = "macos"))]
use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use serde::{de::DeserializeOwned, Serialize};
use std::{fs, io::Write, path::Path, sync::Arc};
use zeroize::Zeroizing;

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
            ensure!(!dir.join("state.sqlite3").exists(),"Vault identifier is missing while a database exists. Restore the original key; refusing to create a replacement");
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
    fn only_one_instance() {
        let d = tempfile::tempdir().unwrap();
        let _a = InstanceLock::acquire(d.path()).unwrap();
        assert!(InstanceLock::acquire(d.path()).is_err());
    }
}
