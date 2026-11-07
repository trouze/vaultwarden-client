//! Device-layer authenticated encryption and owner-only atomic cache publication.
//! No plaintext temp files, plaintext metadata headers, or master/user-key storage.
//!
//! Directory-relative operations pin an opened directory rather than re-resolving
//! paths after validation. This first implementation is Unix/macOS/Linux only.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use rustix::fs::{openat, renameat, unlinkat, AtFlags, Mode, OFlags};
use std::{
    fs::{DirBuilder, File},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
    sync::Arc,
};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"VWDCACHE";
const VERSION: u32 = 1;
const MAX_BYTES: usize = 64 * 1024 * 1024;
const CURRENT: &str = "vault.cache";
const BACKUP: &str = "vault.previous";

#[derive(Debug, PartialEq, Eq)]
pub enum StorageError {
    Io,
    Permissions,
    Corrupt,
    UnsupportedVersion,
    InvalidKey,
    TooLarge,
    Entropy,
}

#[derive(Clone)]
pub struct CacheStore {
    directory: Arc<File>,
    key: Zeroizing<[u8; 32]>,
}

pub struct CacheLoad {
    pub payload: Zeroizing<Vec<u8>>,
    pub recovered: bool,
}

pub struct PreparedSave {
    directory: Arc<File>,
    current: Option<String>,
    backup: Option<String>,
}

impl CacheStore {
    pub fn new(path: &Path, key: &[u8]) -> Result<Self, StorageError> {
        let key: [u8; 32] = key.try_into().map_err(|_| StorageError::InvalidKey)?;
        if !path.is_absolute() {
            return Err(StorageError::Permissions);
        }
        match DirBuilder::new().mode(0o700).recursive(true).create(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(StorageError::Io),
        }
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(
                rustix::fs::OFlags::DIRECTORY.bits() as i32
                    | rustix::fs::OFlags::NOFOLLOW.bits() as i32,
            )
            .open(path)
            .map_err(|_| StorageError::Permissions)?;
        let metadata = directory.metadata().map_err(|_| StorageError::Io)?;
        if !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
        {
            return Err(StorageError::Permissions);
        }
        Ok(Self {
            directory: Arc::new(directory),
            key: Zeroizing::new(key),
        })
    }

    pub fn random_key() -> Result<Vec<u8>, StorageError> {
        let mut key = vec![0u8; 32];
        getrandom::fill(&mut key).map_err(|_| StorageError::Entropy)?;
        Ok(key)
    }

    pub fn load(&self) -> Result<Option<CacheLoad>, StorageError> {
        match self.read(CURRENT) {
            Ok(Some(bytes)) => match self.open(&bytes) {
                Ok(payload) => {
                    return Ok(Some(CacheLoad {
                        payload,
                        recovered: false,
                    }))
                }
                Err(StorageError::Corrupt) => {}
                Err(error) => return Err(error),
            },
            Ok(None) => {}
            Err(error) => return Err(error),
        }
        if let Some(bytes) = self.read(BACKUP)? {
            return Ok(Some(CacheLoad {
                payload: self.open(&bytes)?,
                recovered: true,
            }));
        }
        // Corruption is not silently treated as an empty/new vault.
        if self.read(CURRENT)?.is_some() {
            Err(StorageError::Corrupt)
        } else {
            Ok(None)
        }
    }

    pub fn prepare(&self, payload: &[u8]) -> Result<PreparedSave, StorageError> {
        let mut prepared = PreparedSave {
            directory: self.directory.clone(),
            current: None,
            backup: None,
        };
        // Only an authenticated current file may become the recovery snapshot.
        if let Some(previous) = self.read(CURRENT)? {
            match self.open(&previous) {
                Ok(_) => {
                    prepared.backup = Some(self.write_temporary(&previous)?);
                }
                Err(StorageError::Corrupt) => {} // Keep existing last-good backup.
                Err(error) => return Err(error),
            }
        }
        prepared.current = Some(self.write_temporary(&self.seal(payload)?)?);
        Ok(prepared)
    }

    pub fn clear(&self) -> Result<(), StorageError> {
        for name in [CURRENT, BACKUP] {
            match unlinkat(&*self.directory, name, AtFlags::empty()) {
                Ok(()) | Err(rustix::io::Errno::NOENT) => {}
                Err(_) => return Err(StorageError::Io),
            }
        }
        self.directory.sync_all().map_err(|_| StorageError::Io)
    }

    fn read(&self, name: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let fd = match openat(
            &*self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(rustix::io::Errno::LOOP) => return Err(StorageError::Permissions),
            Err(_) => return Err(StorageError::Io),
        };
        let file = File::from(fd);
        let metadata = file.metadata().map_err(|_| StorageError::Io)?;
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(StorageError::Permissions);
        }
        if metadata.len() > (MAX_BYTES + 128) as u64 {
            return Err(StorageError::TooLarge);
        }
        let mut bytes = Vec::new();
        file.take((MAX_BYTES + 129) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| StorageError::Io)?;
        if bytes.len() > MAX_BYTES + 128 {
            return Err(StorageError::TooLarge);
        }
        Ok(Some(bytes))
    }

    fn write_temporary(&self, bytes: &[u8]) -> Result<String, StorageError> {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| StorageError::Entropy)?;
        let name = format!(
            "temp-{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let fd = openat(
            &*self.directory,
            name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| StorageError::Io)?;
        let mut file = File::from(fd);
        if file.write_all(bytes).and_then(|_| file.sync_all()).is_err() {
            let _ = unlinkat(&*self.directory, name.as_str(), AtFlags::empty());
            return Err(StorageError::Io);
        }
        Ok(name)
    }

    fn seal(&self, payload: &[u8]) -> Result<Vec<u8>, StorageError> {
        if payload.len() > MAX_BYTES {
            return Err(StorageError::TooLarge);
        }
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).map_err(|_| StorageError::Entropy)?;
        let mut header = MAGIC.to_vec();
        header.extend_from_slice(&VERSION.to_be_bytes());
        let cipher = ChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| StorageError::InvalidKey)?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: payload,
                    aad: &header,
                },
            )
            .map_err(|_| StorageError::Corrupt)?;
        header.extend_from_slice(&nonce);
        header.extend_from_slice(&ciphertext);
        Ok(header)
    }

    fn open(&self, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, StorageError> {
        if bytes.len() < 40 || &bytes[..8] != MAGIC {
            return Err(StorageError::Corrupt);
        }
        if bytes[8..12] != VERSION.to_be_bytes() {
            return Err(StorageError::UnsupportedVersion);
        }
        let cipher = ChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| StorageError::InvalidKey)?;
        cipher
            .decrypt(
                Nonce::from_slice(&bytes[12..24]),
                Payload {
                    msg: &bytes[24..],
                    aad: &bytes[..12],
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| StorageError::Corrupt)
    }
}

impl PreparedSave {
    /// Caller must hold its session/state guard through publication, preventing
    /// logout from deleting a cache just before an old worker republishes it.
    pub fn publish(mut self) -> Result<(), StorageError> {
        if let Some(name) = &self.backup {
            renameat(&*self.directory, name.as_str(), &*self.directory, BACKUP)
                .map_err(|_| StorageError::Io)?;
            self.backup = None;
        }
        let name = self.current.as_ref().ok_or(StorageError::Io)?;
        renameat(&*self.directory, name.as_str(), &*self.directory, CURRENT)
            .map_err(|_| StorageError::Io)?;
        self.current = None;
        self.directory.sync_all().map_err(|_| StorageError::Io)
    }
}

impl Drop for PreparedSave {
    fn drop(&mut self) {
        for name in [self.current.as_deref(), self.backup.as_deref()]
            .into_iter()
            .flatten()
        {
            let _ = unlinkat(&*self.directory, name, AtFlags::empty());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn setup() -> (tempfile::TempDir, CacheStore) {
        let dir = tempfile::tempdir().unwrap_or_else(|_| panic!("test directory"));
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|_| panic!("test mode"));
        let store = CacheStore::new(dir.path(), &[42; 32]).unwrap_or_else(|_| panic!("test store"));
        (dir, store)
    }

    #[test]
    fn encrypted_restart_and_last_good_recovery() -> Result<(), StorageError> {
        let (dir, store) = setup();
        store
            .prepare(b"private@example.com; private metadata")?
            .publish()?;
        let disk = std::fs::read(dir.path().join(CURRENT)).map_err(|_| StorageError::Io)?;
        assert!(!disk.windows(19).any(|w| w == b"private@example.com"));
        let reopened = CacheStore::new(dir.path(), &[42; 32])?;
        assert_eq!(
            reopened.load()?.map(|v| v.payload.to_vec()),
            Some(b"private@example.com; private metadata".to_vec())
        );
        store.prepare(b"second authenticated snapshot")?.publish()?;
        std::fs::write(dir.path().join(CURRENT), b"truncated").map_err(|_| StorageError::Io)?;
        let recovered = reopened.load()?.ok_or(StorageError::Corrupt)?;
        assert!(recovered.recovered);
        assert_eq!(
            &*recovered.payload,
            b"private@example.com; private metadata"
        );
        Ok(())
    }

    #[test]
    fn wrong_key_tamper_and_future_version_fail_closed() -> Result<(), StorageError> {
        let (dir, store) = setup();
        store.prepare(b"public fixture")?.publish()?;
        let wrong = CacheStore::new(dir.path(), &[43; 32])?;
        assert!(matches!(wrong.load(), Err(StorageError::Corrupt)));
        let path = dir.path().join(CURRENT);
        let mut disk = std::fs::read(&path).map_err(|_| StorageError::Io)?;
        disk[39] ^= 1;
        std::fs::write(&path, &disk).map_err(|_| StorageError::Io)?;
        assert!(matches!(store.load(), Err(StorageError::Corrupt)));
        disk[8..12].copy_from_slice(&2u32.to_be_bytes());
        std::fs::write(&path, disk).map_err(|_| StorageError::Io)?;
        assert!(matches!(
            store.load(),
            Err(StorageError::UnsupportedVersion)
        ));
        Ok(())
    }

    #[test]
    fn cancelled_write_does_not_replace_current_or_leave_temporary_files(
    ) -> Result<(), StorageError> {
        let (dir, store) = setup();
        store.prepare(b"old")?.publish()?;
        drop(store.prepare(b"never published")?);
        assert_eq!(
            store.load()?.map(|v| v.payload.to_vec()),
            Some(b"old".to_vec())
        );
        assert_eq!(
            std::fs::read_dir(dir.path())
                .map_err(|_| StorageError::Io)?
                .count(),
            1
        );
        store.clear()?;
        assert!(store.load()?.is_none());
        Ok(())
    }

    #[test]
    fn symlinks_and_loose_permissions_are_rejected() -> Result<(), StorageError> {
        let (dir, store) = setup();
        let victim = dir.path().join("untouched");
        std::fs::write(&victim, b"do not overwrite").map_err(|_| StorageError::Io)?;
        symlink(&victim, dir.path().join(CURRENT)).map_err(|_| StorageError::Io)?;
        assert!(matches!(store.load(), Err(StorageError::Permissions)));
        assert!(matches!(
            store.prepare(b"new"),
            Err(StorageError::Permissions)
        ));
        assert_eq!(
            std::fs::read(&victim).map_err(|_| StorageError::Io)?,
            b"do not overwrite"
        );
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
            .map_err(|_| StorageError::Io)?;
        assert!(matches!(
            CacheStore::new(dir.path(), &[42; 32]),
            Err(StorageError::Permissions)
        ));
        Ok(())
    }
}
