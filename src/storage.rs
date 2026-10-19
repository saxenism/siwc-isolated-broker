//! Owner-only, atomic token records for a single trusted broker OS identity.
//! The store holds an exclusive process lock for its lifetime. It is not an
//! encryption boundary against the broker's own UID or root.

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Write},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::Builder;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::tokens::ValidatedSession;

const MAX_RECORD: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("credential store has an unsafe path, owner, or permissions")]
    UnsafePath,
    #[error("another broker already owns this credential store")]
    Locked,
    #[error("credential record is invalid or bound to another account or host")]
    InvalidRecord,
    #[error("credential store I/O failed")]
    Io(#[source] std::io::Error),
}

#[derive(Serialize)]
struct RecordView<'a> {
    version: u32,
    client_id: &'a str,
    subject: &'a str,
    host_id: &'a str,
    scopes: &'a BTreeSet<String>,
    expires_at: u64,
    earliest_refresh_at: u64,
    access_token: &'a str,
    refresh_token: &'a str,
    id_token: &'a str,
}

#[derive(Deserialize)]
struct RecordOwned {
    version: u32,
    client_id: String,
    subject: String,
    host_id: String,
    scopes: BTreeSet<String>,
    expires_at: u64,
    earliest_refresh_at: u64,
    access_token: String,
    refresh_token: String,
    id_token: String,
}

pub struct ProtectedStore {
    dir: PathBuf,
    _lock: File,
}

fn owner_only(metadata: &fs::Metadata, expected_mode: u32) -> bool {
    metadata.uid() == unsafe { libc::geteuid() }
        && metadata.permissions().mode() & 0o7777 == expected_mode
}

fn record_path(dir: &Path, client_id: &str) -> PathBuf {
    let digest = Sha256::digest(client_id.as_bytes());
    dir.join(format!("account-{}.json", hex::encode(digest)))
}

impl ProtectedStore {
    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        if !dir.is_absolute() {
            return Err(StoreError::UnsafePath);
        }
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(dir) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(StoreError::Io(error)),
        }
        let metadata = fs::symlink_metadata(dir).map_err(StoreError::Io)?;
        if !metadata.file_type().is_dir() || !owner_only(&metadata, 0o700) {
            return Err(StoreError::UnsafePath);
        }
        let lock_path = dir.join(".broker.lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(StoreError::Io)?;
        let metadata = lock.metadata().map_err(StoreError::Io)?;
        if !metadata.file_type().is_file() || !owner_only(&metadata, 0o600) {
            return Err(StoreError::UnsafePath);
        }
        // SAFETY: flock receives the valid descriptor owned by `lock`; it
        // remains open in this struct until the broker drops the store.
        let acquired = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if acquired != 0 {
            return Err(StoreError::Locked);
        }
        let store = Self {
            dir: dir.to_owned(),
            _lock: lock,
        };
        store.cleanup_orphan_temps()?;
        Ok(store)
    }

    fn cleanup_orphan_temps(&self) -> Result<(), StoreError> {
        for entry in fs::read_dir(&self.dir).map_err(StoreError::Io)? {
            let entry = entry.map_err(StoreError::Io)?;
            if !entry.file_name().to_string_lossy().starts_with(".account-") {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path()).map_err(StoreError::Io)?;
            if !metadata.file_type().is_file() || !owner_only(&metadata, 0o600) {
                return Err(StoreError::UnsafePath);
            }
            fs::remove_file(entry.path()).map_err(StoreError::Io)?;
        }
        Ok(())
    }

    /// A successful rename and directory fsync make a refresh-token rotation
    /// durable before the broker uses the replacement. The caller must retain
    /// this store's process lock through all refresh and dispatch operations.
    pub fn save(&self, session: &ValidatedSession) -> Result<(), StoreError> {
        if session.client_id.is_empty() || session.subject.is_empty() || session.host_id.is_empty()
        {
            return Err(StoreError::InvalidRecord);
        }
        let path = record_path(&self.dir, &session.client_id);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() && owner_only(&metadata, 0o600) => {}
            Ok(_) => return Err(StoreError::UnsafePath),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(StoreError::Io(error)),
        }
        let view = RecordView {
            version: 1,
            client_id: &session.client_id,
            subject: &session.subject,
            host_id: &session.host_id,
            scopes: &session.scopes,
            expires_at: session.expires_at,
            earliest_refresh_at: session.earliest_refresh_at,
            access_token: &session.access_token,
            refresh_token: &session.refresh_token,
            id_token: &session.id_token,
        };
        let bytes =
            Zeroizing::new(serde_json::to_vec(&view).map_err(|_| StoreError::InvalidRecord)?);
        if bytes.len() > MAX_RECORD {
            return Err(StoreError::InvalidRecord);
        }
        let mut temp = Builder::new()
            .prefix(".account-")
            .tempfile_in(&self.dir)
            .map_err(StoreError::Io)?;
        temp.as_file_mut()
            .write_all(&bytes)
            .map_err(StoreError::Io)?;
        temp.as_file().sync_all().map_err(StoreError::Io)?;
        temp.persist(&path)
            .map_err(|error| StoreError::Io(error.error))?;
        File::open(&self.dir)
            .and_then(|dir| dir.sync_all())
            .map_err(StoreError::Io)?;
        Ok(())
    }

    pub fn load(
        &self,
        expected_client_id: &str,
        expected_host_id: &str,
        expected_subject: &str,
    ) -> Result<ValidatedSession, StoreError> {
        let path = record_path(&self.dir, expected_client_id);
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(StoreError::Io)?;
        let metadata = file.metadata().map_err(StoreError::Io)?;
        if !metadata.file_type().is_file()
            || !owner_only(&metadata, 0o600)
            || metadata.len() > MAX_RECORD as u64
        {
            return Err(StoreError::UnsafePath);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        file.take((MAX_RECORD + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(StoreError::Io)?;
        if bytes.len() > MAX_RECORD {
            return Err(StoreError::InvalidRecord);
        }
        let record: RecordOwned =
            serde_json::from_slice(&bytes).map_err(|_| StoreError::InvalidRecord)?;
        if record.version != 1
            || record.client_id != expected_client_id
            || record.host_id != expected_host_id
            || record.subject != expected_subject
            || record.client_id.is_empty()
            || record.subject.is_empty()
            || record.host_id.is_empty()
            || record.access_token.is_empty()
            || record.refresh_token.is_empty()
            || record.id_token.is_empty()
            || !record.scopes.contains("offline_access")
            || !record.scopes.contains("resource.invoke")
        {
            return Err(StoreError::InvalidRecord);
        }
        Ok(ValidatedSession {
            client_id: record.client_id,
            subject: record.subject,
            host_id: record.host_id,
            scopes: record.scopes,
            expires_at: record.expires_at,
            earliest_refresh_at: record.earliest_refresh_at,
            access_token: Zeroizing::new(record.access_token),
            refresh_token: Zeroizing::new(record.refresh_token),
            id_token: Zeroizing::new(record.id_token),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn fixture() -> ValidatedSession {
        ValidatedSession {
            client_id: "oaiapp-fixture".into(),
            subject: "person-1".into(),
            host_id: "urn:uuid:123e4567-e89b-42d3-a456-426614174000".into(),
            scopes: [
                "offline_access",
                "resource.invoke",
                "chatgpt.tokens.use.direct",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            expires_at: u64::MAX,
            earliest_refresh_at: 0,
            access_token: Zeroizing::new("synthetic-access".into()),
            refresh_token: Zeroizing::new("synthetic-refresh".into()),
            id_token: Zeroizing::new("synthetic-id".into()),
        }
    }

    #[test]
    fn single_owner_store_rotates_atomically_and_binds_identity() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("private");
        let store = ProtectedStore::open(&dir).unwrap();
        assert!(matches!(
            ProtectedStore::open(&dir),
            Err(StoreError::Locked)
        ));
        let mut session = fixture();
        store.save(&session).unwrap();
        let loaded = store
            .load(&session.client_id, &session.host_id, &session.subject)
            .unwrap();
        assert_eq!(loaded.access_token_for_upstream(), Some("synthetic-access"));
        assert!(matches!(
            store.load(&session.client_id, "other-host", &session.subject),
            Err(StoreError::InvalidRecord)
        ));
        session.refresh_token = Zeroizing::new("replacement-refresh".into());
        store.save(&session).unwrap();
        let loaded = store
            .load(&session.client_id, &session.host_id, &session.subject)
            .unwrap();
        assert_eq!(
            loaded.refresh_form()[2],
            ("refresh_token", "replacement-refresh")
        );
        assert_eq!(
            fs::metadata(record_path(&dir, &session.client_id))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        drop(store);
        assert!(ProtectedStore::open(&dir).is_ok());
    }

    #[test]
    fn refuses_symlinked_or_overpermissive_paths() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("private");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            ProtectedStore::open(&dir),
            Err(StoreError::UnsafePath)
        ));
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let path = record_path(&dir, "oaiapp-fixture");
        let target = temp.path().join("elsewhere");
        fs::write(&target, "do not overwrite").unwrap();
        symlink(&target, &path).unwrap();
        let store = ProtectedStore::open(&dir).unwrap();
        assert!(matches!(
            store.save(&fixture()),
            Err(StoreError::UnsafePath)
        ));
        assert_eq!(fs::read_to_string(target).unwrap(), "do not overwrite");
    }

    #[test]
    fn restart_cleans_only_owned_orphan_temp() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("private");
        let store = ProtectedStore::open(&dir).unwrap();
        store.save(&fixture()).unwrap();
        drop(store);
        let orphan = dir.join(".account-crash-orphan");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&orphan)
            .unwrap();
        let other = dir.join("notes");
        fs::write(&other, "keep").unwrap();
        let reopened = ProtectedStore::open(&dir).unwrap();
        assert!(!orphan.exists());
        assert_eq!(fs::read_to_string(other).unwrap(), "keep");
        assert!(
            reopened
                .load(
                    "oaiapp-fixture",
                    "urn:uuid:123e4567-e89b-42d3-a456-426614174000",
                    "person-1"
                )
                .is_ok()
        );
    }
}
