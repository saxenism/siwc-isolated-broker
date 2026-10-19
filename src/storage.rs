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

use jsonwebtoken::jwk::JwkSet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::Builder;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::{identity::verify_refresh_id_token, tokens::ValidatedSession};

const MAX_RECORD: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("credential store has an unsafe path, owner, or permissions")]
    UnsafePath,
    #[error("another broker already owns this credential store")]
    Locked,
    #[error("credential record is invalid or bound to another account or host")]
    InvalidRecord,
    #[error("this client already has a credential record on the broker host")]
    AlreadyExists,
    #[error("refresh outcome is uncertain; reauthorization is required before automatic retry")]
    UncertainRefresh,
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

#[derive(Deserialize)]
struct RecordIndex {
    client_id: String,
    subject: String,
    host_id: String,
}

/// Nonsecret account metadata for a local human-operated account picker.
#[derive(Debug, PartialEq, Eq)]
pub struct SavedAccount {
    pub client_id: String,
    pub subject: String,
    pub plan_enabled: bool,
    pub expires_at: u64,
}

impl Drop for RecordOwned {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        self.id_token.zeroize();
    }
}

pub struct ProtectedStore {
    dir: PathBuf,
    _lock: File,
    refresh_gate: tokio::sync::Mutex<()>,
}

fn owner_only(metadata: &fs::Metadata, expected_mode: u32) -> bool {
    metadata.uid() == unsafe { libc::geteuid() }
        && metadata.permissions().mode() & 0o7777 == expected_mode
}

fn record_path(dir: &Path, client_id: &str) -> PathBuf {
    let digest = Sha256::digest(client_id.as_bytes());
    dir.join(format!("account-{}.json", hex::encode(digest)))
}

fn marker_path(dir: &Path, client_id: &str) -> PathBuf {
    let digest = Sha256::digest(client_id.as_bytes());
    dir.join(format!(".refresh-{}", hex::encode(digest)))
}

impl ProtectedStore {
    pub(crate) fn directory(&self) -> &Path {
        &self.dir
    }

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
            refresh_gate: tokio::sync::Mutex::new(()),
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

    fn sync_dir(&self) -> Result<(), StoreError> {
        File::open(&self.dir)
            .and_then(|dir| dir.sync_all())
            .map_err(StoreError::Io)
    }

    /// Each broker host keeps one stable, opaque identifier across restarts.
    /// It is not a credential and must never be copied from a laptop to a VM.
    pub fn host_id(&self) -> Result<String, StoreError> {
        let path = self.dir.join("host-id");
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                let value = format!("urn:uuid:{}", uuid::Uuid::new_v4());
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&path)
                    .map_err(StoreError::Io)?;
                file.write_all(value.as_bytes()).map_err(StoreError::Io)?;
                file.sync_all().map_err(StoreError::Io)?;
                self.sync_dir()?;
                return Ok(value);
            }
            Err(error) => return Err(StoreError::Io(error)),
        };
        let metadata = file.metadata().map_err(StoreError::Io)?;
        if !metadata.file_type().is_file() || !owner_only(&metadata, 0o600) || metadata.len() > 64 {
            return Err(StoreError::UnsafePath);
        }
        let mut value = String::new();
        file.read_to_string(&mut value).map_err(StoreError::Io)?;
        let valid = value
            .strip_prefix("urn:uuid:")
            .and_then(|raw| uuid::Uuid::parse_str(raw).ok())
            .is_some_and(|id| id.get_version_num() == 4);
        if !valid {
            return Err(StoreError::InvalidRecord);
        }
        Ok(value)
    }

    pub(crate) async fn lock_refresh(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.refresh_gate.lock().await
    }

    /// A durable hash marker prevents replaying a refresh token after a crash
    /// or an uncertain network response. If the saved token changed, the
    /// previous rotation committed and its old marker can be replaced.
    pub(crate) fn begin_refresh(&self, session: &ValidatedSession) -> Result<(), StoreError> {
        let marker = marker_path(&self.dir, &session.client_id);
        let hash = hex::encode(Sha256::digest(session.refresh_token.as_bytes()));
        match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&marker)
        {
            Ok(mut file) => {
                let metadata = file.metadata().map_err(StoreError::Io)?;
                if !metadata.file_type().is_file()
                    || !owner_only(&metadata, 0o600)
                    || metadata.len() > 64
                {
                    return Err(StoreError::UnsafePath);
                }
                let mut previous_hash = String::new();
                file.read_to_string(&mut previous_hash)
                    .map_err(StoreError::Io)?;
                if previous_hash.len() != 64
                    || !previous_hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(StoreError::UncertainRefresh);
                }
                if previous_hash == hash {
                    return Err(StoreError::UncertainRefresh);
                }
                fs::remove_file(&marker).map_err(StoreError::Io)?;
                self.sync_dir()?;
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(StoreError::Io(error)),
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&marker)
            .map_err(StoreError::Io)?;
        file.write_all(hash.as_bytes()).map_err(StoreError::Io)?;
        file.sync_all().map_err(StoreError::Io)?;
        self.sync_dir()?;
        Ok(())
    }

    pub(crate) fn commit_refresh(&self, session: &ValidatedSession) -> Result<(), StoreError> {
        let marker = marker_path(&self.dir, &session.client_id);
        let metadata = fs::symlink_metadata(&marker).map_err(|_| StoreError::UncertainRefresh)?;
        if !metadata.file_type().is_file() || !owner_only(&metadata, 0o600) || metadata.len() != 64
        {
            return Err(StoreError::UncertainRefresh);
        }
        self.save(session)?;
        fs::remove_file(marker).map_err(StoreError::Io)?;
        self.sync_dir()
    }

    /// A successful rename and directory fsync make a refresh-token rotation
    /// durable before the broker uses the replacement. The caller must retain
    /// this store's process lock through all refresh and dispatch operations.
    pub fn save(&self, session: &ValidatedSession) -> Result<(), StoreError> {
        if session.client_id.is_empty()
            || session.subject.is_empty()
            || session.host_id.is_empty()
            || session.host_id != self.host_id()?
        {
            return Err(StoreError::InvalidRecord);
        }
        let path = record_path(&self.dir, &session.client_id);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() && owner_only(&metadata, 0o600) => {
                // A returning sign-in or refresh may rotate credentials for
                // this binding, but cannot silently switch accounts.
                let _previous =
                    self.load(&session.client_id, &session.host_id, &session.subject)?;
            }
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
        self.sync_dir()?;
        Ok(())
    }

    /// Import a disposable, owner-only transfer file on a self-hosted VM.
    /// The signed ID token binds the saved client and subject; the VM keeps
    /// its own pre-existing host ID. This deliberately refuses to replace an
    /// existing account. Only the trusted broker UID may invoke this method.
    pub fn import_vm_transfer(
        &self,
        transfer_file: &Path,
        jwks: &JwkSet,
    ) -> Result<SavedAccount, StoreError> {
        let parent = transfer_file.parent().ok_or(StoreError::UnsafePath)?;
        let name = transfer_file
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(StoreError::UnsafePath)?;
        if !transfer_file.is_absolute()
            || !name.starts_with("siwc-transfer-")
            || !name.ends_with(".json")
            || parent == self.dir
        {
            return Err(StoreError::UnsafePath);
        }
        let parent_metadata = fs::symlink_metadata(parent).map_err(StoreError::Io)?;
        if !parent_metadata.file_type().is_dir() || !owner_only(&parent_metadata, 0o700) {
            return Err(StoreError::UnsafePath);
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(transfer_file)
            .map_err(StoreError::Io)?;
        let metadata = file.metadata().map_err(StoreError::Io)?;
        if !metadata.file_type().is_file()
            || !owner_only(&metadata, 0o600)
            || metadata.len() == 0
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
        let mut record: RecordOwned =
            serde_json::from_slice(&bytes).map_err(|_| StoreError::InvalidRecord)?;
        let host_id = self.host_id()?;
        if record.version != 1
            || record.client_id.is_empty()
            || record.subject.is_empty()
            || record.host_id.is_empty()
            || record.host_id == host_id
            || record.access_token.is_empty()
            || record.refresh_token.is_empty()
            || record.id_token.is_empty()
            || !record.scopes.contains("offline_access")
            || !record.scopes.contains("resource.invoke")
            || !record.scopes.contains("chatgpt.tokens.use.direct")
            || record.earliest_refresh_at > record.expires_at.saturating_add(5)
        {
            return Err(StoreError::InvalidRecord);
        }
        let identity = verify_refresh_id_token(&record.id_token, jwks, &record.client_id)
            .map_err(|_| StoreError::InvalidRecord)?;
        if identity.subject != record.subject {
            return Err(StoreError::InvalidRecord);
        }
        match fs::symlink_metadata(record_path(&self.dir, &record.client_id)) {
            Ok(_) => return Err(StoreError::AlreadyExists),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(StoreError::Io(error)),
        }
        let session = ValidatedSession {
            client_id: std::mem::take(&mut record.client_id),
            subject: std::mem::take(&mut record.subject),
            host_id,
            scopes: std::mem::take(&mut record.scopes),
            expires_at: record.expires_at,
            earliest_refresh_at: record.earliest_refresh_at,
            access_token: Zeroizing::new(std::mem::take(&mut record.access_token)),
            refresh_token: Zeroizing::new(std::mem::take(&mut record.refresh_token)),
            id_token: Zeroizing::new(std::mem::take(&mut record.id_token)),
        };
        self.save(&session)?;
        // The transfer copy must not remain on the VM after a durable import.
        fs::remove_file(transfer_file).map_err(StoreError::Io)?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(StoreError::Io)?;
        let plan_enabled = session.plan_enabled();
        Ok(SavedAccount {
            client_id: session.client_id,
            subject: session.subject,
            plan_enabled,
            expires_at: session.expires_at,
        })
    }

    /// Produce a disposable owner-only credential copy for an operator to
    /// transfer over SSH. The output directory must stay outside agent mounts.
    /// The originating host keeps its original credential record.
    pub fn export_vm_transfer(
        &self,
        client_id: &str,
        subject: &str,
        transfer_dir: &Path,
    ) -> Result<PathBuf, StoreError> {
        if !transfer_dir.is_absolute() || transfer_dir == self.dir {
            return Err(StoreError::UnsafePath);
        }
        let directory = fs::symlink_metadata(transfer_dir).map_err(StoreError::Io)?;
        if !directory.file_type().is_dir() || !owner_only(&directory, 0o700) {
            return Err(StoreError::UnsafePath);
        }
        let host_id = self.host_id()?;
        let _session = self.load(client_id, &host_id, subject)?;
        let source = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(record_path(&self.dir, client_id))
            .map_err(StoreError::Io)?;
        let mut target = Builder::new()
            .prefix("siwc-transfer-")
            .suffix(".json")
            .tempfile_in(transfer_dir)
            .map_err(StoreError::Io)?;
        let copied = std::io::copy(
            &mut source.take((MAX_RECORD + 1) as u64),
            target.as_file_mut(),
        )
        .map_err(StoreError::Io)?;
        if copied == 0 || copied > MAX_RECORD as u64 {
            return Err(StoreError::InvalidRecord);
        }
        target.as_file().sync_all().map_err(StoreError::Io)?;
        let (_file, path) = target.keep().map_err(|error| StoreError::Io(error.error))?;
        File::open(transfer_dir)
            .and_then(|directory| directory.sync_all())
            .map_err(StoreError::Io)?;
        Ok(path)
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
        let mut record: RecordOwned =
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
            client_id: std::mem::take(&mut record.client_id),
            subject: std::mem::take(&mut record.subject),
            host_id: std::mem::take(&mut record.host_id),
            scopes: std::mem::take(&mut record.scopes),
            expires_at: record.expires_at,
            earliest_refresh_at: record.earliest_refresh_at,
            access_token: Zeroizing::new(std::mem::take(&mut record.access_token)),
            refresh_token: Zeroizing::new(std::mem::take(&mut record.refresh_token)),
            id_token: Zeroizing::new(std::mem::take(&mut record.id_token)),
        })
    }

    pub fn list_accounts(&self) -> Result<Vec<SavedAccount>, StoreError> {
        let host_id = self.host_id()?;
        let mut accounts = Vec::new();
        for entry in fs::read_dir(&self.dir).map_err(StoreError::Io)? {
            let entry = entry.map_err(StoreError::Io)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !(name.starts_with("account-") && name.ends_with(".json")) {
                continue;
            }
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(entry.path())
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
            let index: RecordIndex =
                serde_json::from_slice(&bytes).map_err(|_| StoreError::InvalidRecord)?;
            if record_path(&self.dir, &index.client_id) != entry.path() || index.host_id != host_id
            {
                return Err(StoreError::InvalidRecord);
            }
            let session = self.load(&index.client_id, &host_id, &index.subject)?;
            accounts.push(SavedAccount {
                client_id: session.client_id().to_owned(),
                subject: session.subject().to_owned(),
                plan_enabled: session.plan_enabled(),
                expires_at: session.expires_at(),
            });
        }
        accounts.sort_by(|left, right| left.client_id.cmp(&right.client_id));
        Ok(accounts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use rand::rngs::OsRng;
    use rsa::{RsaPrivateKey, pkcs8::EncodePrivateKey, traits::PublicKeyParts};
    use serde_json::json;
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
        let host_id = store.host_id().unwrap();
        assert_eq!(host_id, store.host_id().unwrap());
        assert!(matches!(
            ProtectedStore::open(&dir),
            Err(StoreError::Locked)
        ));
        let mut session = fixture();
        session.host_id = host_id.clone();
        store.save(&session).unwrap();
        let loaded = store
            .load(&session.client_id, &session.host_id, &session.subject)
            .unwrap();
        assert_eq!(loaded.access_token_for_upstream(), Some("synthetic-access"));
        let mut wrong_account = fixture();
        wrong_account.host_id = host_id.clone();
        wrong_account.subject = "person-2".into();
        assert!(matches!(
            store.save(&wrong_account),
            Err(StoreError::InvalidRecord)
        ));
        let mut wrong_host = fixture();
        wrong_host.host_id = "urn:uuid:aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa".into();
        assert!(matches!(
            store.save(&wrong_host),
            Err(StoreError::InvalidRecord)
        ));
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
        let reopened = ProtectedStore::open(&dir).unwrap();
        assert_eq!(host_id, reopened.host_id().unwrap());
    }

    #[test]
    fn account_picker_reads_only_current_host_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let store = ProtectedStore::open(&temp.path().join("private")).unwrap();
        let mut session = fixture();
        session.host_id = store.host_id().unwrap();
        store.save(&session).unwrap();
        assert_eq!(
            store.list_accounts().unwrap(),
            vec![SavedAccount {
                client_id: "oaiapp-fixture".into(),
                subject: "person-1".into(),
                plan_enabled: true,
                expires_at: u64::MAX,
            }]
        );
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
        let mut session = fixture();
        session.host_id = store.host_id().unwrap();
        assert!(matches!(store.save(&session), Err(StoreError::UnsafePath)));
        assert_eq!(fs::read_to_string(target).unwrap(), "do not overwrite");
    }

    #[test]
    fn restart_cleans_only_owned_orphan_temp() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("private");
        let store = ProtectedStore::open(&dir).unwrap();
        let mut session = fixture();
        session.host_id = store.host_id().unwrap();
        store.save(&session).unwrap();
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
                .load("oaiapp-fixture", &session.host_id, "person-1")
                .is_ok()
        );
    }

    #[test]
    fn uncertain_refresh_cannot_replay_rotated_token() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("private");
        let store = ProtectedStore::open(&dir).unwrap();
        let mut old = fixture();
        old.host_id = store.host_id().unwrap();
        store.save(&old).unwrap();
        store.begin_refresh(&old).unwrap();
        drop(store);
        let reopened = ProtectedStore::open(&dir).unwrap();
        let loaded = reopened
            .load(&old.client_id, &old.host_id, &old.subject)
            .unwrap();
        assert!(matches!(
            reopened.begin_refresh(&loaded),
            Err(StoreError::UncertainRefresh)
        ));
        let mut rotated = fixture();
        rotated.host_id = old.host_id.clone();
        rotated.refresh_token = Zeroizing::new("replacement-refresh".into());
        reopened.save(&rotated).unwrap();
        reopened.begin_refresh(&rotated).unwrap();
        reopened.commit_refresh(&rotated).unwrap();
        assert!(!marker_path(&dir, &old.client_id).exists());
        let marker = marker_path(&dir, &old.client_id);
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&marker)
            .unwrap();
        assert!(matches!(
            reopened.begin_refresh(&rotated),
            Err(StoreError::UncertainRefresh)
        ));
    }

    #[test]
    fn vm_import_verifies_identity_rebinds_host_and_consumes_transfer() {
        let temp = tempfile::tempdir().unwrap();
        let laptop = ProtectedStore::open(&temp.path().join("laptop")).unwrap();
        let vm = ProtectedStore::open(&temp.path().join("vm")).unwrap();
        let key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let pem = key.to_pkcs8_pem(Default::default()).unwrap();
        let encoding = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
        let jwks: JwkSet = serde_json::from_value(json!({"keys":[{
            "kty":"RSA", "kid":"fixture", "use":"sig", "alg":"RS256",
            "n":URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
            "e":URL_SAFE_NO_PAD.encode(key.e().to_bytes_be())
        }]}))
        .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("fixture".into());
        let mut session = fixture();
        session.host_id = laptop.host_id().unwrap();
        session.id_token = Zeroizing::new(
            encode(
                &header,
                &json!({
                    "sub":session.subject, "iss":"https://auth.openai.com",
                    "aud":session.client_id, "iat":now, "exp":now + 3600
                }),
                &encoding,
            )
            .unwrap(),
        );
        session.expires_at = now + 3600;
        laptop.save(&session).unwrap();
        let staging = temp.path().join("staging");
        fs::create_dir(&staging).unwrap();
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700)).unwrap();
        let transfer = laptop
            .export_vm_transfer(&session.client_id, &session.subject, &staging)
            .unwrap();
        assert_eq!(
            fs::metadata(&transfer).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let imported = vm.import_vm_transfer(&transfer, &jwks).unwrap();
        assert_eq!(imported.client_id, "oaiapp-fixture");
        assert!(imported.plan_enabled);
        assert!(!transfer.exists());
        assert_ne!(laptop.host_id().unwrap(), vm.host_id().unwrap());
        let recovered = vm
            .load(&session.client_id, &vm.host_id().unwrap(), &session.subject)
            .unwrap();
        assert_eq!(recovered.refresh_form()[2].1, "synthetic-refresh");
        assert!(matches!(vm.save(&session), Err(StoreError::InvalidRecord)));

        let transfer = laptop
            .export_vm_transfer(&session.client_id, &session.subject, &staging)
            .unwrap();
        assert!(matches!(
            vm.import_vm_transfer(&transfer, &jwks),
            Err(StoreError::AlreadyExists)
        ));
        assert!(transfer.exists());

        let mut tampered: serde_json::Value =
            serde_json::from_slice(&fs::read(&transfer).unwrap()).unwrap();
        tampered["subject"] = json!("another-person");
        fs::write(&transfer, serde_json::to_vec(&tampered).unwrap()).unwrap();
        assert!(matches!(
            vm.import_vm_transfer(&transfer, &jwks),
            Err(StoreError::InvalidRecord)
        ));
        fs::set_permissions(&transfer, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            vm.import_vm_transfer(&transfer, &jwks),
            Err(StoreError::UnsafePath)
        ));
    }
}
