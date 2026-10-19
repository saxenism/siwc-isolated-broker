//! Broker-side, durable authority for agent-visible model proxy capabilities.
//! The raw capability and upstream OAuth material must never be stored here.
//! This ledger limits requests and input bytes; it is not a token-usage or
//! monetary meter, and it does not authenticate a real Codex session yet.

use std::path::Path;

use anyhow::{Context, Result, ensure};
use ed25519_dalek::VerifyingKey;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::grants::{Deployment, ModelGrant, verify_authority};
#[cfg(unix)]
use crate::storage::ProtectedStore;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reservation {
    pub grant_id: String,
    pub remaining_requests: i64,
    pub remaining_input_bytes: i64,
    pub expires_at: i64,
}

pub struct ModelGrantLedger {
    conn: Connection,
}

fn token_hash(token: &[u8]) -> Result<[u8; 32]> {
    ensure!(
        (32..=256).contains(&token.len()) && token.iter().all(|byte| byte.is_ascii_graphic()),
        "invalid model proxy capability"
    );
    Ok(Sha256::digest(token).into())
}

impl ModelGrantLedger {
    /// Open beside the owner-only credential store, outside agent mounts.
    /// Keep the store's exclusive process lock alive alongside this ledger.
    #[cfg(unix)]
    pub fn open_owned(store: &ProtectedStore) -> Result<Self> {
        use std::{
            fs::{self, OpenOptions},
            io::ErrorKind,
            os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        };

        let path = store.directory().join("model-grants.db");
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(file) => drop(file),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.file_type().is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.permissions().mode() & 0o7777 == 0o600,
            "model grant ledger path is unsafe"
        );
        Self::open(&path)
    }

    fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).context("open model grant ledger")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS model_grants (
                grant_id TEXT PRIMARY KEY NOT NULL,
                token_hash BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
                campaign_id TEXT NOT NULL,
                lane_id TEXT NOT NULL,
                role TEXT NOT NULL,
                model TEXT NOT NULL,
                issued_at INTEGER NOT NULL CHECK (issued_at >= 0),
                expires_at INTEGER NOT NULL CHECK (expires_at > issued_at),
                max_requests INTEGER NOT NULL CHECK (max_requests > 0),
                max_request_bytes INTEGER NOT NULL CHECK (max_request_bytes > 0),
                max_total_input_bytes INTEGER NOT NULL CHECK (max_total_input_bytes > 0),
                used_requests INTEGER NOT NULL DEFAULT 0 CHECK (used_requests >= 0),
                used_input_bytes INTEGER NOT NULL DEFAULT 0 CHECK (used_input_bytes >= 0),
                revoked_at INTEGER CHECK (revoked_at IS NULL OR revoked_at >= issued_at)
            ) STRICT;
            CREATE UNIQUE INDEX IF NOT EXISTS one_active_model_grant_per_lane
            ON model_grants (campaign_id, lane_id) WHERE revoked_at IS NULL;
            CREATE TABLE IF NOT EXISTS consumed_model_authorities (
                authority_hash BLOB PRIMARY KEY NOT NULL CHECK (length(authority_hash) = 32),
                grant_id TEXT NOT NULL UNIQUE REFERENCES model_grants(grant_id),
                consumed_at INTEGER NOT NULL CHECK (consumed_at >= 0)
            ) STRICT;",
        )?;
        Ok(Self { conn })
    }

    /// Synthetic fixture only. Production must consume a controller-signed
    /// approval through `issue_signed`, never call this direct issuer.
    #[cfg(test)]
    pub fn issue(&mut self, grant: &ModelGrant, token: &[u8], now: i64) -> Result<String> {
        grant.validate(now)?;
        let hash = token_hash(token)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let id = Self::issue_in_transaction(&tx, grant, &hash, now)?;
        tx.commit()?;
        Ok(id)
    }

    /// Verify a fresh approval signature and burn it exactly once while
    /// issuing the proxy capability. Neither raw proxy nor OAuth token is
    /// written to SQLite. Broker deployment must guard its own database.
    pub fn issue_signed(
        &mut self,
        authority: &[u8],
        key: &VerifyingKey,
        deployment: &Deployment<'_>,
        token: &[u8],
        now: i64,
    ) -> Result<String> {
        let verified = verify_authority(authority, key, deployment, now)?;
        let hash = token_hash(token)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let id = Self::issue_in_transaction(&tx, &verified.grant, &hash, now)?;
        tx.execute(
            "INSERT INTO consumed_model_authorities (authority_hash,grant_id,consumed_at)
             VALUES (?1,?2,?3)",
            params![verified.authority_hash.as_slice(), id, now],
        )?;
        tx.commit()?;
        Ok(id)
    }

    fn issue_in_transaction(
        tx: &Transaction<'_>,
        grant: &ModelGrant,
        hash: &[u8; 32],
        now: i64,
    ) -> Result<String> {
        let previous: Option<Vec<u8>> = tx
            .query_row(
                "SELECT token_hash FROM model_grants
                 WHERE campaign_id=?1 AND lane_id=?2 AND revoked_at IS NULL",
                params![grant.campaign_id, grant.lane_id],
                |row| row.get(0),
            )
            .optional()?;
        ensure!(
            previous.as_deref() != Some(hash.as_slice()),
            "model capability rotation requires fresh token"
        );
        tx.execute(
            "UPDATE model_grants SET revoked_at=?3
             WHERE campaign_id=?1 AND lane_id=?2 AND revoked_at IS NULL",
            params![grant.campaign_id, grant.lane_id, now],
        )?;
        let id = uuid::Uuid::new_v4().to_string();
        tx.execute(
            "INSERT INTO model_grants
             (grant_id,token_hash,campaign_id,lane_id,role,model,issued_at,expires_at,
              max_requests,max_request_bytes,max_total_input_bytes)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                id,
                hash.as_slice(),
                grant.campaign_id,
                grant.lane_id,
                grant.role,
                grant.model,
                now,
                grant.expires_at,
                grant.max_requests,
                grant.max_request_bytes,
                grant.max_total_input_bytes,
            ],
        )?;
        Ok(id)
    }

    /// Atomically spend one request slot before sending to the upstream.
    /// An uncertain or failed upstream call is still charged to the slot.
    pub fn reserve(
        &mut self,
        token: &[u8],
        campaign_id: &str,
        lane_id: &str,
        model: &str,
        request_bytes: usize,
        now: i64,
    ) -> Result<Reservation> {
        let hash = token_hash(token)?;
        let bytes = i64::try_from(request_bytes).context("model request size overflow")?;
        ensure!(now >= 0 && bytes > 0, "invalid model request");
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE model_grants
             SET used_requests=used_requests+1, used_input_bytes=used_input_bytes+?5
             WHERE token_hash=?1 AND campaign_id=?2 AND lane_id=?3 AND model=?4
               AND revoked_at IS NULL AND issued_at<=?6 AND expires_at>?6
               AND ?5<=max_request_bytes AND used_requests<max_requests
               AND ?5<=max_total_input_bytes-used_input_bytes",
            params![hash.as_slice(), campaign_id, lane_id, model, bytes, now],
        )?;
        ensure!(changed == 1, "model capability denied");
        let reservation = tx.query_row(
            "SELECT grant_id,max_requests-used_requests,
                    max_total_input_bytes-used_input_bytes,expires_at
             FROM model_grants WHERE token_hash=?1",
            [hash.as_slice()],
            |row| {
                Ok(Reservation {
                    grant_id: row.get(0)?,
                    remaining_requests: row.get(1)?,
                    remaining_input_bytes: row.get(2)?,
                    expires_at: row.get(3)?,
                })
            },
        )?;
        tx.commit()?;
        Ok(reservation)
    }

    /// Closing a lane revokes its capability even when no replacement exists.
    pub fn revoke_lane(&mut self, campaign_id: &str, lane_id: &str, now: i64) -> Result<bool> {
        ensure!(now >= 0, "invalid revocation time");
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE model_grants SET revoked_at=?3
             WHERE campaign_id=?1 AND lane_id=?2 AND revoked_at IS NULL AND issued_at<=?3",
            params![campaign_id, lane_id, now],
        )?;
        tx.commit()?;
        Ok(changed == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;
    const TOKEN_A: &[u8] = b"synthetic-model-capability-token-0001";
    const TOKEN_B: &[u8] = b"synthetic-model-capability-token-0002";

    fn grant() -> ModelGrant {
        ModelGrant {
            campaign_id: "campaign-1".into(),
            lane_id: "lane-1".into(),
            role: "hunter".into(),
            model: "gpt-6-sol".into(),
            expires_at: NOW + 60,
            max_requests: 2,
            max_request_bytes: 100,
            max_total_input_bytes: 150,
        }
    }

    #[test]
    fn request_budget_survives_restart_and_denies_cross_lane_or_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("model-grants.db");
        let mut ledger = ModelGrantLedger::open(&db).unwrap();
        ledger.issue(&grant(), TOKEN_A, NOW).unwrap();
        assert!(
            ledger
                .reserve(TOKEN_A, "campaign-1", "other", "gpt-6-sol", 1, NOW)
                .is_err()
        );
        assert!(
            ledger
                .reserve(TOKEN_A, "campaign-1", "lane-1", "other", 1, NOW)
                .is_err()
        );
        assert!(
            ledger
                .reserve(TOKEN_A, "campaign-1", "lane-1", "gpt-6-sol", 101, NOW)
                .is_err()
        );
        let first = ledger
            .reserve(TOKEN_A, "campaign-1", "lane-1", "gpt-6-sol", 100, NOW)
            .unwrap();
        assert_eq!(first.remaining_requests, 1);
        drop(ledger);
        let mut ledger = ModelGrantLedger::open(&db).unwrap();
        assert!(
            ledger
                .reserve(TOKEN_A, "campaign-1", "lane-1", "gpt-6-sol", 51, NOW)
                .is_err()
        );
        let second = ledger
            .reserve(TOKEN_A, "campaign-1", "lane-1", "gpt-6-sol", 50, NOW)
            .unwrap();
        assert_eq!(second.remaining_requests, 0);
        assert_eq!(second.remaining_input_bytes, 0);
        assert!(
            ledger
                .reserve(TOKEN_A, "campaign-1", "lane-1", "gpt-6-sol", 1, NOW)
                .is_err()
        );
        assert!(
            ledger
                .reserve(TOKEN_A, "campaign-1", "lane-1", "gpt-6-sol", 1, NOW + 60)
                .is_err()
        );
        let file = std::fs::read(&db).unwrap();
        assert!(!file.windows(TOKEN_A.len()).any(|window| window == TOKEN_A));
    }

    #[test]
    fn rotation_and_close_revoke_old_capability_without_resetting_it() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("model-grants.db");
        let mut ledger = ModelGrantLedger::open(&db).unwrap();
        ledger.issue(&grant(), TOKEN_A, NOW).unwrap();
        assert!(ledger.issue(&grant(), TOKEN_A, NOW + 1).is_err());
        let mut rotated = grant();
        rotated.expires_at = NOW + 120;
        ledger.issue(&rotated, TOKEN_B, NOW + 1).unwrap();
        assert!(
            ledger
                .reserve(TOKEN_A, "campaign-1", "lane-1", "gpt-6-sol", 1, NOW + 1)
                .is_err()
        );
        assert!(
            ledger
                .reserve(TOKEN_B, "campaign-1", "lane-1", "gpt-6-sol", 1, NOW + 1)
                .is_ok()
        );
        assert!(ledger.revoke_lane("campaign-1", "lane-1", NOW + 2).unwrap());
        drop(ledger);
        let mut ledger = ModelGrantLedger::open(&db).unwrap();
        assert!(
            ledger
                .reserve(TOKEN_B, "campaign-1", "lane-1", "gpt-6-sol", 1, NOW + 2)
                .is_err()
        );
        assert!(!ledger.revoke_lane("campaign-1", "lane-1", NOW + 3).unwrap());
    }

    #[test]
    fn rejects_unbounded_or_malformed_grants() {
        let dir = tempfile::tempdir().unwrap();
        let mut ledger = ModelGrantLedger::open(&dir.path().join("model-grants.db")).unwrap();
        let mut invalid = grant();
        invalid.expires_at = NOW + 3601;
        assert!(ledger.issue(&invalid, TOKEN_A, NOW).is_err());
        invalid = grant();
        invalid.role = "administrator".into();
        assert!(ledger.issue(&invalid, TOKEN_A, NOW).is_err());
        assert!(ledger.issue(&grant(), b"short", NOW).is_err());
    }

    #[test]
    fn concurrent_broker_requests_cannot_exceed_one_grant() {
        use std::sync::{Arc, Barrier};

        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("model-grants.db");
        ModelGrantLedger::open(&db)
            .unwrap()
            .issue(&grant(), TOKEN_A, NOW)
            .unwrap();
        let barrier = Arc::new(Barrier::new(4));
        let attempts: Vec<_> = (0..4)
            .map(|_| {
                let db = db.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let mut ledger = ModelGrantLedger::open(&db).unwrap();
                    barrier.wait();
                    ledger
                        .reserve(TOKEN_A, "campaign-1", "lane-1", "gpt-6-sol", 1, NOW)
                        .is_ok()
                })
            })
            .collect();
        assert_eq!(
            attempts
                .into_iter()
                .map(|attempt| attempt.join().unwrap())
                .filter(|succeeded| *succeeded)
                .count(),
            2
        );
    }

    #[test]
    fn signed_authority_is_burned_once_across_restart() {
        let (authority, key) = crate::grants::signed_fixture();
        let deployment = Deployment {
            campaign_id: "campaign-1",
            lane_id: "lane-1",
            aoe_session_id: "session-1",
        };
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("model-grants.db");
        let mut ledger = ModelGrantLedger::open(&path).unwrap();
        ledger
            .issue_signed(&authority, &key, &deployment, TOKEN_A, NOW + 1)
            .unwrap();
        assert!(
            ledger
                .reserve(TOKEN_A, "campaign-1", "lane-1", "gpt-6-sol", 8, NOW + 1)
                .is_ok()
        );
        drop(ledger);
        let mut ledger = ModelGrantLedger::open(&path).unwrap();
        let reformatted = serde_json::to_vec_pretty(
            &serde_json::from_slice::<serde_json::Value>(&authority).unwrap(),
        )
        .unwrap();
        assert!(
            ledger
                .issue_signed(&reformatted, &key, &deployment, TOKEN_B, NOW + 2)
                .is_err()
        );
        assert!(
            ledger
                .reserve(TOKEN_A, "campaign-1", "lane-1", "gpt-6-sol", 8, NOW + 2)
                .is_ok()
        );
        assert!(ledger.revoke_lane("campaign-1", "lane-1", NOW + 3).unwrap());
        assert!(
            ledger
                .reserve(TOKEN_A, "campaign-1", "lane-1", "gpt-6-sol", 8, NOW + 3)
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn ledger_opens_only_under_broker_owned_store() {
        use std::{fs, os::unix::fs::PermissionsExt};

        let temp = tempfile::tempdir().unwrap();
        let store = ProtectedStore::open(&temp.path().join("broker")).unwrap();
        let ledger = ModelGrantLedger::open_owned(&store).unwrap();
        drop(ledger);
        let path = store.directory().join("model-grants.db");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(ModelGrantLedger::open_owned(&store).is_err());
    }
}
