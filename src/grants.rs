//! Verify a controller-signed, short-lived model authority before issuing a
//! worker capability. This module contains no controller approval database or
//! signing key; the controller must make those decisions outside the broker.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const DOMAIN: &[u8] = b"hunter-factory/model-authority/v1\0";
const MAX_AUTHORITY_BYTES: usize = 4096;
const ISSUE_WINDOW_SECONDS: i64 = 60;
const MAX_GRANT_SECONDS: i64 = 3600;
const MAX_REQUESTS: i64 = 1000;
const MAX_REQUEST_BYTES: i64 = 1024 * 1024;
const MAX_TOTAL_INPUT_BYTES: i64 = 1024 * 1024 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GrantError {
    #[error("model authority is invalid, expired, or belongs to another deployment")]
    InvalidAuthority,
    #[error("model grant exceeds permitted identity, term, or quota bounds")]
    InvalidGrant,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelGrant {
    pub campaign_id: String,
    pub lane_id: String,
    pub role: String,
    pub model: String,
    pub expires_at: i64,
    pub max_requests: i64,
    pub max_request_bytes: i64,
    pub max_total_input_bytes: i64,
}

impl ModelGrant {
    pub fn validate(&self, now: i64) -> Result<(), GrantError> {
        for identity in [&self.campaign_id, &self.lane_id, &self.role, &self.model] {
            if identity.is_empty()
                || identity.len() > 128
                || !identity
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return Err(GrantError::InvalidGrant);
            }
        }
        if !matches!(self.role.as_str(), "hunter" | "reviewer" | "orchestrator")
            || now < 0
            || self.expires_at <= now
            || self.expires_at - now > MAX_GRANT_SECONDS
            || !(1..=MAX_REQUESTS).contains(&self.max_requests)
            || !(1..=MAX_REQUEST_BYTES).contains(&self.max_request_bytes)
            || !(self.max_request_bytes..=MAX_TOTAL_INPUT_BYTES)
                .contains(&self.max_total_input_bytes)
        {
            return Err(GrantError::InvalidGrant);
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityBody {
    format_version: u32,
    key_id: String,
    issued_at: i64,
    approval_id: String,
    resource_id: String,
    source_pin: String,
    aoe_session_id: String,
    grant: ModelGrant,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedAuthority {
    body: AuthorityBody,
    signature: String,
}

pub struct Deployment<'a> {
    pub campaign_id: &'a str,
    pub lane_id: &'a str,
    pub aoe_session_id: &'a str,
}

pub struct VerifiedAuthority {
    pub grant: ModelGrant,
    pub approval_id: String,
    pub resource_id: String,
    pub source_pin: String,
    pub aoe_session_id: String,
    pub authority_hash: [u8; 32],
}

fn key_id(key: &VerifyingKey) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))
}

fn signed_message(body: &AuthorityBody) -> Result<Vec<u8>, GrantError> {
    let payload = serde_json::to_vec(body).map_err(|_| GrantError::InvalidAuthority)?;
    if payload.len() > MAX_AUTHORITY_BYTES {
        return Err(GrantError::InvalidAuthority);
    }
    let mut message = Vec::with_capacity(DOMAIN.len() + payload.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&payload);
    Ok(message)
}

/// Verify the exact authority format emitted by Hunter Factory's approved-lane
/// signer. A separate durable ledger must burn `authority_hash` once and
/// reserve request quota before any upstream call.
pub fn verify_authority(
    bytes: &[u8],
    key: &VerifyingKey,
    deployment: &Deployment<'_>,
    now: i64,
) -> Result<VerifiedAuthority, GrantError> {
    if bytes.len() > MAX_AUTHORITY_BYTES {
        return Err(GrantError::InvalidAuthority);
    }
    let signed: SignedAuthority =
        serde_json::from_slice(bytes).map_err(|_| GrantError::InvalidAuthority)?;
    let body = signed.body;
    if body.format_version != 1
        || body.key_id != key_id(key)
        || !now
            .checked_sub(body.issued_at)
            .is_some_and(|age| (0..=ISSUE_WINDOW_SECONDS).contains(&age))
    {
        return Err(GrantError::InvalidAuthority);
    }
    body.grant.validate(body.issued_at)?;
    if body.grant.expires_at <= now
        || body.grant.campaign_id != deployment.campaign_id
        || body.grant.lane_id != deployment.lane_id
        || body.aoe_session_id != deployment.aoe_session_id
        || body.approval_id.is_empty()
        || body.resource_id.is_empty()
        || body.aoe_session_id.is_empty()
        || !matches!(body.source_pin.len(), 40 | 64)
        || !body.source_pin.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(GrantError::InvalidAuthority);
    }
    let signature = hex::decode(&signed.signature)
        .ok()
        .and_then(|bytes| Signature::from_slice(&bytes).ok())
        .ok_or(GrantError::InvalidAuthority)?;
    let message = signed_message(&body)?;
    key.verify_strict(&message, &signature)
        .map_err(|_| GrantError::InvalidAuthority)?;
    Ok(VerifiedAuthority {
        grant: body.grant,
        approval_id: body.approval_id,
        resource_id: body.resource_id,
        source_pin: body.source_pin,
        aoe_session_id: body.aoe_session_id,
        authority_hash: Sha256::digest(&message).into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const NOW: i64 = 1_800_000_000;

    fn signed_fixture() -> (Vec<u8>, VerifyingKey) {
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let body = AuthorityBody {
            format_version: 1,
            key_id: key_id(&signer.verifying_key()),
            issued_at: NOW,
            approval_id: "approval-1".into(),
            resource_id: "worker-1".into(),
            source_pin: "a".repeat(40),
            aoe_session_id: "session-1".into(),
            grant: ModelGrant {
                campaign_id: "campaign-1".into(),
                lane_id: "lane-1".into(),
                role: "hunter".into(),
                model: "gpt-6-sol".into(),
                expires_at: NOW + 90,
                max_requests: 2,
                max_request_bytes: 1024,
                max_total_input_bytes: 4096,
            },
        };
        let signed = SignedAuthority {
            signature: hex::encode(signer.sign(&signed_message(&body).unwrap()).to_bytes()),
            body,
        };
        (serde_json::to_vec(&signed).unwrap(), signer.verifying_key())
    }

    #[test]
    fn signed_approval_is_bound_to_exact_lane_and_expiry() {
        let (bytes, key) = signed_fixture();
        let deployment = Deployment {
            campaign_id: "campaign-1",
            lane_id: "lane-1",
            aoe_session_id: "session-1",
        };
        let valid = verify_authority(&bytes, &key, &deployment, NOW + 1).unwrap();
        assert_eq!(valid.grant.model, "gpt-6-sol");
        assert_eq!(valid.source_pin, "a".repeat(40));
        assert!(verify_authority(&bytes, &key, &deployment, NOW + 91).is_err());
        assert!(
            verify_authority(
                &bytes,
                &key,
                &Deployment {
                    lane_id: "other",
                    ..deployment
                },
                NOW + 1
            )
            .is_err()
        );
        let mut tampered: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        tampered["body"]["grant"]["max_requests"] = 900.into();
        assert!(
            verify_authority(
                &serde_json::to_vec(&tampered).unwrap(),
                &key,
                &deployment,
                NOW + 1
            )
            .is_err()
        );
    }
}
