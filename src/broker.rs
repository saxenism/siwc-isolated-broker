//! Trusted broker core. Transport must separately expose `issue_signed` and
//! `revoke_lane` only on a privileged control channel, and `dispatch` only on
//! an agent channel with an isolated Unix socket and denied direct egress.

use std::sync::Mutex;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::VerifyingKey;
use serde_json::Value;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    authority::OpenAiAuthority, grants::Deployment, inference::PlanInference,
    ledger::ModelGrantLedger, policy::valid_plan_request, storage::ProtectedStore,
};

const MAX_REQUEST_BYTES: usize = 1024 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BrokerError {
    #[error("broker account, storage, or grant authority is unavailable")]
    Unavailable,
    #[error("model request is invalid or outside the permitted route")]
    InvalidRequest,
    #[error("model capability is invalid, exhausted, revoked, or expired")]
    Denied,
    #[error("OpenAI model request failed or did not complete")]
    Upstream,
}

/// The raw capability is returned only to a privileged controller channel and
/// then delivered to one isolated agent lane. It is not logged or persisted.
pub struct IssuedCapability {
    pub token: Zeroizing<String>,
    pub grant_id: String,
}

pub struct BrokerCore {
    store: ProtectedStore,
    ledger: Mutex<ModelGrantLedger>,
    authority: OpenAiAuthority,
    inference: PlanInference,
    controller_key: VerifyingKey,
    client_id: String,
    subject: String,
    host_id: String,
}

impl BrokerCore {
    pub fn new(
        store: ProtectedStore,
        controller_key: VerifyingKey,
        client_id: String,
        subject: String,
    ) -> Result<Self, BrokerError> {
        let authority = OpenAiAuthority::new().map_err(|_| BrokerError::Unavailable)?;
        let inference = PlanInference::new().map_err(|_| BrokerError::Unavailable)?;
        Self::with_transports(
            store,
            controller_key,
            client_id,
            subject,
            authority,
            inference,
        )
    }

    pub(crate) fn with_transports(
        store: ProtectedStore,
        controller_key: VerifyingKey,
        client_id: String,
        subject: String,
        authority: OpenAiAuthority,
        inference: PlanInference,
    ) -> Result<Self, BrokerError> {
        let host_id = store.host_id().map_err(|_| BrokerError::Unavailable)?;
        let account = store
            .load(&client_id, &host_id, &subject)
            .map_err(|_| BrokerError::Unavailable)?;
        if !account.plan_enabled() {
            return Err(BrokerError::Unavailable);
        }
        let ledger = ModelGrantLedger::open_owned(&store).map_err(|_| BrokerError::Unavailable)?;
        Ok(Self {
            store,
            ledger: Mutex::new(ledger),
            authority,
            inference,
            controller_key,
            client_id,
            subject,
            host_id,
        })
    }

    /// Privileged control channel only. A valid, unused signed authority is
    /// burned in the same durable transaction as capability issuance.
    pub fn issue_signed(
        &self,
        authority: &[u8],
        deployment: &Deployment<'_>,
        now: i64,
    ) -> Result<IssuedCapability, BrokerError> {
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).map_err(|_| BrokerError::Unavailable)?;
        let token = Zeroizing::new(URL_SAFE_NO_PAD.encode(random));
        let grant_id = self
            .ledger
            .lock()
            .map_err(|_| BrokerError::Unavailable)?
            .issue_signed(
                authority,
                &self.controller_key,
                deployment,
                token.as_bytes(),
                now,
            )
            .map_err(|_| BrokerError::Denied)?;
        Ok(IssuedCapability { token, grant_id })
    }

    /// Privileged control channel only. A closed lane's next request fails,
    /// including after a broker restart.
    pub fn revoke_lane(
        &self,
        campaign_id: &str,
        lane_id: &str,
        now: i64,
    ) -> Result<bool, BrokerError> {
        self.ledger
            .lock()
            .map_err(|_| BrokerError::Unavailable)?
            .revoke_lane(campaign_id, lane_id, now)
            .map_err(|_| BrokerError::Unavailable)
    }

    /// Agent channel only. The body is validated, then a request slot and
    /// input bytes are durably spent before loading the OAuth token or calling
    /// the upstream. Failed or uncertain calls keep their reservation.
    pub async fn dispatch(
        &self,
        capability: &[u8],
        campaign_id: &str,
        lane_id: &str,
        body: &[u8],
        now: i64,
    ) -> Result<Vec<u8>, BrokerError> {
        if body.is_empty() || body.len() > MAX_REQUEST_BYTES {
            return Err(BrokerError::InvalidRequest);
        }
        let value: Value = serde_json::from_slice(body).map_err(|_| BrokerError::InvalidRequest)?;
        let model = value
            .get("model")
            .and_then(Value::as_str)
            .ok_or(BrokerError::InvalidRequest)?;
        if !valid_plan_request(&value, model) {
            return Err(BrokerError::InvalidRequest);
        }
        self.ledger
            .lock()
            .map_err(|_| BrokerError::Unavailable)?
            .reserve(capability, campaign_id, lane_id, model, body.len(), now)
            .map_err(|_| BrokerError::Denied)?;
        let mut session = self
            .store
            .load(&self.client_id, &self.host_id, &self.subject)
            .map_err(|_| BrokerError::Unavailable)?;
        if !session.plan_enabled() {
            return Err(BrokerError::Denied);
        }
        if session.access_token_for_upstream().is_none() {
            session = self
                .authority
                .refresh_session(&self.store, &self.client_id, &self.host_id, &self.subject)
                .await
                .map_err(|_| BrokerError::Unavailable)?;
        }
        self.inference
            .complete(&session, body, model)
            .await
            .map_err(|_| BrokerError::Upstream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        http::{HeaderMap, StatusCode, header},
        routing::post,
    };
    use std::{
        collections::BTreeSet,
        time::{SystemTime, UNIX_EPOCH},
    };
    use url::Url;

    const NOW: i64 = 1_800_000_000;
    const REQUEST: &[u8] = br#"{"model":"gpt-6-sol","store":false,"stream":true,"input":[{"role":"user","content":"hi"}]}"#;
    const COMPLETE: &str = "event: response.created\ndata: {\"type\":\"response.created\"}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n";

    async fn fake_transport() -> PlanInference {
        let app = Router::new().route(
            "/v1/responses",
            post(|headers: HeaderMap| async move {
                if headers
                    .get(header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    != Some("Bearer synthetic-access-token-123")
                {
                    return (
                        StatusCode::FORBIDDEN,
                        [("content-type", "text/event-stream")],
                        "wrong token",
                    );
                }
                (
                    StatusCode::OK,
                    [("content-type", "text/event-stream")],
                    COMPLETE,
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        PlanInference::for_loopback_test(
            Url::parse(&format!("http://{address}/v1/responses")).unwrap(),
        )
    }

    fn saved_session(host_id: String) -> crate::tokens::ValidatedSession {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        crate::tokens::ValidatedSession {
            client_id: "oaiapp-test".into(),
            subject: "person-test".into(),
            host_id,
            scopes: BTreeSet::from([
                "offline_access".into(),
                "resource.invoke".into(),
                "chatgpt.tokens.use.direct".into(),
            ]),
            expires_at: now + 3600,
            earliest_refresh_at: now + 1800,
            access_token: Zeroizing::new("synthetic-access-token-123".into()),
            refresh_token: Zeroizing::new("synthetic-refresh-token-123".into()),
            id_token: Zeroizing::new("synthetic-id-token-123".into()),
        }
    }

    #[tokio::test]
    async fn signed_grant_dispatch_and_revocation_survive_restart() {
        let (authority, key) = crate::grants::signed_fixture();
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("broker");
        let store = ProtectedStore::open(&dir).unwrap();
        store
            .save(&saved_session(store.host_id().unwrap()))
            .unwrap();
        let broker = BrokerCore::with_transports(
            store,
            key,
            "oaiapp-test".into(),
            "person-test".into(),
            OpenAiAuthority::new().unwrap(),
            fake_transport().await,
        )
        .unwrap();
        let deployment = Deployment {
            campaign_id: "campaign-1",
            lane_id: "lane-1",
            aoe_session_id: "session-1",
        };
        let issued = broker
            .issue_signed(&authority, &deployment, NOW + 1)
            .unwrap();
        let capability = issued.token.to_string();
        assert_eq!(
            broker
                .dispatch(
                    capability.as_bytes(),
                    "campaign-1",
                    "lane-1",
                    &vec![b'x'; MAX_REQUEST_BYTES + 1],
                    NOW + 1,
                )
                .await
                .unwrap_err(),
            BrokerError::InvalidRequest
        );
        assert_eq!(
            broker
                .dispatch(
                    capability.as_bytes(),
                    "campaign-1",
                    "lane-1",
                    REQUEST,
                    NOW + 1
                )
                .await
                .unwrap(),
            COMPLETE.as_bytes()
        );
        assert_eq!(
            broker
                .dispatch(
                    capability.as_bytes(),
                    "campaign-1",
                    "other",
                    REQUEST,
                    NOW + 1
                )
                .await
                .unwrap_err(),
            BrokerError::Denied
        );
        assert!(broker.revoke_lane("campaign-1", "lane-1", NOW + 2).unwrap());
        drop(broker);
        let reopened = BrokerCore::with_transports(
            ProtectedStore::open(&dir).unwrap(),
            key,
            "oaiapp-test".into(),
            "person-test".into(),
            OpenAiAuthority::new().unwrap(),
            fake_transport().await,
        )
        .unwrap();
        assert_eq!(
            reopened
                .dispatch(
                    capability.as_bytes(),
                    "campaign-1",
                    "lane-1",
                    REQUEST,
                    NOW + 2
                )
                .await
                .unwrap_err(),
            BrokerError::Denied
        );
    }
}
