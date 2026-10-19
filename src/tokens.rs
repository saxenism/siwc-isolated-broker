//! Initial token-response validation. Call this only on a bounded HTTP 200
//! body from the fixed OpenAI token endpoint over authenticated TLS.

use std::{
    collections::BTreeSet,
    time::{SystemTime, UNIX_EPOCH},
};

use jsonwebtoken::jwk::JwkSet;
use serde::Deserialize;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    identity::{verify_id_token, verify_refresh_id_token},
    oauth::CodeExchange,
};

const MAX_TOKEN_RESPONSE: usize = 64 * 1024;
const REQUIRED_SCOPES: &[&str] = &["offline_access", "resource.invoke"];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("invalid token response")]
    InvalidResponse,
    #[error("ID token does not bind to this sign-in")]
    InvalidIdentity,
    #[error("the selected ChatGPT account differs from the expected account")]
    WrongAccount,
    #[error("system clock is unavailable")]
    Clock,
}

#[derive(Deserialize)]
struct RawTokenResponse {
    access_token: String,
    refresh_token: String,
    id_token: String,
    token_type: String,
    expires_in: u64,
    scope: String,
    earliest_refresh_at: u64,
}

impl Drop for RawTokenResponse {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        self.id_token.zeroize();
    }
}

/// Lives only in the trusted broker identity. Deliberately lacks Debug,
/// Serialize, and Clone so ordinary logs cannot reveal the token set.
pub struct ValidatedSession {
    pub(crate) client_id: String,
    pub(crate) subject: String,
    pub(crate) host_id: String,
    pub(crate) scopes: BTreeSet<String>,
    pub(crate) expires_at: u64,
    pub(crate) earliest_refresh_at: u64,
    pub(crate) access_token: Zeroizing<String>,
    pub(crate) refresh_token: Zeroizing<String>,
    pub(crate) id_token: Zeroizing<String>,
}

impl ValidatedSession {
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn host_id(&self) -> &str {
        &self.host_id
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub fn earliest_refresh_at(&self) -> u64 {
        self.earliest_refresh_at
    }
    pub fn plan_enabled(&self) -> bool {
        self.scopes.contains("chatgpt.tokens.use.direct")
    }

    /// Only trusted broker code may use this. Never send it to an agent.
    pub fn access_token_for_upstream(&self) -> Option<&str> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        (self.plan_enabled() && self.expires_at > now.saturating_add(30))
            .then_some(self.access_token.as_str())
    }

    /// Use only for the documented token refresh, under a single refresh owner.
    pub fn refresh_form(&self) -> [(&str, &str); 4] {
        [
            ("grant_type", "refresh_token"),
            ("client_id", &self.client_id),
            ("refresh_token", &self.refresh_token),
            ("resource", "https://api.openai.com/v1"),
        ]
    }

    /// For reauthorization only; never log the resulting authorization URL.
    pub fn id_token_hint(&self) -> &str {
        &self.id_token
    }
}

/// Accept a code-exchange response only after the browser callback was bound
/// and consumed. A valid identity without direct-plan scope is retained as a
/// disabled session; no access token is exposed for inference in that state.
pub fn accept_initial_token_response(
    body: &[u8],
    exchange: &CodeExchange,
    jwks: &JwkSet,
    expected_subject: Option<&str>,
) -> Result<ValidatedSession, TokenError> {
    if body.len() > MAX_TOKEN_RESPONSE || exchange.host_id.is_empty() {
        return Err(TokenError::InvalidResponse);
    }
    let mut raw: RawTokenResponse =
        serde_json::from_slice(body).map_err(|_| TokenError::InvalidResponse)?;
    if raw.access_token.is_empty()
        || raw.refresh_token.is_empty()
        || raw.id_token.is_empty()
        || raw.token_type != "Bearer"
        || !(60..=86_400).contains(&raw.expires_in)
    {
        return Err(TokenError::InvalidResponse);
    }
    let scopes: BTreeSet<String> = raw
        .scope
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect();
    if !REQUIRED_SCOPES.iter().all(|scope| scopes.contains(*scope)) {
        return Err(TokenError::InvalidResponse);
    }
    let identity = verify_id_token(
        &raw.id_token,
        jwks,
        &exchange.client_id,
        &exchange.expected_nonce,
    )
    .map_err(|_| TokenError::InvalidIdentity)?;
    if expected_subject.is_some_and(|expected| expected != identity.subject) {
        return Err(TokenError::WrongAccount);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TokenError::Clock)?
        .as_secs();
    let expires_at = now
        .checked_add(raw.expires_in)
        .ok_or(TokenError::InvalidResponse)?;
    if raw.earliest_refresh_at > expires_at.saturating_add(5) {
        return Err(TokenError::InvalidResponse);
    }
    Ok(ValidatedSession {
        client_id: exchange.client_id.clone(),
        subject: identity.subject,
        host_id: exchange.host_id.clone(),
        scopes,
        expires_at,
        earliest_refresh_at: raw.earliest_refresh_at,
        access_token: Zeroizing::new(std::mem::take(&mut raw.access_token)),
        refresh_token: Zeroizing::new(std::mem::take(&mut raw.refresh_token)),
        id_token: Zeroizing::new(std::mem::take(&mut raw.id_token)),
    })
}

/// Accept a rotating refresh response only if its newly signed identity is
/// still the same account and client. The caller must durably save the entire
/// returned set before issuing any new upstream request.
pub fn accept_refresh_token_response(
    body: &[u8],
    previous: &ValidatedSession,
    jwks: &JwkSet,
) -> Result<ValidatedSession, TokenError> {
    if body.len() > MAX_TOKEN_RESPONSE {
        return Err(TokenError::InvalidResponse);
    }
    let mut raw: RawTokenResponse =
        serde_json::from_slice(body).map_err(|_| TokenError::InvalidResponse)?;
    if raw.access_token.is_empty()
        || raw.refresh_token.is_empty()
        || raw.id_token.is_empty()
        || raw.token_type != "Bearer"
        || !(60..=86_400).contains(&raw.expires_in)
    {
        return Err(TokenError::InvalidResponse);
    }
    let scopes: BTreeSet<String> = raw
        .scope
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect();
    if !REQUIRED_SCOPES.iter().all(|scope| scopes.contains(*scope)) {
        return Err(TokenError::InvalidResponse);
    }
    let identity = verify_refresh_id_token(&raw.id_token, jwks, &previous.client_id)
        .map_err(|_| TokenError::InvalidIdentity)?;
    if identity.subject != previous.subject {
        return Err(TokenError::WrongAccount);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TokenError::Clock)?
        .as_secs();
    let expires_at = now
        .checked_add(raw.expires_in)
        .ok_or(TokenError::InvalidResponse)?;
    if raw.earliest_refresh_at > expires_at.saturating_add(5) {
        return Err(TokenError::InvalidResponse);
    }
    Ok(ValidatedSession {
        client_id: previous.client_id.clone(),
        subject: previous.subject.clone(),
        host_id: previous.host_id.clone(),
        scopes,
        expires_at,
        earliest_refresh_at: raw.earliest_refresh_at,
        access_token: Zeroizing::new(std::mem::take(&mut raw.access_token)),
        refresh_token: Zeroizing::new(std::mem::take(&mut raw.refresh_token)),
        id_token: Zeroizing::new(std::mem::take(&mut raw.id_token)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use rand::rngs::OsRng;
    use rsa::{RsaPrivateKey, pkcs8::EncodePrivateKey, traits::PublicKeyParts};
    use serde_json::json;

    #[test]
    fn consent_controls_inference_and_identity_cannot_switch() {
        let key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let pem = key.to_pkcs8_pem(Default::default()).unwrap();
        let encoding = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
        let jwks: JwkSet = serde_json::from_value(json!({"keys":[{
            "kty":"RSA", "kid":"fixture", "use":"sig", "alg":"RS256",
            "n":URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
            "e":URL_SAFE_NO_PAD.encode(key.e().to_bytes_be())
        }]}))
        .unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("fixture".into());
        let id_token = encode(
            &header,
            &json!({
                "sub":"person-1", "iss":"https://auth.openai.com", "aud":"oaiapp-fixture",
                "nonce":"nonce-1", "iat":now, "exp":now+3600
            }),
            &encoding,
        )
        .unwrap();
        let exchange = CodeExchange {
            client_id: "oaiapp-fixture".into(),
            code: "test".into(),
            code_verifier: "verifier".into(),
            redirect_uri: "http://127.0.0.1:1455/auth/callback".into(),
            expected_nonce: "nonce-1".into(),
            host_id: "urn:uuid:123e4567-e89b-42d3-a456-426614174000".into(),
        };
        let mut response = json!({
            "access_token":"synthetic-access", "refresh_token":"synthetic-refresh",
            "id_token":id_token, "token_type":"Bearer", "expires_in":3600,
            "earliest_refresh_at":now+1800,
            "scope":"openid profile email offline_access resource.invoke"
        });
        let disabled = accept_initial_token_response(
            &serde_json::to_vec(&response).unwrap(),
            &exchange,
            &jwks,
            None,
        )
        .unwrap();
        assert!(!disabled.plan_enabled());
        assert!(disabled.access_token_for_upstream().is_none());
        response["scope"] =
            json!("openid profile email offline_access resource.invoke chatgpt.tokens.use.direct");
        let enabled = accept_initial_token_response(
            &serde_json::to_vec(&response).unwrap(),
            &exchange,
            &jwks,
            Some("person-1"),
        )
        .unwrap();
        assert!(enabled.plan_enabled());
        assert_eq!(
            enabled.access_token_for_upstream(),
            Some("synthetic-access")
        );
        assert_eq!(enabled.refresh_form()[1], ("client_id", "oaiapp-fixture"));
        assert!(matches!(
            accept_initial_token_response(
                &serde_json::to_vec(&response).unwrap(),
                &exchange,
                &jwks,
                Some("person-2")
            ),
            Err(TokenError::WrongAccount)
        ));
        response["id_token"] = json!("forged");
        assert!(matches!(
            accept_initial_token_response(
                &serde_json::to_vec(&response).unwrap(),
                &exchange,
                &jwks,
                None
            ),
            Err(TokenError::InvalidIdentity)
        ));

        let refresh_id_token = encode(
            &header,
            &json!({
                "sub":"person-1", "iss":"https://auth.openai.com", "aud":"oaiapp-fixture",
                "iat":now, "exp":now+3600
            }),
            &encoding,
        )
        .unwrap();
        response["id_token"] = json!(refresh_id_token);
        response["refresh_token"] = json!("replacement-refresh");
        let rotated =
            accept_refresh_token_response(&serde_json::to_vec(&response).unwrap(), &enabled, &jwks)
                .unwrap();
        assert_eq!(
            rotated.refresh_form()[2],
            ("refresh_token", "replacement-refresh")
        );
        response["id_token"] = json!(
            encode(
                &header,
                &json!({
                    "sub":"person-2", "iss":"https://auth.openai.com", "aud":"oaiapp-fixture",
                    "iat":now, "exp":now+3600
                }),
                &encoding
            )
            .unwrap()
        );
        assert!(matches!(
            accept_refresh_token_response(&serde_json::to_vec(&response).unwrap(), &enabled, &jwks),
            Err(TokenError::WrongAccount)
        ));
    }
}
