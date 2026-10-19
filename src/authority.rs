//! Fixed OpenAI token endpoint and issuer JWKS transport. No response body or
//! token is ever included in an error. A caller must run this under the
//! credential-owning broker OS identity, never inside an agent process.

use std::time::Duration;

use jsonwebtoken::jwk::JwkSet;
use reqwest::{Client, StatusCode, Url, redirect::Policy};
use thiserror::Error;
use zeroize::Zeroizing;

#[cfg(unix)]
use crate::storage::{ProtectedStore, StoreError};
use crate::{
    oauth::CodeExchange,
    tokens::{
        TokenError, ValidatedSession, accept_initial_token_response, accept_refresh_token_response,
    },
};

const TOKEN_ENDPOINT: &str = "https://auth.openai.com/api/accounts/oauth/token";
const JWKS_ENDPOINT: &str = "https://auth.openai.com/.well-known/jwks.json";
const MAX_JWKS: usize = 256 * 1024;
const MAX_TOKEN_BODY: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum AuthorityError {
    #[error("OpenAI authority transport failed")]
    Transport,
    #[error("OpenAI authority returned HTTP {0}")]
    Http(u16),
    #[error("OpenAI authority response exceeded size limit")]
    TooLarge,
    #[error("OpenAI authority response was invalid")]
    InvalidResponse,
    #[error("OpenAI sign-in validation failed: {0}")]
    Token(#[from] TokenError),
    #[cfg(unix)]
    #[error("protected credential store rejected rotation: {0}")]
    Store(#[from] StoreError),
    #[error("refresh is not yet permitted by the issued token set")]
    RefreshTooEarly,
}

pub struct OpenAiAuthority {
    client: Client,
    token_endpoint: Url,
    jwks_endpoint: Url,
}

impl OpenAiAuthority {
    pub fn new() -> Result<Self, AuthorityError> {
        let client = Client::builder()
            .no_proxy()
            .https_only(true)
            .redirect(Policy::none())
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| AuthorityError::Transport)?;
        Ok(Self {
            client,
            token_endpoint: Url::parse(TOKEN_ENDPOINT).expect("fixed token endpoint"),
            jwks_endpoint: Url::parse(JWKS_ENDPOINT).expect("fixed JWKS endpoint"),
        })
    }

    async fn bounded_body(
        mut response: reqwest::Response,
        max: usize,
    ) -> Result<Vec<u8>, AuthorityError> {
        let mut result = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| AuthorityError::Transport)?
        {
            if chunk.len() > max.saturating_sub(result.len()) {
                return Err(AuthorityError::TooLarge);
            }
            result.extend_from_slice(&chunk);
        }
        Ok(result)
    }

    /// Retrieve trusted keys from the fixed issuer. This must not accept a
    /// target-supplied discovery URL or an arbitrary JWKS endpoint.
    pub async fn fetch_jwks(&self) -> Result<JwkSet, AuthorityError> {
        let response = self
            .client
            .get(self.jwks_endpoint.clone())
            .send()
            .await
            .map_err(|_| AuthorityError::Transport)?;
        if response.status() != StatusCode::OK {
            return Err(AuthorityError::Http(response.status().as_u16()));
        }
        let bytes = Self::bounded_body(response, MAX_JWKS).await?;
        let jwks: JwkSet =
            serde_json::from_slice(&bytes).map_err(|_| AuthorityError::InvalidResponse)?;
        if jwks.keys.is_empty() {
            return Err(AuthorityError::InvalidResponse);
        }
        Ok(jwks)
    }

    /// Consumes a validated callback exactly once. Fetches JWKS first so a
    /// temporary key-service failure does not consume the authorization code.
    pub async fn exchange_code(
        &self,
        exchange: CodeExchange,
        expected_subject: Option<&str>,
    ) -> Result<ValidatedSession, AuthorityError> {
        let jwks = self.fetch_jwks().await?;
        let response = self
            .client
            .post(self.token_endpoint.clone())
            .header("accept", "application/json")
            .form(&exchange.form())
            .send()
            .await
            .map_err(|_| AuthorityError::Transport)?;
        if response.status() != StatusCode::OK {
            return Err(AuthorityError::Http(response.status().as_u16()));
        }
        let body = Zeroizing::new(Self::bounded_body(response, MAX_TOKEN_BODY).await?);
        accept_initial_token_response(&body, &exchange, &jwks, expected_subject)
            .map_err(AuthorityError::Token)
    }

    /// The store's process lock and async gate serialize refreshes. An
    /// uncertain result leaves a durable marker so automatic retries stop.
    #[cfg(unix)]
    pub async fn refresh_session(
        &self,
        store: &ProtectedStore,
        client_id: &str,
        host_id: &str,
        subject: &str,
    ) -> Result<ValidatedSession, AuthorityError> {
        let _guard = store.lock_refresh().await;
        let previous = store.load(client_id, host_id, subject)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| AuthorityError::InvalidResponse)?
            .as_secs();
        if now < previous.earliest_refresh_at() {
            return Err(AuthorityError::RefreshTooEarly);
        }
        let jwks = self.fetch_jwks().await?;
        store.begin_refresh(&previous)?;
        let response = self
            .client
            .post(self.token_endpoint.clone())
            .header("accept", "application/json")
            .form(&previous.refresh_form())
            .send()
            .await
            .map_err(|_| AuthorityError::Transport)?;
        if response.status() != StatusCode::OK {
            return Err(AuthorityError::Http(response.status().as_u16()));
        }
        let body = Zeroizing::new(Self::bounded_body(response, MAX_TOKEN_BODY).await?);
        let rotated = accept_refresh_token_response(&body, &previous, &jwks)?;
        store.commit_refresh(&rotated)?;
        Ok(rotated)
    }

    #[cfg(test)]
    fn for_loopback_test(base: &str) -> Self {
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        Self {
            client,
            token_endpoint: Url::parse(&format!("{base}/token")).unwrap(),
            jwks_endpoint: Url::parse(&format!("{base}/jwks")).unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Form, Json, Router,
        extract::State,
        routing::{get, post},
    };
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use rand::rngs::OsRng;
    use rsa::{RsaPrivateKey, pkcs8::EncodePrivateKey, traits::PublicKeyParts};
    use serde_json::{Value, json};
    use std::{
        collections::HashMap,
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    struct FakeAuthority {
        jwks: Value,
        token: Value,
        refresh: Value,
    }

    async fn jwks(State(fake): State<Arc<FakeAuthority>>) -> Json<Value> {
        Json(fake.jwks.clone())
    }

    async fn token(
        State(fake): State<Arc<FakeAuthority>>,
        Form(form): Form<HashMap<String, String>>,
    ) -> Result<Json<Value>, StatusCode> {
        match form.get("grant_type").map(String::as_str) {
            Some("authorization_code")
                if form.get("client_id").map(String::as_str) == Some("oaiapp-fixture")
                    && form.get("code_verifier").map(String::as_str) == Some("verifier")
                    && form.get("resource").map(String::as_str)
                        == Some("https://api.openai.com/v1")
                    && form.len() == 6 =>
            {
                Ok(Json(fake.token.clone()))
            }
            Some("refresh_token")
                if form.get("client_id").map(String::as_str) == Some("oaiapp-fixture")
                    && form.get("refresh_token").map(String::as_str)
                        == Some("synthetic-refresh")
                    && form.get("resource").map(String::as_str)
                        == Some("https://api.openai.com/v1")
                    && form.len() == 4 =>
            {
                Ok(Json(fake.refresh.clone()))
            }
            _ => Err(StatusCode::FORBIDDEN),
        }
    }

    #[tokio::test]
    async fn fixed_shape_exchange_validates_a_fake_signed_response() {
        let key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let pem = key.to_pkcs8_pem(Default::default()).unwrap();
        let encoding = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
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
        let refresh_id_token = encode(
            &header,
            &json!({
                "sub":"person-1", "iss":"https://auth.openai.com", "aud":"oaiapp-fixture",
                "iat":now, "exp":now+3600
            }),
            &encoding,
        )
        .unwrap();
        let fake = Arc::new(FakeAuthority {
            jwks: json!({"keys":[{
                "kty":"RSA", "kid":"fixture", "use":"sig", "alg":"RS256",
                "n":URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
                "e":URL_SAFE_NO_PAD.encode(key.e().to_bytes_be())
            }]}),
            token: json!({
                "access_token":"synthetic-access", "refresh_token":"synthetic-refresh",
                "id_token":id_token, "token_type":"Bearer", "expires_in":3600,
                "earliest_refresh_at":now,
                "scope":"openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
            }),
            refresh: json!({
                "access_token":"replacement-access", "refresh_token":"replacement-refresh",
                "id_token":refresh_id_token, "token_type":"Bearer", "expires_in":3600,
                "earliest_refresh_at":now+1800,
                "scope":"openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
            }),
        });
        let app = Router::new()
            .route("/jwks", get(jwks))
            .route("/token", post(token))
            .with_state(fake);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let authority = OpenAiAuthority::for_loopback_test(&format!("http://{address}"));
        let exchange = CodeExchange {
            client_id: "oaiapp-fixture".into(),
            code: "test-code".into(),
            code_verifier: "verifier".into(),
            redirect_uri: "http://127.0.0.1:1455/auth/callback".into(),
            expected_nonce: "nonce-1".into(),
            host_id: "urn:uuid:123e4567-e89b-42d3-a456-426614174000".into(),
        };
        let session = authority.exchange_code(exchange, None).await.unwrap();
        assert!(session.plan_enabled());
        assert_eq!(session.subject(), "person-1");
        assert_eq!(
            session.access_token_for_upstream(),
            Some("synthetic-access")
        );
        #[cfg(unix)]
        {
            let temp = tempfile::tempdir().unwrap();
            let store = ProtectedStore::open(&temp.path().join("credentials")).unwrap();
            store.save(&session).unwrap();
            let rotated = authority
                .refresh_session(
                    &store,
                    session.client_id(),
                    session.host_id(),
                    session.subject(),
                )
                .await
                .unwrap();
            assert_eq!(
                rotated.access_token_for_upstream(),
                Some("replacement-access")
            );
            let recovered = store
                .load(session.client_id(), session.host_id(), session.subject())
                .unwrap();
            assert_eq!(
                recovered.refresh_form()[2],
                ("refresh_token", "replacement-refresh")
            );
        }
        task.abort();
    }
}
