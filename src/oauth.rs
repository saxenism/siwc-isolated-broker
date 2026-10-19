//! Browser authorization request and callback validation for the SIWC OSS flow.
//! An attempt is consumed on callback so its state and PKCE verifier cannot be reused.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use url::Url;
use zeroize::Zeroize;

const AUTHORIZE: &str = "https://auth.openai.com/api/accounts/authorize";
const RESOURCE: &str = "https://api.openai.com/v1";
const SCOPES: &str =
    "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("invalid authorization configuration")]
    InvalidConfiguration,
    #[error("failed to create a cryptographically random authorization attempt")]
    Entropy,
    #[error("callback target does not match the bound loopback listener")]
    WrongCallback,
    #[error("callback has missing or repeated authorization fields")]
    InvalidCallback,
    #[error("authorization state mismatch")]
    StateMismatch,
    #[error("the user declined authorization")]
    AccessDenied,
    #[error("authorization did not complete")]
    AuthorizationFailed,
}

pub enum Registration<'a> {
    New { app_name: &'a str },
    Existing { client_id: &'a str },
}

/// Contains ephemeral secrets. Intentionally does not implement Debug or Clone.
pub struct AuthorizationAttempt {
    authorization_url: Url,
    callback: Url,
    state: String,
    nonce: String,
    pkce_verifier: String,
    existing_client_id: Option<String>,
    host_id: String,
}

impl Drop for AuthorizationAttempt {
    fn drop(&mut self) {
        self.state.zeroize();
        self.nonce.zeroize();
        self.pkce_verifier.zeroize();
    }
}

/// A validated callback still needs code exchange and signed ID-token validation.
/// Intentionally does not implement Debug or Clone.
pub struct CodeExchange {
    pub client_id: String,
    pub code: String,
    pub code_verifier: String,
    pub redirect_uri: String,
    pub expected_nonce: String,
    pub host_id: String,
}

impl Drop for CodeExchange {
    fn drop(&mut self) {
        self.code.zeroize();
        self.code_verifier.zeroize();
        self.expected_nonce.zeroize();
    }
}

impl CodeExchange {
    /// The exact fields for the documented authorization-code token exchange.
    pub fn form(&self) -> [(&str, &str); 6] {
        [
            ("grant_type", "authorization_code"),
            ("client_id", &self.client_id),
            ("code", &self.code),
            ("code_verifier", &self.code_verifier),
            ("redirect_uri", &self.redirect_uri),
            ("resource", RESOURCE),
        ]
    }
}

fn random_secret() -> Result<String, AuthError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| AuthError::Entropy)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn valid_callback(callback: &Url) -> bool {
    callback.scheme() == "http"
        && callback.host_str() == Some("127.0.0.1")
        && callback.port().is_some()
        && callback.path() == "/auth/callback"
        && callback.username().is_empty()
        && callback.password().is_none()
        && callback.query().is_none()
        && callback.fragment().is_none()
}

fn valid_host_id(host_id: &str) -> bool {
    host_id
        .strip_prefix("urn:uuid:")
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .is_some_and(|id| id.get_version_num() == 4)
}

impl AuthorizationAttempt {
    /// The caller must bind the callback listener before directing a browser
    /// to the returned URL. The host ID must persist for this host's lifetime.
    pub fn begin(
        host_id: &str,
        callback: Url,
        registration: Registration<'_>,
    ) -> Result<Self, AuthError> {
        if !valid_host_id(host_id) || !valid_callback(&callback) {
            return Err(AuthError::InvalidConfiguration);
        }
        let (client_id, app_name, existing_client_id) = match registration {
            Registration::New { app_name }
                if !app_name.trim().is_empty() && app_name.len() <= 80 =>
            {
                ("dynamic_agent_client", Some(app_name), None)
            }
            Registration::Existing { client_id }
                if !client_id.is_empty() && client_id != "dynamic_agent_client" =>
            {
                (client_id, None, Some(client_id.to_owned()))
            }
            _ => return Err(AuthError::InvalidConfiguration),
        };
        let state = random_secret()?;
        let nonce = random_secret()?;
        let pkce_verifier = random_secret()?;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(pkce_verifier.as_bytes()));
        let mut authorization_url = Url::parse(AUTHORIZE).expect("constant authorization URL");
        {
            let mut query = authorization_url.query_pairs_mut();
            query
                .append_pair("client_id", client_id)
                .append_pair("ext_agent_host_id", host_id)
                .append_pair("response_type", "code")
                .append_pair("redirect_uri", callback.as_str())
                .append_pair("scope", SCOPES)
                .append_pair("resource", RESOURCE)
                .append_pair("state", &state)
                .append_pair("nonce", &nonce)
                .append_pair("code_challenge_method", "S256")
                .append_pair("code_challenge", &challenge);
            if let Some(name) = app_name {
                query.append_pair("agent_name_hint", name);
            }
        }
        Ok(Self {
            authorization_url,
            callback,
            state,
            nonce,
            pkce_verifier,
            existing_client_id,
            host_id: host_id.to_owned(),
        })
    }

    pub fn authorization_url(&self) -> &Url {
        &self.authorization_url
    }

    pub fn finish(mut self, callback: &Url) -> Result<CodeExchange, AuthError> {
        let mut expected = self.callback.clone();
        expected.set_query(callback.query());
        if callback != &expected {
            return Err(AuthError::WrongCallback);
        }
        let mut code = None;
        let mut state = None;
        let mut returned_client_id = None;
        let mut error = None;
        for (key, value) in callback.query_pairs() {
            let target = match key.as_ref() {
                "code" => &mut code,
                "state" => &mut state,
                "client_id" => &mut returned_client_id,
                "error" => &mut error,
                _ => continue,
            };
            if target.replace(value.into_owned()).is_some() {
                return Err(AuthError::InvalidCallback);
            }
        }
        let state = state.ok_or(AuthError::InvalidCallback)?;
        if state.as_bytes().ct_eq(self.state.as_bytes()).unwrap_u8() != 1 {
            return Err(AuthError::StateMismatch);
        }
        if error.as_deref() == Some("access_denied") {
            return Err(AuthError::AccessDenied);
        }
        if error.is_some() {
            return Err(AuthError::AuthorizationFailed);
        }
        let code = code
            .filter(|code| !code.is_empty())
            .ok_or(AuthError::InvalidCallback)?;
        let client_id = match self.existing_client_id.take() {
            Some(expected) => {
                if returned_client_id
                    .as_deref()
                    .is_some_and(|id| id != expected)
                {
                    return Err(AuthError::InvalidCallback);
                }
                expected
            }
            None => returned_client_id
                .filter(|id| !id.is_empty() && id != "dynamic_agent_client")
                .ok_or(AuthError::InvalidCallback)?,
        };
        Ok(CodeExchange {
            client_id,
            code,
            code_verifier: std::mem::take(&mut self.pkce_verifier),
            redirect_uri: self.callback.to_string(),
            expected_nonce: std::mem::take(&mut self.nonce),
            host_id: std::mem::take(&mut self.host_id),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn begin(registration: Registration<'_>) -> AuthorizationAttempt {
        AuthorizationAttempt::begin(
            "urn:uuid:123e4567-e89b-42d3-a456-426614174000",
            Url::parse("http://127.0.0.1:1455/auth/callback").unwrap(),
            registration,
        )
        .unwrap()
    }

    fn callback(attempt: &AuthorizationAttempt, client_id: &str) -> Url {
        let state = attempt.state.clone();
        Url::parse(&format!(
            "http://127.0.0.1:1455/auth/callback?code=test-code&state={state}&client_id={client_id}"
        ))
        .unwrap()
    }

    #[test]
    fn new_registration_binds_client_pkce_and_host() {
        let attempt = begin(Registration::New {
            app_name: "SIWC Isolated Broker",
        });
        let query: std::collections::HashMap<_, _> = attempt
            .authorization_url()
            .query_pairs()
            .into_owned()
            .collect();
        assert_eq!(query["client_id"], "dynamic_agent_client");
        assert_eq!(query["agent_name_hint"], "SIWC Isolated Broker");
        assert_eq!(query["code_challenge_method"], "S256");
        assert_eq!(query["scope"], SCOPES);
        assert_eq!(query["resource"], RESOURCE);
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(attempt.pkce_verifier.as_bytes()));
        assert_eq!(query["code_challenge"], expected);
        let returned = callback(&attempt, "oaiapp-test");
        let result = attempt.finish(&returned);
        assert!(result.is_ok());
    }

    #[test]
    fn callback_rejects_cross_port_state_and_client_substitution() {
        let attempt = begin(Registration::New { app_name: "Broker" });
        let mut wrong_port = callback(&attempt, "oaiapp-test");
        wrong_port.set_port(Some(1234)).unwrap();
        assert!(matches!(
            attempt.finish(&wrong_port),
            Err(AuthError::WrongCallback)
        ));

        let attempt = begin(Registration::New { app_name: "Broker" });
        let mut wrong_state = callback(&attempt, "oaiapp-test");
        wrong_state
            .query_pairs_mut()
            .clear()
            .append_pair("state", "bad")
            .append_pair("code", "x")
            .append_pair("client_id", "oaiapp-test");
        assert!(matches!(
            attempt.finish(&wrong_state),
            Err(AuthError::StateMismatch)
        ));

        let attempt = begin(Registration::Existing {
            client_id: "oaiapp-original",
        });
        let substituted = callback(&attempt, "oaiapp-other");
        assert!(matches!(
            attempt.finish(&substituted),
            Err(AuthError::InvalidCallback)
        ));
    }

    #[test]
    fn callback_rejects_duplicate_fields_and_requires_issued_client() {
        let attempt = begin(Registration::New { app_name: "Broker" });
        let mut duplicated = callback(&attempt, "oaiapp-test");
        duplicated.query_pairs_mut().append_pair("state", "again");
        assert!(matches!(
            attempt.finish(&duplicated),
            Err(AuthError::InvalidCallback)
        ));

        let attempt = begin(Registration::New { app_name: "Broker" });
        let missing = Url::parse(&format!(
            "http://127.0.0.1:1455/auth/callback?code=x&state={}",
            attempt.state
        ))
        .unwrap();
        assert!(matches!(
            attempt.finish(&missing),
            Err(AuthError::InvalidCallback)
        ));
    }

    #[test]
    fn callback_returns_exact_exchange_form() {
        let attempt = begin(Registration::Existing {
            client_id: "oaiapp-original",
        });
        let callback = callback(&attempt, "oaiapp-original");
        let exchange = attempt.finish(&callback).unwrap();
        assert_eq!(exchange.client_id, "oaiapp-original");
        assert_eq!(exchange.form()[0], ("grant_type", "authorization_code"));
        assert_eq!(exchange.form()[5], ("resource", RESOURCE));
    }
}
