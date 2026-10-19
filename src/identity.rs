//! Signed ID-token validation. The caller must obtain JWKS from the fixed
//! OpenAI issuer over authenticated TLS and refresh it on an unknown key ID.

use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{JwkSet, KeyAlgorithm, PublicKeyUse},
};
use serde::Deserialize;
use serde_json::Value;
use subtle::ConstantTimeEq;
use thiserror::Error;

const ISSUER: &str = "https://auth.openai.com";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdentityError {
    #[error("invalid or untrusted ID token")]
    InvalidToken,
    #[error("trusted signing key is unavailable; refresh issuer JWKS")]
    UnknownKey,
    #[error("system clock is unavailable")]
    Clock,
}

#[derive(Deserialize)]
struct Claims {
    sub: String,
    nonce: String,
    iat: u64,
    exp: u64,
    iss: String,
    aud: Value,
}

/// The verified identity is deliberately small. Tokens stay in protected
/// broker storage and are never returned to an agent or a campaign controller.
pub struct VerifiedIdentity {
    pub subject: String,
}

/// Verify signature, issuer, audience, expiry, issued-at, and transaction nonce.
/// An unknown `kid` is distinct so the trusted broker can refresh JWKS once.
pub fn verify_id_token(
    token: &str,
    jwks: &JwkSet,
    expected_client_id: &str,
    expected_nonce: &str,
) -> Result<VerifiedIdentity, IdentityError> {
    if expected_client_id.is_empty() || expected_nonce.is_empty() || token.len() > 32_768 {
        return Err(IdentityError::InvalidToken);
    }
    let header = decode_header(token).map_err(|_| IdentityError::InvalidToken)?;
    if header.alg != Algorithm::RS256 {
        return Err(IdentityError::InvalidToken);
    }
    let kid = header.kid.as_deref().ok_or(IdentityError::InvalidToken)?;
    let jwk = jwks.find(kid).ok_or(IdentityError::UnknownKey)?;
    if jwk.common.public_key_use != Some(PublicKeyUse::Signature)
        || jwk.common.key_algorithm != Some(KeyAlgorithm::RS256)
    {
        return Err(IdentityError::InvalidToken);
    }
    let key = DecodingKey::from_jwk(jwk).map_err(|_| IdentityError::InvalidToken)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.leeway = 5;
    validation.validate_nbf = true;
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[expected_client_id]);
    validation.required_spec_claims = ["sub", "exp", "iss", "aud"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let claims = decode::<Claims>(token, &key, &validation)
        .map_err(|_| IdentityError::InvalidToken)?
        .claims;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| IdentityError::Clock)?
        .as_secs();
    let valid_audience = claims.aud.as_str() == Some(expected_client_id)
        || claims.aud.as_array().is_some_and(|items| {
            items
                .iter()
                .any(|item| item.as_str() == Some(expected_client_id))
        });
    if claims.sub.is_empty()
        || claims.iss != ISSUER
        || !valid_audience
        || claims.iat > now.saturating_add(5)
        || claims.exp <= claims.iat
        || claims
            .nonce
            .as_bytes()
            .ct_eq(expected_nonce.as_bytes())
            .unwrap_u8()
            != 1
    {
        return Err(IdentityError::InvalidToken);
    }
    Ok(VerifiedIdentity {
        subject: claims.sub,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::{EncodingKey, Header, encode};
    use rand::rngs::OsRng;
    use rsa::{RsaPrivateKey, pkcs8::EncodePrivateKey, traits::PublicKeyParts};
    use serde_json::json;

    #[test]
    fn signed_identity_binds_client_issuer_nonce_and_time() {
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
        let claims = json!({
            "sub":"person-1", "iss":ISSUER, "aud":"oaiapp-fixture",
            "nonce":"bound-nonce", "iat":now, "exp":now + 3600
        });
        let token = encode(&header, &claims, &encoding).unwrap();
        assert_eq!(
            verify_id_token(&token, &jwks, "oaiapp-fixture", "bound-nonce")
                .unwrap()
                .subject,
            "person-1"
        );
        assert!(matches!(
            verify_id_token(&token, &jwks, "other", "bound-nonce"),
            Err(IdentityError::InvalidToken)
        ));
        assert!(matches!(
            verify_id_token(&token, &jwks, "oaiapp-fixture", "other"),
            Err(IdentityError::InvalidToken)
        ));
        let mut modified = claims.clone();
        modified["iss"] = json!("https://attacker.example");
        let wrong_issuer = encode(&header, &modified, &encoding).unwrap();
        assert!(matches!(
            verify_id_token(&wrong_issuer, &jwks, "oaiapp-fixture", "bound-nonce"),
            Err(IdentityError::InvalidToken)
        ));
        modified = claims.clone();
        modified["exp"] = json!(now - 30);
        let expired = encode(&header, &modified, &encoding).unwrap();
        assert!(matches!(
            verify_id_token(&expired, &jwks, "oaiapp-fixture", "bound-nonce"),
            Err(IdentityError::InvalidToken)
        ));
        let empty_jwks = JwkSet { keys: vec![] };
        assert!(matches!(
            verify_id_token(&token, &empty_jwks, "oaiapp-fixture", "bound-nonce"),
            Err(IdentityError::UnknownKey)
        ));
    }
}
