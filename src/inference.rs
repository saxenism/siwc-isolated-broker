//! Fixed-route ChatGPT-plan transport. A trusted caller must reserve a lane's
//! durable request budget before invoking this module. No upstream headers or
//! error bodies are returned. Successful SSE is checked before release.

use std::time::Duration;

use reqwest::{Client, StatusCode, Url, redirect::Policy};
use serde_json::Value;
use thiserror::Error;

use crate::{policy::valid_plan_request, tokens::ValidatedSession};

const RESPONSES_ENDPOINT: &str = "https://api.openai.com/v1/responses";
const MAX_REQUEST: usize = 1024 * 1024;
const MAX_RESPONSE: usize = 32 * 1024 * 1024;
const MAX_EVENTS: usize = 100_000;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum InferenceError {
    #[error("model request violates the approved plan route")]
    InvalidRequest,
    #[error("selected account lacks valid plan authorization")]
    Unauthorized,
    #[error("OpenAI model transport failed")]
    Transport,
    #[error("OpenAI model route returned HTTP {0}")]
    Http(u16),
    #[error("OpenAI model response was incomplete, invalid, or exceeded the size limit")]
    InvalidResponse,
}

/// Runs only in the trusted credential-owning broker identity. It deliberately
/// has no generic URL forwarding method in non-test builds.
pub struct PlanInference {
    client: Client,
    endpoint: Url,
}

impl PlanInference {
    pub fn new() -> Result<Self, InferenceError> {
        let client = Client::builder()
            .no_proxy()
            .https_only(true)
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(600))
            .build()
            .map_err(|_| InferenceError::Transport)?;
        Ok(Self {
            client,
            endpoint: Url::parse(RESPONSES_ENDPOINT).expect("fixed Responses endpoint"),
        })
    }

    /// The caller must verify and durably reserve a signed, unexpired lane
    /// grant before this call. A failed or uncertain upstream call still burns
    /// that reservation. Success is buffered and bounded; incremental release
    /// needs a separate streaming quarantine design and live latency tests.
    pub async fn complete(
        &self,
        session: &ValidatedSession,
        request: &[u8],
        allowed_model: &str,
    ) -> Result<Vec<u8>, InferenceError> {
        if request.is_empty() || request.len() > MAX_REQUEST {
            return Err(InferenceError::InvalidRequest);
        }
        let value: Value =
            serde_json::from_slice(request).map_err(|_| InferenceError::InvalidRequest)?;
        if !valid_plan_request(&value, allowed_model) {
            return Err(InferenceError::InvalidRequest);
        }
        let access_token = session
            .access_token_for_upstream()
            .ok_or(InferenceError::Unauthorized)?;
        let mut upstream = self
            .client
            .post(self.endpoint.clone())
            .bearer_auth(access_token)
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(request.to_vec())
            .send()
            .await
            .map_err(|_| InferenceError::Transport)?;
        if upstream.status() != StatusCode::OK {
            return Err(InferenceError::Http(upstream.status().as_u16()));
        }
        let is_sse = upstream
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|header| header.to_str().ok())
            .is_some_and(|value| value.to_ascii_lowercase().starts_with("text/event-stream"));
        if !is_sse {
            return Err(InferenceError::InvalidResponse);
        }
        let mut body = Vec::new();
        while let Some(chunk) = upstream
            .chunk()
            .await
            .map_err(|_| InferenceError::Transport)?
        {
            if chunk.len() > MAX_RESPONSE.saturating_sub(body.len()) {
                return Err(InferenceError::InvalidResponse);
            }
            body.extend_from_slice(&chunk);
        }
        if reflects_any_credential(&body, session) || !validated_complete_sse(&body) {
            return Err(InferenceError::InvalidResponse);
        }
        Ok(body)
    }

    #[cfg(test)]
    pub(crate) fn for_loopback_test(endpoint: Url) -> Self {
        Self {
            client: Client::builder().no_proxy().build().unwrap(),
            endpoint,
        }
    }
}

fn reflects_any_credential(body: &[u8], session: &ValidatedSession) -> bool {
    for credential in [
        session.access_token.as_bytes(),
        session.refresh_token.as_bytes(),
        session.id_token.as_bytes(),
    ] {
        if credential.len() >= 8
            && body
                .windows(credential.len())
                .any(|window| window == credential)
        {
            return true;
        }
    }
    false
}

/// Validate one bounded Responses SSE body before a trusted caller releases it
/// to a Codex client. It does not inspect upstream error bodies or credentials.
pub fn validated_complete_sse(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let normalized = text.replace("\r\n", "\n");
    let mut created = false;
    let mut completed = false;
    let mut count = 0;
    for frame in normalized
        .split("\n\n")
        .filter(|frame| !frame.trim().is_empty())
    {
        let mut event = None;
        let mut data = Vec::new();
        for line in frame.lines() {
            if let Some(value) = line.strip_prefix("event:") {
                if event.replace(value.trim()).is_some() {
                    return false;
                }
            } else if let Some(value) = line.strip_prefix("data:") {
                data.push(value.trim_start());
            } else if !line.starts_with(':') {
                return false;
            }
        }
        if data.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(&data.join("\n")) else {
            return false;
        };
        let Some(kind) = value.get("type").and_then(Value::as_str) else {
            return false;
        };
        if event.is_some_and(|name| name != kind) || completed {
            return false;
        }
        if matches!(kind, "error" | "response.failed" | "response.incomplete") {
            return false;
        }
        if kind == "response.created" {
            if created {
                return false;
            }
            created = true;
        } else if kind == "response.completed" {
            completed = created
                && value
                    .get("response")
                    .and_then(|response| response.get("status"))
                    .and_then(Value::as_str)
                    == Some("completed");
        }
        count += 1;
        if count > MAX_EVENTS {
            return false;
        }
    }
    created && completed
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        http::{HeaderMap, StatusCode as AxumStatus, header},
        routing::post,
    };
    use std::{
        collections::BTreeSet,
        time::{SystemTime, UNIX_EPOCH},
    };
    use zeroize::Zeroizing;

    fn session() -> ValidatedSession {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        ValidatedSession {
            client_id: "oaiapp-test".into(),
            subject: "person-test".into(),
            host_id: "urn:uuid:123e4567-e89b-42d3-a456-426614174000".into(),
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

    async fn transport_with_body(body: &'static str, status: AxumStatus) -> PlanInference {
        let app = Router::new().route(
            "/v1/responses",
            post(move |headers: HeaderMap| async move {
                if headers
                    .get(header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    != Some("Bearer synthetic-access-token-123")
                {
                    return (
                        AxumStatus::FORBIDDEN,
                        [("content-type", "text/event-stream")],
                        "missing broker token",
                    );
                }
                (status, [("content-type", "text/event-stream")], body)
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        PlanInference::for_loopback_test(
            Url::parse(&format!("http://{address}/v1/responses")).unwrap(),
        )
    }

    const REQUEST: &[u8] = br#"{"model":"test-model","store":false,"stream":true,"input":[{"role":"user","content":"hi"}]}"#;
    const COMPLETE: &str = "event: response.created\ndata: {\"type\":\"response.created\"}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n";

    #[tokio::test]
    async fn exact_plan_request_and_completed_sse_pass() {
        let transport = transport_with_body(COMPLETE, AxumStatus::OK).await;
        assert_eq!(
            transport
                .complete(&session(), REQUEST, "test-model")
                .await
                .unwrap(),
            COMPLETE.as_bytes()
        );
        assert_eq!(
            transport
                .complete(&session(), REQUEST, "other-model")
                .await
                .unwrap_err(),
            InferenceError::InvalidRequest
        );
        let mut without_plan = session();
        without_plan.scopes.remove("chatgpt.tokens.use.direct");
        assert_eq!(
            transport
                .complete(&without_plan, REQUEST, "test-model")
                .await
                .unwrap_err(),
            InferenceError::Unauthorized
        );
    }

    #[tokio::test]
    async fn upstream_errors_failure_events_and_reflections_are_quarantined() {
        let transport =
            transport_with_body("synthetic-access-token-123", AxumStatus::UNAUTHORIZED).await;
        assert_eq!(
            transport
                .complete(&session(), REQUEST, "test-model")
                .await
                .unwrap_err(),
            InferenceError::Http(401)
        );
        let transport = transport_with_body(
            "event: response.failed\ndata: {\"type\":\"response.failed\"}\n\n",
            AxumStatus::OK,
        )
        .await;
        assert_eq!(
            transport
                .complete(&session(), REQUEST, "test-model")
                .await
                .unwrap_err(),
            InferenceError::InvalidResponse
        );
        let transport = transport_with_body("event: response.created\ndata: {\"type\":\"response.created\"}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"},\"leak\":\"synthetic-access-token-123\"}\n\n", AxumStatus::OK).await;
        assert_eq!(
            transport
                .complete(&session(), REQUEST, "test-model")
                .await
                .unwrap_err(),
            InferenceError::InvalidResponse
        );
    }

    #[test]
    fn completion_parser_rejects_late_failure_and_truncated_stream() {
        assert!(validated_complete_sse(COMPLETE.as_bytes()));
        assert!(!validated_complete_sse(
            b"event: response.created\ndata: {\"type\":\"response.created\"}\n\n"
        ));
        let late_failure =
            format!("{COMPLETE}event: response.failed\ndata: {{\"type\":\"response.failed\"}}\n\n");
        assert!(!validated_complete_sse(late_failure.as_bytes()));
        assert!(!validated_complete_sse(
            b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n"
        ));
    }
}
