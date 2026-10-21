//! Loopback browser callback for a broker process running under its own OS
//! identity. The listener binds only 127.0.0.1 and holds one pending attempt.

use std::{
    num::NonZeroU16,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    extract::{OriginalUri, State},
    response::Html,
    routing::get,
};
use thiserror::Error;
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle, time::timeout};
use url::Url;

use crate::{
    authority::{AuthorityError, OpenAiAuthority},
    oauth::{AuthError, AuthorizationAttempt, CodeExchange, Registration},
    storage::{ProtectedStore, StoreError},
};

const APP_NAME: &str = "SIWC Isolated Broker";
const CALLBACK_WAIT: Duration = Duration::from_secs(300);

#[derive(Debug, Error)]
pub enum LoginError {
    #[error("loopback callback listener failed")]
    Listener,
    #[error("browser callback did not arrive in time")]
    Timeout,
    #[error("authorization failed: {0}")]
    Authorization(#[from] AuthError),
    #[error("OpenAI authority failed: {0}")]
    Authority(#[from] AuthorityError),
    #[error("protected credential store failed: {0}")]
    Store(#[from] StoreError),
    #[error("broker host identity changed during sign-in")]
    HostChanged,
}

#[derive(Clone)]
struct CallbackState {
    port: u16,
    sender: Arc<Mutex<Option<oneshot::Sender<Url>>>>,
}

async fn callback(
    State(state): State<CallbackState>,
    OriginalUri(uri): OriginalUri,
) -> Html<&'static str> {
    let mut url = Url::parse(&format!("http://127.0.0.1:{}/auth/callback", state.port))
        .expect("bound loopback callback URL");
    url.set_query(uri.query());
    if let Ok(mut sender) = state.sender.lock()
        && let Some(sender) = sender.take()
    {
        let _ = sender.send(url);
    }
    Html(
        "<!doctype html><meta charset=utf-8><title>Callback received</title><script>history.replaceState(null,'','/auth/complete')</script>Callback received. Return to the broker to see the result.",
    )
}

/// A one-time browser attempt. It does not implement Debug or Clone because
/// the authorization URL contains state and nonce values.
pub struct LoginSession {
    attempt: Option<AuthorizationAttempt>,
    expected_subject: Option<String>,
    receiver: Option<oneshot::Receiver<Url>>,
    server: JoinHandle<()>,
}

pub struct LoginOutcome {
    pub client_id: String,
    pub subject: String,
    pub plan_enabled: bool,
}

impl Drop for LoginSession {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl LoginSession {
    /// Register another ChatGPT account or workspace with this broker host.
    pub async fn start(store: &ProtectedStore) -> Result<Self, LoginError> {
        Self::start_inner(store, Registration::New { app_name: APP_NAME }, None, None).await
    }

    /// Bind a known loopback port so a user can forward only that port over
    /// SSH to a trusted VM. The credential exchange still runs on the VM.
    pub async fn start_on_port(
        store: &ProtectedStore,
        port: NonZeroU16,
    ) -> Result<Self, LoginError> {
        Self::start_inner(
            store,
            Registration::New { app_name: APP_NAME },
            None,
            Some(port),
        )
        .await
    }

    /// Reauthorize one previously validated account. The account selector is
    /// shown in the browser; the signed replacement identity must still match
    /// the selected record before any credential is replaced.
    pub async fn start_returning(
        store: &ProtectedStore,
        client_id: &str,
        subject: &str,
    ) -> Result<Self, LoginError> {
        let host_id = store.host_id()?;
        let _previous = store.load(client_id, &host_id, subject)?;
        Self::start_inner(
            store,
            Registration::Existing { client_id },
            Some(subject.to_owned()),
            None,
        )
        .await
    }

    /// Reauthorize a saved identity through a pre-established SSH tunnel.
    pub async fn start_returning_on_port(
        store: &ProtectedStore,
        client_id: &str,
        subject: &str,
        port: NonZeroU16,
    ) -> Result<Self, LoginError> {
        let host_id = store.host_id()?;
        let _previous = store.load(client_id, &host_id, subject)?;
        Self::start_inner(
            store,
            Registration::Existing { client_id },
            Some(subject.to_owned()),
            Some(port),
        )
        .await
    }

    async fn start_inner(
        store: &ProtectedStore,
        registration: Registration<'_>,
        expected_subject: Option<String>,
        callback_port: Option<NonZeroU16>,
    ) -> Result<Self, LoginError> {
        let host_id = store.host_id()?;
        let listen = format!("127.0.0.1:{}", callback_port.map_or(0, NonZeroU16::get));
        let listener = TcpListener::bind(listen)
            .await
            .map_err(|_| LoginError::Listener)?;
        let port = listener
            .local_addr()
            .map_err(|_| LoginError::Listener)?
            .port();
        let callback_uri = Url::parse(&format!("http://127.0.0.1:{port}/auth/callback"))
            .expect("bound loopback callback URL");
        let attempt = AuthorizationAttempt::begin(&host_id, callback_uri, registration)?;
        let (sender, receiver) = oneshot::channel();
        let state = CallbackState {
            port,
            sender: Arc::new(Mutex::new(Some(sender))),
        };
        let router = Router::new()
            .route("/auth/callback", get(callback))
            .with_state(state);
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        Ok(Self {
            attempt: Some(attempt),
            expected_subject,
            receiver: Some(receiver),
            server,
        })
    }

    /// Show as a Continue with ChatGPT action in the trusted login UI. Do not
    /// log or send this URL to an untrusted agent or research transcript.
    pub fn authorization_url(&self) -> &Url {
        self.attempt
            .as_ref()
            .expect("pending attempt")
            .authorization_url()
    }

    async fn receive_code(&mut self) -> Result<CodeExchange, LoginError> {
        let receiver = self.receiver.take().ok_or(LoginError::Listener)?;
        let callback = timeout(CALLBACK_WAIT, receiver)
            .await
            .map_err(|_| LoginError::Timeout)?
            .map_err(|_| LoginError::Listener)?;
        self.attempt
            .take()
            .ok_or(LoginError::Listener)?
            .finish(&callback)
            .map_err(LoginError::Authorization)
    }

    pub async fn complete(
        mut self,
        authority: &OpenAiAuthority,
        store: &ProtectedStore,
    ) -> Result<LoginOutcome, LoginError> {
        let exchange = self.receive_code().await?;
        if exchange.host_id != store.host_id()? {
            return Err(LoginError::HostChanged);
        }
        let session = authority
            .exchange_code(exchange, self.expected_subject.as_deref())
            .await?;
        store.save(&session)?;
        Ok(LoginOutcome {
            client_id: session.client_id().to_owned(),
            subject: session.subject().to_owned(),
            plan_enabled: session.plan_enabled(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fixed_callback_port_is_loopback_only_and_exclusive() {
        let temp = tempfile::tempdir().unwrap();
        let store = ProtectedStore::open(&temp.path().join("credentials")).unwrap();
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = NonZeroU16::new(reserved.local_addr().unwrap().port()).unwrap();
        drop(reserved);
        let login = LoginSession::start_on_port(&store, port).await.unwrap();
        let callback = login
            .authorization_url()
            .query_pairs()
            .find(|(key, _)| key == "redirect_uri")
            .unwrap()
            .1
            .into_owned();
        assert_eq!(callback, format!("http://127.0.0.1:{port}/auth/callback"));
        assert!(matches!(
            LoginSession::start_on_port(&store, port).await,
            Err(LoginError::Listener)
        ));
    }

    #[tokio::test]
    async fn loopback_callback_preserves_exact_state_and_issued_client() {
        let temp = tempfile::tempdir().unwrap();
        let store = ProtectedStore::open(&temp.path().join("credentials")).unwrap();
        let mut login = LoginSession::start(&store).await.unwrap();
        let query: std::collections::HashMap<_, _> = login
            .authorization_url()
            .query_pairs()
            .into_owned()
            .collect();
        let callback = format!(
            "{}?code=fake-code&state={}&client_id=oaiapp-fixture",
            query["redirect_uri"], query["state"]
        );
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(callback)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let exchange = login.receive_code().await.unwrap();
        assert_eq!(exchange.client_id, "oaiapp-fixture");
        assert_eq!(exchange.host_id, store.host_id().unwrap());
    }

    #[tokio::test]
    async fn returning_account_requires_saved_identity() {
        let temp = tempfile::tempdir().unwrap();
        let store = ProtectedStore::open(&temp.path().join("credentials")).unwrap();
        assert!(
            LoginSession::start_returning(&store, "oaiapp-missing", "person-1")
                .await
                .is_err()
        );
    }
}
