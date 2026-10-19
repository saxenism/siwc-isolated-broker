//! Agent-side Codex connector. It owns only a revocable lane capability and
//! can reach only the broker's agent Unix socket. It never loads SIWC tokens.

use std::{convert::Infallible, io, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Bytes, Incoming},
    header::{self, HeaderValue},
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use tokio::{
    net::{TcpListener, UnixStream},
    sync::Semaphore,
    time::timeout,
};
use zeroize::Zeroizing;

use crate::inference::validated_complete_sse;

const MAX_REQUEST: usize = 1024 * 1024;
const MAX_RESPONSE: usize = 32 * 1024 * 1024;
const DENIED: &[u8] = b"{\"error\":{\"message\":\"lane model request rejected\"}}";

pub struct AgentBridge {
    socket: PathBuf,
    capability: Zeroizing<String>,
    campaign_id: String,
    lane_id: String,
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn reply(status: StatusCode, content_type: &'static str, body: Vec<u8>) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

fn reject(status: StatusCode) -> Response<Full<Bytes>> {
    reply(status, "application/json", DENIED.to_vec())
}

impl AgentBridge {
    pub fn new(
        socket: PathBuf,
        capability: Zeroizing<String>,
        campaign_id: String,
        lane_id: String,
    ) -> io::Result<Self> {
        let valid_capability = URL_SAFE_NO_PAD
            .decode(capability.as_bytes())
            .is_ok_and(|raw| raw.len() == 32);
        if !socket.is_absolute()
            || !valid_capability
            || !valid_identity(&campaign_id)
            || !valid_identity(&lane_id)
        {
            return Err(io::Error::other("invalid bridge lane configuration"));
        }
        Ok(Self {
            socket,
            capability,
            campaign_id,
            lane_id,
        })
    }

    async fn call_broker(&self, body: Bytes) -> Result<(StatusCode, Vec<u8>), ()> {
        let stream = timeout(Duration::from_secs(5), UnixStream::connect(&self.socket))
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|_| ())?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let bearer = Zeroizing::new(format!("Bearer {}", self.capability.as_str()));
        let authorization = HeaderValue::from_str(&bearer).map_err(|_| ())?;
        let request = Request::builder()
            .method(Method::POST)
            .uri("/v1/responses")
            .header(header::HOST, "broker")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, authorization)
            .header("x-factory-campaign-id", self.campaign_id.as_str())
            .header("x-factory-lane-id", self.lane_id.as_str())
            .body(Full::new(body))
            .map_err(|_| ())?;
        let response = timeout(Duration::from_secs(650), sender.send_request(request))
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;
        let status = response.status();
        if status != StatusCode::OK {
            return Ok((status, Vec::new()));
        }
        if response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            != Some("text/event-stream")
        {
            return Err(());
        }
        let bytes = timeout(
            Duration::from_secs(650),
            Limited::new(response.into_body(), MAX_RESPONSE).collect(),
        )
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?
        .to_bytes();
        if !validated_complete_sse(&bytes) {
            return Err(());
        }
        Ok((status, bytes.to_vec()))
    }

    async fn handle(self: Arc<Self>, request: Request<Incoming>) -> Response<Full<Bytes>> {
        if request.method() != Method::POST
            || request.uri().path() != "/v1/responses"
            || request.uri().query().is_some()
            || request
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                != Some("application/json")
        {
            return reject(StatusCode::FORBIDDEN);
        }
        let body = match Limited::new(request.into_body(), MAX_REQUEST)
            .collect()
            .await
        {
            Ok(collected) => collected.to_bytes(),
            Err(_) => return reject(StatusCode::PAYLOAD_TOO_LARGE),
        };
        match self.call_broker(body).await {
            Ok((StatusCode::OK, bytes)) => reply(StatusCode::OK, "text/event-stream", bytes),
            Ok((status, _)) => reject(status),
            Err(()) => reject(StatusCode::BAD_GATEWAY),
        }
    }

    pub async fn serve(self, listener: TcpListener) -> io::Result<()> {
        let address: SocketAddr = listener.local_addr()?;
        if !address.ip().is_loopback() {
            return Err(io::Error::other("bridge must bind only to loopback"));
        }
        let bridge = Arc::new(self);
        let permits = Arc::new(Semaphore::new(32));
        loop {
            let permit = permits
                .clone()
                .acquire_owned()
                .await
                .map_err(io::Error::other)?;
            let (stream, _) = listener.accept().await?;
            let bridge = bridge.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let service = service_fn(move |request| {
                    let bridge = bridge.clone();
                    async move { Ok::<_, Infallible>(bridge.handle(request).await) }
                });
                let _ = timeout(
                    Duration::from_secs(660),
                    hyper::server::conn::http1::Builder::new()
                        .keep_alive(false)
                        .serve_connection(TokioIo::new(stream), service),
                )
                .await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    const COMPLETE: &str = "event: response.created\ndata: {\"type\":\"response.created\"}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n";

    #[tokio::test]
    async fn codex_loopback_request_uses_only_scoped_unix_socket() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("agent.sock");
        let fake = UnixListener::bind(&socket).unwrap();
        let capability = URL_SAFE_NO_PAD.encode([9u8; 32]);
        let expected = format!("Bearer {capability}");
        let fake_task = tokio::spawn(async move {
            let (stream, _) = fake.accept().await.unwrap();
            let service = service_fn(move |request: Request<Incoming>| {
                let expected = expected.clone();
                async move {
                    assert_eq!(request.method(), Method::POST);
                    assert_eq!(request.uri().path(), "/v1/responses");
                    assert_eq!(
                        request.headers().get(header::AUTHORIZATION).unwrap(),
                        expected.as_str()
                    );
                    assert_eq!(
                        request.headers().get("x-factory-campaign-id").unwrap(),
                        "campaign-1"
                    );
                    assert_eq!(
                        request.headers().get("x-factory-lane-id").unwrap(),
                        "lane-1"
                    );
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    assert_eq!(&body[..], b"{\"model\":\"gpt-6-sol\"}");
                    Ok::<_, Infallible>(reply(
                        StatusCode::OK,
                        "text/event-stream",
                        COMPLETE.as_bytes().to_vec(),
                    ))
                }
            });
            hyper::server::conn::http1::Builder::new()
                .keep_alive(false)
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        });

        let bridge = AgentBridge::new(
            socket,
            Zeroizing::new(capability),
            "campaign-1".into(),
            "lane-1".into(),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let bridge_task = tokio::spawn(bridge.serve(listener));
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let wrong_route = client
            .post(format!("http://{address}/v1/grants"))
            .header("content-type", "application/json")
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(wrong_route.status(), StatusCode::FORBIDDEN);
        let completed = client
            .post(format!("http://{address}/v1/responses"))
            .header("content-type", "application/json")
            .header("authorization", "Bearer untrusted-codex-placeholder")
            .body("{\"model\":\"gpt-6-sol\"}")
            .send()
            .await
            .unwrap();
        assert_eq!(completed.status(), StatusCode::OK);
        assert_eq!(completed.text().await.unwrap(), COMPLETE);
        timeout(Duration::from_secs(5), fake_task)
            .await
            .unwrap()
            .unwrap();
        bridge_task.abort();
    }

    #[test]
    fn bridge_refuses_malformed_lane_or_capability() {
        let valid = Zeroizing::new(URL_SAFE_NO_PAD.encode([2u8; 32]));
        assert!(
            AgentBridge::new(
                PathBuf::from("relative.sock"),
                valid.clone(),
                "c".into(),
                "l".into()
            )
            .is_err()
        );
        assert!(
            AgentBridge::new(
                PathBuf::from("/tmp/agent.sock"),
                Zeroizing::new("short".into()),
                "c".into(),
                "l".into()
            )
            .is_err()
        );
        assert!(
            AgentBridge::new(
                PathBuf::from("/tmp/agent.sock"),
                valid,
                "invalid/campaign".into(),
                "l".into()
            )
            .is_err()
        );
    }
}
