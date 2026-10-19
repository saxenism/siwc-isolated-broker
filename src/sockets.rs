//! Separate Unix sockets for the trusted control plane and untrusted agent
//! plane. Each socket lives in its own broker-owned 0750 exchange directory,
//! grouped only to the intended peer identity. The credential store remains
//! in a separate 0700 directory. A bearer capability is additionally required
//! on the agent socket.

use std::{
    convert::Infallible,
    ffi::CString,
    fs::{self, Permissions},
    io,
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
    },
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Bytes, Incoming},
    header::{self, HeaderMap},
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    time::timeout,
};
use zeroize::Zeroizing;

use crate::{broker::BrokerCore, grants::Deployment};

const MAX_AGENT_BODY: usize = 1024 * 1024;
const MAX_ADMIN_BODY: usize = 16 * 1024;
const DENIED: &[u8] = b"{\"error\":{\"message\":\"model broker rejected request\"}}";

#[derive(Clone, Copy)]
enum Surface {
    Agent,
    Admin,
}

pub struct BrokerSockets {
    agent: UnixListener,
    admin: UnixListener,
    core: Arc<BrokerCore>,
    peers: PeerUids,
}

/// Dedicated OS identities admitted to each socket. The broker itself must
/// run under a third, non-root identity. Filesystem permissions are a second
/// boundary, not a substitute for checking the connecting process.
#[derive(Clone, Copy)]
pub struct PeerUids {
    pub agent: u32,
    pub controller: u32,
}

impl PeerUids {
    pub fn new(agent: u32, controller: u32) -> io::Result<Self> {
        // SAFETY: querying the current process effective UID has no side effects.
        let broker = unsafe { libc::geteuid() };
        if broker == 0
            || agent == 0
            || controller == 0
            || agent == controller
            || agent == broker
            || controller == broker
        {
            return Err(io::Error::other(
                "broker, agent, and controller need separate non-root UIDs",
            ));
        }
        Ok(Self { agent, controller })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantRequest {
    authority_base64: String,
    campaign_id: String,
    lane_id: String,
    aoe_session_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeRequest {
    campaign_id: String,
    lane_id: String,
}

#[derive(Serialize)]
struct GrantReply<'a> {
    token: &'a str,
    grant_id: &'a str,
}

#[derive(Serialize)]
struct RevokeReply {
    revoked: bool,
}

fn current_time() -> Result<i64, ()> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|time| i64::try_from(time.as_secs()).ok())
        .ok_or(())
}

fn response(
    status: StatusCode,
    content_type: &'static str,
    body: Vec<u8>,
) -> Response<Full<Bytes>> {
    let length = body.len();
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static(content_type),
    );
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        hyper::header::HeaderValue::from_str(&length.to_string())
            .expect("bounded broker response length"),
    );
    response
}

fn reject(status: StatusCode) -> Response<Full<Bytes>> {
    response(status, "application/json", DENIED.to_vec())
}

fn json_response<T: Serialize>(value: &T) -> Response<Full<Bytes>> {
    match serde_json::to_vec(value) {
        Ok(body) => response(StatusCode::OK, "application/json", body),
        Err(_) => reject(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

fn exact_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

async fn collect_body(body: Incoming, limit: usize) -> Result<Bytes, ()> {
    Limited::new(body, limit)
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .map_err(|_| ())
}

async fn agent_request(core: Arc<BrokerCore>, request: Request<Incoming>) -> Response<Full<Bytes>> {
    if request.method() != Method::POST
        || request.uri().path() != "/v1/responses"
        || request.uri().query().is_some()
        || exact_header(request.headers(), "content-type") != Some("application/json")
    {
        return reject(StatusCode::FORBIDDEN);
    }
    let Some(capability) = exact_header(request.headers(), "authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| (32..=256).contains(&value.len()))
        .map(|value| Zeroizing::new(value.to_owned()))
    else {
        return reject(StatusCode::UNAUTHORIZED);
    };
    let Some(campaign_id) = exact_header(request.headers(), "x-factory-campaign-id")
        .filter(|value| valid_identity(value))
        .map(str::to_owned)
    else {
        return reject(StatusCode::UNAUTHORIZED);
    };
    let Some(lane_id) = exact_header(request.headers(), "x-factory-lane-id")
        .filter(|value| valid_identity(value))
        .map(str::to_owned)
    else {
        return reject(StatusCode::UNAUTHORIZED);
    };
    let Ok(body) = collect_body(request.into_body(), MAX_AGENT_BODY).await else {
        return reject(StatusCode::PAYLOAD_TOO_LARGE);
    };
    let Ok(now) = current_time() else {
        return reject(StatusCode::SERVICE_UNAVAILABLE);
    };
    match core
        .dispatch(capability.as_bytes(), &campaign_id, &lane_id, &body, now)
        .await
    {
        Ok(sse) => response(StatusCode::OK, "text/event-stream", sse),
        Err(crate::broker::BrokerError::InvalidRequest) => reject(StatusCode::BAD_REQUEST),
        Err(crate::broker::BrokerError::Denied) => reject(StatusCode::UNAUTHORIZED),
        Err(crate::broker::BrokerError::Unavailable) => reject(StatusCode::SERVICE_UNAVAILABLE),
        Err(crate::broker::BrokerError::Upstream) => reject(StatusCode::BAD_GATEWAY),
    }
}

async fn admin_request(core: Arc<BrokerCore>, request: Request<Incoming>) -> Response<Full<Bytes>> {
    if request.method() != Method::POST
        || request.uri().query().is_some()
        || exact_header(request.headers(), "content-type") != Some("application/json")
    {
        return reject(StatusCode::FORBIDDEN);
    }
    let path = request.uri().path().to_owned();
    if !matches!(path.as_str(), "/v1/grants" | "/v1/revoke") {
        return reject(StatusCode::FORBIDDEN);
    }
    let Ok(body) = collect_body(request.into_body(), MAX_ADMIN_BODY).await else {
        return reject(StatusCode::PAYLOAD_TOO_LARGE);
    };
    let Ok(now) = current_time() else {
        return reject(StatusCode::SERVICE_UNAVAILABLE);
    };
    match path.as_str() {
        "/v1/grants" => {
            let Ok(input) = serde_json::from_slice::<GrantRequest>(&body) else {
                return reject(StatusCode::BAD_REQUEST);
            };
            let Ok(authority) = URL_SAFE_NO_PAD.decode(input.authority_base64) else {
                return reject(StatusCode::BAD_REQUEST);
            };
            let deployment = Deployment {
                campaign_id: &input.campaign_id,
                lane_id: &input.lane_id,
                aoe_session_id: &input.aoe_session_id,
            };
            match core.issue_signed(&authority, &deployment, now) {
                Ok(issued) => json_response(&GrantReply {
                    token: issued.token.as_str(),
                    grant_id: &issued.grant_id,
                }),
                Err(crate::broker::BrokerError::Denied) => reject(StatusCode::FORBIDDEN),
                Err(_) => reject(StatusCode::SERVICE_UNAVAILABLE),
            }
        }
        "/v1/revoke" => {
            let Ok(input) = serde_json::from_slice::<RevokeRequest>(&body) else {
                return reject(StatusCode::BAD_REQUEST);
            };
            if !valid_identity(&input.campaign_id) || !valid_identity(&input.lane_id) {
                return reject(StatusCode::BAD_REQUEST);
            }
            match core.revoke_lane(&input.campaign_id, &input.lane_id, now) {
                Ok(revoked) => json_response(&RevokeReply { revoked }),
                Err(_) => reject(StatusCode::SERVICE_UNAVAILABLE),
            }
        }
        _ => reject(StatusCode::FORBIDDEN),
    }
}

fn bind_socket(path: &Path, mode: u32, gid: Option<u32>) -> io::Result<UnixListener> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_socket() && metadata.uid() == unsafe { libc::geteuid() } =>
        {
            fs::remove_file(path)?;
        }
        Ok(_) => return Err(io::Error::other("unsafe existing broker socket path")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = UnixListener::bind(path)?;
    if let Some(gid) = gid {
        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::other("invalid socket path"))?;
        // SAFETY: `c_path` is NUL-terminated and remains alive for the call.
        if unsafe { libc::chown(c_path.as_ptr(), libc::uid_t::MAX, gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    fs::set_permissions(path, Permissions::from_mode(mode))?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o7777 != mode
        || gid.is_some_and(|expected| metadata.gid() != expected)
    {
        return Err(io::Error::other("broker socket ownership changed"));
    }
    Ok(listener)
}

fn check_exchange_directory(path: &Path, gid: u32) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(io::Error::other("broker socket path must be absolute"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("broker socket has no parent"))?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.gid() != gid
        || metadata.permissions().mode() & 0o7777 != 0o750
    {
        return Err(io::Error::other("broker socket directory is unsafe"));
    }
    Ok(())
}

fn peer_authorized(stream: &UnixStream, expected_uid: u32) -> io::Result<bool> {
    Ok(stream.peer_cred()?.uid() == expected_uid)
}

impl BrokerSockets {
    pub fn bind(
        core: Arc<BrokerCore>,
        agent_path: &Path,
        agent_gid: u32,
        admin_path: &Path,
        controller_gid: u32,
        peers: PeerUids,
    ) -> io::Result<Self> {
        PeerUids::new(peers.agent, peers.controller)?;
        Self::bind_checked(
            core,
            agent_path,
            agent_gid,
            admin_path,
            controller_gid,
            peers,
        )
    }

    fn bind_checked(
        core: Arc<BrokerCore>,
        agent_path: &Path,
        agent_gid: u32,
        admin_path: &Path,
        controller_gid: u32,
        peers: PeerUids,
    ) -> io::Result<Self> {
        check_exchange_directory(agent_path, agent_gid)?;
        check_exchange_directory(admin_path, controller_gid)?;
        if agent_path == admin_path || agent_path.parent() == admin_path.parent() {
            return Err(io::Error::other("agent and admin sockets must differ"));
        }
        let admin = bind_socket(admin_path, 0o660, Some(controller_gid))?;
        let agent = bind_socket(agent_path, 0o660, Some(agent_gid))?;
        Ok(Self {
            agent,
            admin,
            core,
            peers,
        })
    }

    #[cfg(test)]
    fn bind_for_test(
        core: Arc<BrokerCore>,
        agent_path: &Path,
        agent_gid: u32,
        admin_path: &Path,
        controller_gid: u32,
    ) -> io::Result<Self> {
        // A local unit test cannot impersonate two additional OS users.
        // Deployment must use `bind`, which rejects shared/root identities.
        // SAFETY: querying the current process effective UID has no side effects.
        let current = unsafe { libc::geteuid() };
        Self::bind_checked(
            core,
            agent_path,
            agent_gid,
            admin_path,
            controller_gid,
            PeerUids {
                agent: current,
                controller: current,
            },
        )
    }

    pub async fn serve(self) -> io::Result<()> {
        let Self {
            agent,
            admin,
            core,
            peers,
        } = self;
        tokio::try_join!(
            serve_listener(agent, core.clone(), Surface::Agent, peers.agent),
            serve_listener(admin, core, Surface::Admin, peers.controller),
        )?;
        Ok(())
    }
}

async fn serve_listener(
    listener: UnixListener,
    core: Arc<BrokerCore>,
    surface: Surface,
    expected_uid: u32,
) -> io::Result<()> {
    let permits = Arc::new(Semaphore::new(match surface {
        Surface::Agent => 32,
        Surface::Admin => 4,
    }));
    loop {
        let permit = permits
            .clone()
            .acquire_owned()
            .await
            .map_err(io::Error::other)?;
        let (stream, _) = listener.accept().await?;
        if !peer_authorized(&stream, expected_uid)? {
            continue;
        }
        let core = core.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let service = service_fn(move |request| {
                let core = core.clone();
                async move {
                    let response = match surface {
                        Surface::Agent => agent_request(core, request).await,
                        Surface::Admin => admin_request(core, request).await,
                    };
                    Ok::<_, Infallible>(response)
                }
            });
            let duration = match surface {
                Surface::Agent => Duration::from_secs(650),
                Surface::Admin => Duration::from_secs(30),
            };
            let _ = timeout(
                duration,
                hyper::server::conn::http1::Builder::new()
                    .keep_alive(false)
                    .serve_connection(TokioIo::new(stream), service),
            )
            .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{authority::OpenAiAuthority, inference::PlanInference, storage::ProtectedStore};
    use axum::{Router, http::StatusCode as AxumStatus, routing::post};
    use std::collections::BTreeSet;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixStream,
    };
    use url::Url;
    use zeroize::Zeroizing;

    const REQUEST: &str = "{\"model\":\"gpt-6-sol\",\"store\":false,\"stream\":true,\"input\":[{\"role\":\"user\",\"content\":\"hi\"}]}";
    const COMPLETE: &str = "event: response.created\ndata: {\"type\":\"response.created\"}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n";

    #[test]
    fn peer_identities_must_be_distinct_non_root_accounts() {
        // SAFETY: querying the current effective UID has no side effects.
        let broker = unsafe { libc::geteuid() };
        assert!(PeerUids::new(broker, broker.saturating_add(1)).is_err());
        assert!(PeerUids::new(0, broker.saturating_add(1)).is_err());
        assert!(PeerUids::new(47, 47).is_err());
    }

    #[tokio::test]
    async fn peer_credentials_are_checked_before_http() {
        let (stream, _other) = UnixStream::pair().unwrap();
        // SAFETY: querying the current effective UID has no side effects.
        let own_uid = unsafe { libc::geteuid() };
        assert!(peer_authorized(&stream, own_uid).unwrap());
        assert!(!peer_authorized(&stream, own_uid.wrapping_add(1)).unwrap());
    }

    async fn fake_inference() -> PlanInference {
        let app = Router::new().route(
            "/v1/responses",
            post(|headers: axum::http::HeaderMap| async move {
                if headers.get("authorization").and_then(|v| v.to_str().ok())
                    != Some("Bearer synthetic-access-token-123")
                {
                    return (
                        AxumStatus::FORBIDDEN,
                        [("content-type", "text/event-stream")],
                        "wrong token",
                    );
                }
                (
                    AxumStatus::OK,
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

    fn save_synthetic_session(store: &ProtectedStore) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        store
            .save(&crate::tokens::ValidatedSession {
                client_id: "oaiapp-test".into(),
                subject: "person-test".into(),
                host_id: store.host_id().unwrap(),
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
            })
            .unwrap();
    }

    fn post_request(path: &str, body: &str, extra_headers: &str) -> Vec<u8> {
        format!(
            "POST {path} HTTP/1.1\r\nHost: broker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{extra_headers}\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    async fn send(path: &Path, request: &[u8]) -> String {
        let mut stream = UnixStream::connect(path).await.unwrap();
        stream.write_all(request).await.unwrap();
        let mut response = Vec::new();
        timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        String::from_utf8(response).unwrap()
    }

    fn body(response: &str) -> &str {
        response.split_once("\r\n\r\n").unwrap().1
    }

    #[tokio::test]
    async fn separate_sockets_enforce_grant_route_and_revocation() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let store = ProtectedStore::open(&temp.path().join("protected")).unwrap();
        save_synthetic_session(&store);
        let now = current_time().unwrap();
        let (authority, key) = crate::grants::signed_fixture_at(now);
        let core = Arc::new(
            BrokerCore::with_transports(
                store,
                key,
                "oaiapp-test".into(),
                "person-test".into(),
                OpenAiAuthority::new().unwrap(),
                fake_inference().await,
            )
            .unwrap(),
        );
        let agent_dir = temp.path().join("agent-exchange");
        fs::create_dir(&agent_dir).unwrap();
        fs::set_permissions(&agent_dir, Permissions::from_mode(0o750)).unwrap();
        let admin_dir = temp.path().join("admin-exchange");
        fs::create_dir(&admin_dir).unwrap();
        fs::set_permissions(&admin_dir, Permissions::from_mode(0o750)).unwrap();
        // SAFETY: querying the current process effective GID has no side effects.
        let agent_gid = unsafe { libc::getegid() };
        let agent_path = agent_dir.join("agent.sock");
        let admin_path = admin_dir.join("admin.sock");
        let sockets =
            BrokerSockets::bind_for_test(core, &agent_path, agent_gid, &admin_path, agent_gid)
                .unwrap();
        assert_eq!(
            fs::symlink_metadata(&agent_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o660
        );
        assert_eq!(
            fs::symlink_metadata(&admin_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o660
        );
        let task = tokio::spawn(sockets.serve());
        assert!(
            send(&agent_path, &post_request("/v1/grants", "{}", ""))
                .await
                .starts_with("HTTP/1.1 403")
        );
        assert!(
            send(&admin_path, &post_request("/v1/responses", REQUEST, ""))
                .await
                .starts_with("HTTP/1.1 403")
        );
        let grant_body = serde_json::json!({
            "authority_base64": URL_SAFE_NO_PAD.encode(authority),
            "campaign_id": "campaign-1",
            "lane_id": "lane-1",
            "aoe_session_id": "session-1"
        })
        .to_string();
        let grant_response = send(&admin_path, &post_request("/v1/grants", &grant_body, "")).await;
        assert!(grant_response.starts_with("HTTP/1.1 200"));
        let grant: serde_json::Value = serde_json::from_str(body(&grant_response)).unwrap();
        let token = grant["token"].as_str().unwrap();
        let agent_headers = format!(
            "Authorization: Bearer {token}\r\nX-Factory-Campaign-Id: campaign-1\r\nX-Factory-Lane-Id: lane-1\r\n"
        );
        let completed = send(
            &agent_path,
            &post_request("/v1/responses", REQUEST, &agent_headers),
        )
        .await;
        assert!(completed.starts_with("HTTP/1.1 200"));
        assert_eq!(body(&completed), COMPLETE);
        let revoke = send(
            &admin_path,
            &post_request(
                "/v1/revoke",
                "{\"campaign_id\":\"campaign-1\",\"lane_id\":\"lane-1\"}",
                "",
            ),
        )
        .await;
        assert!(revoke.starts_with("HTTP/1.1 200"));
        assert!(
            send(
                &agent_path,
                &post_request("/v1/responses", REQUEST, &agent_headers)
            )
            .await
            .starts_with("HTTP/1.1 401")
        );
        task.abort();
    }
}
