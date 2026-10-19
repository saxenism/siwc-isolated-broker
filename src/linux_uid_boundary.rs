//! Run the ignored test as root inside a disposable, networkless Linux
//! container. It gives broker, controller, and agent separate real UIDs.

use std::{
    collections::BTreeSet,
    env, fs,
    io::{Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
        net::UnixStream,
        process::CommandExt,
    },
    path::Path,
    process::{Child, Command},
    sync::Arc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    broker::BrokerCore,
    sockets::{BrokerSockets, PeerUids},
    storage::ProtectedStore,
    tokens::ValidatedSession,
};
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

const BROKER_UID: u32 = 29001;
const CONTROLLER_UID: u32 = 29002;
const AGENT_UID: u32 = 29003;

struct BrokerChild(Child);

impl Drop for BrokerChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn chown(path: &Path, uid: u32, gid: u32) {
    let bytes = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: NUL-terminated path remains alive for this libc call.
    assert_eq!(unsafe { libc::chown(bytes.as_ptr(), uid, gid) }, 0);
}

fn spawn_as(role: &str, base: &Path, uid: u32, gid: u32, groups: &[u32]) -> Child {
    let mut command = Command::new(env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "linux_uid_boundary::fixture_child",
            "--nocapture",
        ])
        .env("SIWC_FIXTURE_ROLE", role)
        .env("SIWC_FIXTURE_DIR", base);
    let groups = groups.to_vec();
    // SAFETY: only async-signal-safe setgroups/setgid/setuid syscalls run
    // between fork and exec. The groups array is owned by the closure.
    unsafe {
        command.pre_exec(move || {
            if libc::setgroups(groups.len(), groups.as_ptr()) != 0
                || libc::setgid(gid) != 0
                || libc::setuid(uid) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn().unwrap()
}

fn post(socket: &Path, route: &str) -> String {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .write_all(
            format!(
                "POST {route} HTTP/1.1\r\nHost: broker\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            )
            .as_bytes(),
        )
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

async fn broker(base: &Path) {
    eprintln!("fixture broker: opening protected store");
    let store = ProtectedStore::open(&base.join("protected")).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    store
        .save(&ValidatedSession {
            client_id: "oaiapp-synthetic".into(),
            subject: "synthetic-subject".into(),
            host_id: store.host_id().unwrap(),
            scopes: BTreeSet::from([
                "offline_access".into(),
                "resource.invoke".into(),
                "chatgpt.tokens.use.direct".into(),
            ]),
            expires_at: now + 3600,
            earliest_refresh_at: now + 1800,
            access_token: Zeroizing::new("synthetic-access-never-sent".into()),
            refresh_token: Zeroizing::new("synthetic-refresh-never-sent".into()),
            id_token: Zeroizing::new("synthetic-id-never-sent".into()),
        })
        .unwrap();
    eprintln!("fixture broker: creating core");
    let core = Arc::new(
        BrokerCore::new(
            store,
            SigningKey::from_bytes(&[7u8; 32]).verifying_key(),
            "oaiapp-synthetic".into(),
            "synthetic-subject".into(),
        )
        .unwrap(),
    );
    eprintln!("fixture broker: binding sockets");
    let sockets = BrokerSockets::bind(
        core,
        &base.join("agent/agent.sock"),
        AGENT_UID,
        &base.join("controller/admin.sock"),
        CONTROLLER_UID,
        PeerUids::new(AGENT_UID, CONTROLLER_UID).unwrap(),
    )
    .unwrap();
    eprintln!("fixture broker: serving sockets");
    sockets.serve().await.unwrap();
}

#[test]
fn fixture_child() {
    let Ok(role) = env::var("SIWC_FIXTURE_ROLE") else {
        return;
    };
    let base = std::path::PathBuf::from(env::var_os("SIWC_FIXTURE_DIR").unwrap());
    match role.as_str() {
        "broker" => tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(broker(&base)),
        "agent" => {
            assert!(fs::read_dir(base.join("protected")).is_err());
            assert!(UnixStream::connect(base.join("controller/admin.sock")).is_err());
            assert!(post(&base.join("agent/agent.sock"), "/v1/grants").starts_with("HTTP/1.1 403"));
        }
        "controller" => {
            assert!(fs::read_dir(base.join("protected")).is_err());
            assert!(UnixStream::connect(base.join("agent/agent.sock")).is_err());
            assert!(
                post(&base.join("controller/admin.sock"), "/v1/responses")
                    .starts_with("HTTP/1.1 403")
            );
        }
        _ => panic!("unknown fixture role"),
    }
}

#[test]
#[ignore = "run explicitly as root inside a networkless disposable Linux container"]
fn three_real_uid_socket_boundary() {
    // SAFETY: querying the current effective UID has no side effects.
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "fixture needs container root"
    );
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    fs::set_permissions(base, fs::Permissions::from_mode(0o755)).unwrap();
    for (name, gid, mode) in [
        ("protected", BROKER_UID, 0o700),
        ("agent", AGENT_UID, 0o750),
        ("controller", CONTROLLER_UID, 0o750),
    ] {
        let path = base.join(name);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        chown(&path, BROKER_UID, gid);
    }
    let mut broker = BrokerChild(spawn_as(
        "broker",
        base,
        BROKER_UID,
        BROKER_UID,
        &[AGENT_UID, CONTROLLER_UID],
    ));
    let agent_socket = base.join("agent/agent.sock");
    let admin_socket = base.join("controller/admin.sock");
    for _ in 0..100 {
        if agent_socket.exists() && admin_socket.exists() {
            break;
        }
        assert!(
            broker.0.try_wait().unwrap().is_none(),
            "broker exited before bind"
        );
        thread::sleep(Duration::from_millis(100));
    }
    assert!(agent_socket.exists() && admin_socket.exists());
    assert_eq!(
        fs::symlink_metadata(&agent_socket).unwrap().gid(),
        AGENT_UID
    );
    assert_eq!(
        fs::symlink_metadata(&admin_socket).unwrap().gid(),
        CONTROLLER_UID
    );
    for (role, uid) in [("agent", AGENT_UID), ("controller", CONTROLLER_UID)] {
        let status = spawn_as(role, base, uid, uid, &[]).wait().unwrap();
        assert!(status.success(), "{role} boundary failed: {status}");
    }
    // Root can traverse both directories, but the broker rejects its peer UID.
    for socket in [&agent_socket, &admin_socket] {
        let mut stream = UnixStream::connect(socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let _ = stream.write_all(b"GET / HTTP/1.1\r\nHost: broker\r\n\r\n");
        let mut byte = [0u8; 1];
        assert!(matches!(stream.read(&mut byte), Ok(0) | Err(_)));
    }
}
