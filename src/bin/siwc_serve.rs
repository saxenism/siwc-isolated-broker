//! Experimental service entry point. Run under a dedicated non-root broker
//! identity after a separate isolated sign-in. Never run under an agent UID.

use std::{path::PathBuf, sync::Arc};

use clap::Parser;
use ed25519_dalek::VerifyingKey;
use siwc_isolated_broker::{
    broker::BrokerCore,
    sockets::{BrokerSockets, PeerUids},
    storage::ProtectedStore,
};

#[derive(Parser)]
#[command(about = "Experimental Unix-socket SIWC broker; requires isolated OS identities")]
struct Args {
    /// Absolute owner-only credential directory, outside agent mounts.
    #[arg(long)]
    store_dir: PathBuf,
    /// Issued SIWC client ID selected during sign-in.
    #[arg(long)]
    client_id: String,
    /// Signed account subject selected during sign-in.
    #[arg(long)]
    subject: String,
    /// Controller Ed25519 public key, 64 hexadecimal characters.
    #[arg(long)]
    controller_public_key_hex: String,
    /// Absolute agent socket path in a broker-owned, agent-group 0750 directory.
    #[arg(long)]
    agent_socket: PathBuf,
    /// Absolute admin socket path in a distinct broker-owned controller-group 0750 directory.
    #[arg(long)]
    admin_socket: PathBuf,
    /// Dedicated agent account UID; must differ from broker and controller.
    #[arg(long)]
    agent_uid: u32,
    /// Dedicated controller account UID; must differ from broker and agent.
    #[arg(long)]
    controller_uid: u32,
    /// Agent socket directory GID; the socket is made group-readable/writable.
    #[arg(long)]
    agent_gid: u32,
    /// Admin socket directory GID; only the controller may connect by peer UID.
    #[arg(long)]
    controller_gid: u32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let peers = PeerUids::new(args.agent_uid, args.controller_uid)?;
    let public_key = hex::decode(&args.controller_public_key_hex)?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("controller public key must be 32 bytes"))?;
    let controller_key = VerifyingKey::from_bytes(&public_key)?;
    let store = ProtectedStore::open(&args.store_dir)?;
    let core = Arc::new(BrokerCore::new(
        store,
        controller_key,
        args.client_id,
        args.subject,
    )?);
    let sockets = BrokerSockets::bind(
        core,
        &args.agent_socket,
        args.agent_gid,
        &args.admin_socket,
        args.controller_gid,
        peers,
    )?;
    eprintln!("SIWC broker serving on restricted Unix sockets");
    sockets.serve().await?;
    Ok(())
}
