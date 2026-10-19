//! Codex-compatible loopback endpoint inside one isolated agent namespace.
//! It reads only a revocable lane capability, never a ChatGPT credential.

use std::{
    fs::OpenOptions,
    io::Read,
    net::SocketAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::PathBuf,
};

use clap::Parser;
use siwc_isolated_broker::bridge::AgentBridge;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(about = "Experimental loopback-to-broker connector for one Codex lane")]
struct Args {
    /// Loopback listener inside the isolated agent namespace.
    #[arg(long)]
    listen: SocketAddr,
    /// Agent-visible broker Unix socket; no admin socket is mounted here.
    #[arg(long)]
    broker_socket: PathBuf,
    /// Agent-owned 0600 file containing only a revocable lane capability.
    #[arg(long)]
    capability_file: PathBuf,
    #[arg(long)]
    campaign_id: String,
    #[arg(long)]
    lane_id: String,
}

fn read_capability(path: &PathBuf) -> anyhow::Result<Zeroizing<String>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    // SAFETY: querying the current effective UID has no side effects.
    anyhow::ensure!(
        metadata.file_type().is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.permissions().mode() & 0o7777 == 0o600
            && metadata.len() <= 128,
        "lane capability file must be agent-owned and 0600"
    );
    let mut capability = Zeroizing::new(String::new());
    file.take(129).read_to_string(&mut capability)?;
    anyhow::ensure!(capability.len() <= 128, "lane capability file is too large");
    Ok(capability)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    anyhow::ensure!(args.listen.ip().is_loopback(), "listener must be loopback");
    let capability = read_capability(&args.capability_file)?;
    let bridge = AgentBridge::new(
        args.broker_socket,
        capability,
        args.campaign_id,
        args.lane_id,
    )?;
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    eprintln!(
        "SIWC agent bridge serving loopback at {}",
        listener.local_addr()?
    );
    bridge.serve(listener).await?;
    Ok(())
}
