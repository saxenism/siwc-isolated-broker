//! Run only under a separate trusted broker OS identity. This executable is
//! intentionally feature gated while live eligibility and isolation remain
//! unverified. It never imports Codex CLI authentication files.

use std::{io::Write, path::PathBuf};

use clap::{Parser, Subcommand};
use siwc_isolated_broker::{
    authority::OpenAiAuthority, login::LoginSession, storage::ProtectedStore,
};

#[derive(Parser)]
#[command(about = "Experimental, isolated Sign in with ChatGPT enrollment")]
struct Args {
    /// Absolute owner-only directory, outside every agent and target-build mount.
    #[arg(long)]
    store_dir: PathBuf,
    #[command(subcommand)]
    account: Account,
}

#[derive(Subcommand)]
enum Account {
    /// Register a new ChatGPT account/workspace for this broker host.
    New,
    /// Reauthorize one saved client/subject binding; browser account picker appears.
    Returning {
        #[arg(long)]
        client_id: String,
        #[arg(long)]
        subject: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let store = ProtectedStore::open(&args.store_dir)?;
    let login = match args.account {
        Account::New => LoginSession::start(&store).await?,
        Account::Returning { client_id, subject } => {
            LoginSession::start_returning(&store, &client_id, &subject).await?
        }
    };
    println!("Continue with ChatGPT: {}", login.authorization_url());
    std::io::stdout().flush()?;
    let authority = OpenAiAuthority::new()?;
    let outcome = login.complete(&authority, &store).await?;
    println!("Account subject: {}", outcome.subject);
    println!("Issued client ID: {}", outcome.client_id);
    println!(
        "ChatGPT plan access: {}",
        if outcome.plan_enabled {
            "granted"
        } else {
            "not granted"
        }
    );
    Ok(())
}
