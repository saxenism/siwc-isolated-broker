//! Run only under a separate trusted broker OS identity. This executable is
//! intentionally feature gated while live eligibility and isolation remain
//! unverified. It never imports Codex CLI authentication files.

use std::{io::Write, num::NonZeroU16, path::PathBuf};

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
    /// List saved account identities and plan permission, without printing tokens.
    List,
    /// Register a new ChatGPT account/workspace for this broker host.
    New {
        /// Fixed loopback port for an SSH local forward to this broker host.
        #[arg(long)]
        callback_port: Option<NonZeroU16>,
    },
    /// Reauthorize one saved client/subject binding; browser account picker appears.
    Returning {
        #[arg(long)]
        client_id: String,
        #[arg(long)]
        subject: String,
        /// Fixed loopback port for an SSH local forward to this broker host.
        #[arg(long)]
        callback_port: Option<NonZeroU16>,
    },
    /// Import a disposable 0600 transfer file into this VM's broker store.
    ImportVm {
        #[arg(long)]
        transfer_file: PathBuf,
    },
    /// Write a disposable 0600 transfer copy to a trusted 0700 directory.
    ExportVm {
        #[arg(long)]
        client_id: String,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        transfer_dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let store = ProtectedStore::open(&args.store_dir)?;
    let login = match args.account {
        Account::List => {
            for account in store.list_accounts()? {
                println!(
                    "{}  {}  plan={}  access_expires_at={}",
                    account.client_id, account.subject, account.plan_enabled, account.expires_at
                );
            }
            return Ok(());
        }
        Account::ImportVm { transfer_file } => {
            let authority = OpenAiAuthority::new()?;
            let jwks = authority.fetch_jwks().await?;
            let account = store.import_vm_transfer(&transfer_file, &jwks)?;
            println!(
                "Imported client {} for subject {}; plan={}",
                account.client_id, account.subject, account.plan_enabled
            );
            return Ok(());
        }
        Account::ExportVm {
            client_id,
            subject,
            transfer_dir,
        } => {
            let path = store.export_vm_transfer(&client_id, &subject, &transfer_dir)?;
            println!("Transfer file: {}", path.display());
            return Ok(());
        }
        Account::New { callback_port } => match callback_port {
            Some(port) => LoginSession::start_on_port(&store, port).await?,
            None => LoginSession::start(&store).await?,
        },
        Account::Returning {
            client_id,
            subject,
            callback_port,
        } => match callback_port {
            Some(port) => {
                LoginSession::start_returning_on_port(&store, &client_id, &subject, port).await?
            }
            None => LoginSession::start_returning(&store, &client_id, &subject).await?,
        },
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
