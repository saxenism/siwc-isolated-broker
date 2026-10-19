//! Small, auditable building blocks for a credential-isolated ChatGPT-plan broker.
//! The experimental service is runnable, but has not been tested against a
//! live account or under a production three-identity deployment.

pub mod authority;
#[cfg(unix)]
pub mod bridge;
#[cfg(unix)]
pub mod broker;
pub mod grants;
pub mod identity;
pub mod inference;
pub mod ledger;
#[cfg(unix)]
pub mod login;
pub mod oauth;
pub mod policy;
#[cfg(unix)]
pub mod sockets;
#[cfg(unix)]
pub mod storage;
pub mod tokens;

#[cfg(all(test, target_os = "linux"))]
mod linux_uid_boundary;
