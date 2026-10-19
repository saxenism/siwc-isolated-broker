//! Small, auditable building blocks for a credential-isolated ChatGPT-plan broker.
//! This crate can validate and persist credentials. It is not a runnable broker
//! and has not been tested against a live account or authority.

pub mod authority;
pub mod grants;
pub mod identity;
pub mod inference;
pub mod ledger;
#[cfg(unix)]
pub mod login;
pub mod oauth;
pub mod policy;
#[cfg(unix)]
pub mod storage;
pub mod tokens;
