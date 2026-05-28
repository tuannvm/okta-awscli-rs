#![forbid(unsafe_code)]

pub mod aws;
pub mod cli;
pub mod config;
pub mod okta;
pub mod secrets;
pub mod u2f;
pub mod webauthn_keychain;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
