//! This module contains the various redactors used by `biip`.
//!
//! Each submodule is responsible for a specific category of redactions.
pub mod env;
pub mod patterns;
pub mod user;

/// Redacts sensitive information from environment variables.
/// @see env::secrets_redactor
pub use env::secrets_redactor;
/// Redacts patterns like email addresses and IP addresses.
/// @see patterns
pub use patterns::{email_redactor, ipv4_redactor, ipv6_redactor};
/// Redacts user-specific information like home directory and username.
/// @see user
pub use user::{home_redactor, username_redactor};
