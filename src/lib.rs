//! `biip` is a library to scrub personally identifiable information (PII) from text.
//!
//! It provides a flexible way to define and apply redaction rules to any string.
//!
//! # How it works
//!
//! `biip` works by applying a series of "redactors" to the input text. Each redactor
//! is responsible for finding and replacing a specific type of sensitive information.
//! The library includes redactors for common patterns like usernames, environment secrets,
//! IP addresses, API keys, and more.
//!
//! # Example
//!
//! ```
//! use biip::Biip;
//! use std::env;
//!
//! // Setting env vars for the example
//! # unsafe {
//! #   env::set_var("USER", "awesome-user");
//! #   env::set_var("HOME", "/Users/awesome-user");
//! #   env::set_var("MY_SECRET_KEY", "mAM3zwogXpV6Czj6J");
//! # }
//!
//! let input = r#"
//! Hi, I am "Awesome-User". My home is /Users/awesome-user.
//! My IP is 8.8.8.8 and the gateway is 2001:0db8:85a3:0000:0000:8a2e:0370:7334.
//! My secret is mAM3zwogXpV6Czj6J.
//! "#;
//!
//! let biip = Biip::new();
//! let redacted = biip.process(input);
//!
//! assert!(redacted.contains(r#"Hi, I am "user". My home is ~."#));
//! assert!(redacted.contains("My IP is ••.••.••.•• and the gateway is ••:••:••:••:••:••:••:••."));
//! assert!(redacted.contains("My secret is ••••••⚿•."));
//! ```
pub mod biip;
pub mod redactor;
pub mod redactors;

pub use biip::Biip;
pub use redactor::Redactor;
