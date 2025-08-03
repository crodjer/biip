//! `biip` is a library to scrub personally identifiable information (PII) from text.
//!
//! It provides a flexible way to define and apply redaction rules to any string.
//!
//! # How does it work?
//!
//! `biip` works by applying a series of "redactors" to the input text. Each redactor
//! is responsible for finding and replacing a specific type of sensitive information.
//!
//! For example, if you have a file with content:
//! ```text
//! Hi, I am "awesome-user"
//! Current Directory: /Users/awesome-user/foo/bar/baz
//! My Secret Key: mAM3zwogXpV6Czj6J
//! My Email: foo@bar.com
//! My IPs:
//! - fe80::aaa:8888:ffff:9999
//! - 192.168.42.42
//! ```
//!
//! `biip` can redact some sensitive information from it:
//! ```
//! use biip::Biip;
//! use std::env;
//!
//! // Setting env vars for the example
//! # unsafe {
//! env::set_var("USER", "awesome-user");
//! env::set_var("HOME", "/Users/awesome-user");
//! env::set_var("MY_SECRET_KEY", "mAM3zwogXpV6Czj6J");
//! # }
//!
//! let input = r#"
//! Hi, I am "awesome-user"
//! Current Directory: /Users/awesome-user/foo/bar/baz
//! My Secret Key: mAM3zwogXpV6Czj6J
//! My Email: foo@bar.com
//! My IPs:
//! - fe80::aaa:8888:ffff:9999
//! - 192.168.42.42
//! "#;
//!
//! let biip = Biip::new();
//! let redacted = biip.process(input);
//!
//! // The output will be redacted. Note that the exact output might vary
//! // based on the environment and redactors.
//! assert!(redacted.contains("Current Directory: ~/foo/bar/baz"));
//! assert!(redacted.contains("My Secret Key: **secret**"));
//! assert!(redacted.contains("My Email: ***@***"));
//! ```
//!
//! # What does it scrub?
//!
//! By default, `biip` can scrub:
//!
//! 1.  **Unix (Linux/Mac) username**: It removes any mention of a user's Unix username from the supplied text, replacing it with `user`.
//! 2.  **Home directory**: It replaces paths referring to the home directory with `~`.
//! 3.  **Emails**: It replaces any email addresses in the text with a pattern: `***@***`.
//! 4.  **IP Addresses**: It replaces IPv4 and IPv6 addresses.
//! 5.  **Keys / Passwords from environment**: It replaces the values for any potentially sensitive environment variables with: `**secret**`. It looks for any environment variables that may have these keywords in the name: `username`, `password`, `email`, `secret`, `token`, `key`.

pub mod biip;
pub mod redactor;
pub mod redactors;

pub use biip::Biip;
pub use redactor::Redactor;
