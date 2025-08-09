use std::{net::Ipv6Addr, str::FromStr};

use crate::redactor::Redactor;
use regex::Regex;

/// Creates a `Redactor` for URL credentials.
///
/// Redacts credentials embedded within a URL.
pub fn url_credentials_redactor() -> Option<Redactor> {
    Regex::new(r"(?P<protocol>https?|ftp)://([^:]+):([^@]+)@")
        .ok()
        .map(|re| Redactor::regex_with_capture(re, "${protocol}://••••:••••@".to_string()))
}

/// Creates a `Redactor` for email addresses.
///
/// This redactor uses a regex to find and replace email addresses with `•••@•••`.
pub fn email_redactor() -> Option<Redactor> {
    Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
        .ok()
        .map(|regex| Redactor::regex(regex, Some("•••@•••".to_owned())))
}

/// Redacts MAC addresses.
pub fn mac_address_redactor() -> Option<Redactor> {
    Regex::new(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})")
        .ok()
        .map(|re| Redactor::regex(re, Some("••:••:••:••:••:••".to_string())))
}

/// Creates a `Redactor` for IPv4 addresses.
///
/// This redactor uses a regex to find and replace IPv4 addresses with `IPv4<••.••.••.••>`.
pub fn ipv4_redactor() -> Option<Redactor> {
    Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        .ok()
        .map(|regex| Redactor::regex(regex, Some("IPv4<••.••.••.••>".to_owned())))
}

// A simple validator function that leverages Rust's IPv6 parser.
fn is_valid_ipv6(s: &str) -> bool {
    Ipv6Addr::from_str(s).is_ok()
}

/// Creates a Redactor for IPv6 addresses using regex search and std lib validation.
pub fn ipv6_redactor() -> Option<Redactor> {
    // This regex is intentionally broad. It finds any "word" that contains hex
    // characters and at least one colon. The powerful `Ipv6Addr` parser
    // will then reject anything that isn't a valid address (like a MAC address).
    let pattern = r"\b[0-9a-fA-F:]+:[0-9a-fA-F:]*\b";

    Regex::new(pattern).ok().map(|re| {
        Redactor::validated(
            re,
            is_valid_ipv6,
            Some("IPv6<••:••:••:••:••:••:••:••>".to_owned()),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_redactor() {
        let redactor = email_redactor().unwrap();
        assert_eq!(redactor.redact("john.doe@example.com"), "•••@•••");
    }

    #[test]
    fn test_ipv4_redactor() {
        let redactor = ipv4_redactor().unwrap();
        assert_eq!(redactor.redact("192.168.0.1"), "IPv4<••.••.••.••>");
        assert_eq!(redactor.redact("10.0.0.1"), "IPv4<••.••.••.••>");
    }

    #[test]
    fn test_ipv6_redactor() {
        let redactor = ipv6_redactor().unwrap();
        assert_eq!(
            redactor.redact("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            "IPv6<••:••:••:••:••:••:••:••>"
        );
        assert_eq!(
            redactor.redact("2001:0db8:85a3:1234::8a2e:0370:7334"),
            "IPv6<••:••:••:••:••:••:••:••>"
        );
    }
}
