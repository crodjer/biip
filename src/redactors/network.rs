use std::net::{
    Ipv4Addr,
    Ipv6Addr,
};

use regex::Regex;

use crate::redactor::Redactor;

/// Creates a `Redactor` for URL credentials.
///
/// Redacts credentials embedded within a URL.
pub fn url_credentials_redactor() -> Option<Redactor> {
    Regex::new(r"(?P<protocol>https?|ftp)://([^:]+):([^@]+)@")
        .ok()
        .map(|re| {
            Redactor::regex_with_capture(
                re,
                "${protocol}://••••:••••@".to_string(),
            )
        })
}

/// Creates a `Redactor` for email addresses.
///
/// This redactor uses a regex to find and replace email addresses with
/// `•••@•••`.
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
/// This redactor uses a regex to find and replace IPv4 addresses with
/// `••.••.••.••`.
pub fn ipv4_redactor() -> Option<Redactor> {
    // Broadly match IPv4 candidates, then validate and only redact public ones.
    Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        .ok()
        .map(|regex| {
            Redactor::validated(
                regex,
                is_public_ipv4,
                Some("••.••.••.••".to_owned()),
            )
        })
}

// Validators that only consider addresses "public" (i.e., redactable).
// Local/private/link-local/loopback/unspecified/etc. are NOT redacted.
fn is_public_ipv4(s: &str) -> bool {
    if let Ok(addr) = s.parse::<Ipv4Addr>() {
        // Treat these as local/non-sensitive -> do not redact.
        !(addr.is_private()
            || addr.is_loopback()
            || addr.is_link_local()
            || addr.is_unspecified()
            || addr.is_broadcast())
    } else {
        false
    }
}

fn is_public_ipv6(s: &str) -> bool {
    if let Ok(addr) = s.parse::<Ipv6Addr>() {
        // Do not redact loopback (::1), link-local (fe80::/10), unique local
        // (fc00::/7), unspecified (::), or multicast.
        !(addr.is_loopback()
            || addr.is_unicast_link_local()
            || addr.is_unique_local()
            || addr.is_unspecified()
            || addr.is_multicast())
    } else {
        false
    }
}

/// Creates a Redactor for IPv6 addresses using regex search and std lib
/// validation.
pub fn ipv6_redactor() -> Option<Redactor> {
    // Broad candidate: contains at least one colon and ends with a hex digit.
    // This avoids matching bare `::` and most code scopes like `crate::path`.
    // Validation via std parses and filters non-public scopes.
    let pattern = r"\b[0-9a-fA-F:]+:[0-9a-fA-F:]*[0-9a-fA-F]\b";

    Regex::new(pattern).ok().map(|re| {
        Redactor::validated(
            re,
            is_public_ipv6,
            Some("••:••:••:••:••:••:••:••".to_owned()),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_credentials_redactor() {
        let redactor = url_credentials_redactor().unwrap();
        assert_eq!(
            redactor.redact("visit https://user:password123@example.com"),
            "visit https://••••:••••@example.com"
        );
        assert_eq!(
            redactor.redact("no creds here: http://example.com"),
            "no creds here: http://example.com"
        );
    }

    #[test]
    fn test_mac_address_redactor() {
        let redactor = mac_address_redactor().unwrap();
        assert_eq!(
            redactor.redact("My MAC is 00:1A:2B:3C:4D:5E."),
            "My MAC is ••:••:••:••:••:••."
        );
        assert_eq!(
            redactor.redact("Another is 01-23-45-67-89-AB."),
            "Another is ••:••:••:••:••:••."
        );
    }

    #[test]
    fn test_ipv6_redactor_validated() {
        let redactor = ipv6_redactor().unwrap();
        // Link-local should NOT be redacted
        assert_eq!(
            redactor.redact("The address is fe80::aaa:8888:ffff:9999"),
            "The address is fe80::aaa:8888:ffff:9999"
        );
        // Test uncompressed
        assert_eq!(
            redactor.redact("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            "••:••:••:••:••:••:••:••"
        );
        // Ensure it does NOT redact a MAC address
        assert_eq!(
            redactor.redact("This is a MAC: 00:1A:2B:3C:4D:5E"),
            "This is a MAC: 00:1A:2B:3C:4D:5E"
        );
    }

    #[test]
    fn test_ipv6_does_not_redact_rust_paths_or_unspecified() {
        let redactor = ipv6_redactor().unwrap();
        // Rust paths should be unchanged
        assert_eq!(
            redactor.redact("use crate::redactor::Redactor;"),
            "use crate::redactor::Redactor;"
        );
        // Bare unspecified should not be redacted
        assert_eq!(redactor.redact("::"), "::");
    }

    #[test]
    fn test_email_redactor() {
        let redactor = email_redactor().unwrap();
        assert_eq!(
            redactor.redact("email: test@example.com"),
            "email: •••@•••"
        );
    }

    #[test]
    fn test_ipv4_redactor() {
        let redactor = ipv4_redactor().unwrap();
        // Private IPv4 should NOT be redacted
        assert_eq!(redactor.redact("IP: 192.168.1.1"), "IP: 192.168.1.1");
        // Public IPv4 should be redacted
        assert_eq!(redactor.redact("DNS: 8.8.8.8"), "DNS: ••.••.••.••");
    }
}
