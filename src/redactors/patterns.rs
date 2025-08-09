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

/// Redacts JWTs (JSON Web Tokens).
pub fn jwt_redactor() -> Option<Redactor> {
    Regex::new(r"\b(ey[a-zA-Z0-9_-]{10,})\.(ey[a-zA-Z0-9_-]{10,})\.[a-zA-Z0-9_-]*\b")
        .ok()
        .map(|re| Redactor::regex(re, Some("••••🌐•".to_string())))
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

/// Creates a `Redactor` for IPv6 addresses.
///
/// This redactor uses a regex to find and replace both compressed and uncompressed
/// IPv6 addresses with `IPv6<••:••:••:••:••:••:••:••>`.
pub fn ipv6_redactor() -> Option<Redactor> {
    let patterns = [
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b", // Uncompressed
        r"\b(?:[0-9a-fA-F]{1,4}:){1,6}(?::[0-9a-fA-F]{1,4}){0,6}\b", // Compressed
    ];
    Regex::new(&patterns.join("|"))
        .inspect_err(|err| println!("Got error in Foo: {err:#?}"))
        .ok()
        .map(|regex| Redactor::regex(regex, Some("IPv6<••:••:••:••:••:••:••:••>".to_owned())))
}

/// Redacts common credit card number patterns.
/// This is a basic pattern and does not perform Luhn validation.
pub fn credit_card_redactor() -> Option<Redactor> {
    Regex::new(r"\b(?:\d[ -]*?){13,16}\b")
        .ok()
        .map(|re| Redactor::regex(re, Some("•••• •••• •••• ••••".to_string())))
}

/// Redacts common phone number patterns.
pub fn phone_number_redactor() -> Option<Redactor> {
    Regex::new(r"\(?\d{3}\)?[ -]?\d{3}[ -]?\d{4}")
        .ok()
        .map(|re| Redactor::regex(re, Some("(•••) •••-••••".to_string())))
}

/// Redacts UUIDs.
pub fn uuid_redactor() -> Option<Redactor> {
    Regex::new(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
        .ok()
        .map(|re| Redactor::regex(re, Some("••••••••-••••-••••-••••-••••••••••••".to_string())))
}

/// Redacts cloud provider keys (AWS, etc.) and generic hex tokens.
pub fn cloud_keys_redactor() -> Option<Redactor> {
    let patterns = [
        r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",  // AWS Access Key ID
        r"\bsk-[a-zA-Z0-9]{32,48}\b",    // OpenAI
        r"\bAI[a-zA-Z0-9_-]{30,40}\b",   // Gemini
        r"\bgcp_[a-zA-Z0-9_-]{30,40}\b", // Google Cloud Platform
        r"xai-[a-zA-Z0-9]{32,64}\b",     // X Ai
        r"csk-[a-zA-Z0-9]{40,50}\b",     // Cerebras
    ];
    Regex::new(&patterns.join("|"))
        .ok()
        .map(|re| Redactor::regex(re, Some("••••☁️•".to_string())))
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
