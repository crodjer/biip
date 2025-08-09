use crate::redactor::Redactor;
use regex::Regex;

/// Redacts JWTs (JSON Web Tokens).
pub fn jwt_redactor() -> Option<Redactor> {
    Regex::new(r"\b(ey[a-zA-Z0-9_-]{10,})\.(ey[a-zA-Z0-9_-]{10,})\.[a-zA-Z0-9_-]*\b")
        .ok()
        .map(|re| Redactor::regex(re, Some("••••🌐•".to_string())))
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
    fn test_jwt_redactor() {
        let redactor = jwt_redactor().unwrap();
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assert_eq!(redactor.redact(jwt), "••••🌐•");
        // Ensure it doesn't redact a regular domain
        assert_eq!(redactor.redact("api.service.io"), "api.service.io");
    }

    #[test]
    fn test_credit_card_redactor() {
        let redactor = credit_card_redactor().unwrap();
        assert_eq!(
            redactor.redact("4111-1111-1111-1111"),
            "•••• •••• •••• ••••"
        );
        assert_eq!(
            redactor.redact("4111 1111 1111 1111"),
            "•••• •••• •••• ••••"
        );
        assert_eq!(redactor.redact("4111111111111111"), "•••• •••• •••• ••••");
    }

    #[test]
    fn test_phone_number_redactor() {
        let redactor = phone_number_redactor().unwrap();
        assert_eq!(redactor.redact("(123) 456-7890"), "(•••) •••-••••");
        assert_eq!(redactor.redact("123-456-7890"), "(•••) •••-••••");
    }

    #[test]
    fn test_uuid_redactor() {
        let redactor = uuid_redactor().unwrap();
        assert_eq!(
            redactor.redact("User ID: 123e4567-e89b-12d3-a456-426614174000"),
            "User ID: ••••••••-••••-••••-••••-••••••••••••"
        );
    }

    #[test]
    fn test_cloud_keys_redactor() {
        let redactor = cloud_keys_redactor().unwrap();
        assert_eq!(
            redactor.redact("My key is AKIAIOSFODNN7EXAMPLE"),
            "My key is ••••☁️•"
        );
        assert_eq!(
            redactor.redact("sk-abcdefghijklmnopqrstuvwxyz1234567890ABCD"),
            "••••☁️•"
        );
    }
}
