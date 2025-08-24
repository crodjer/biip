use std::borrow::Cow;

use crate::redactor;
use crate::redactors;

/// The main struct for `biip`, responsible for holding the redactors and processing text.
pub struct Biip {
    redactors: Vec<redactor::Redactor>,
}

impl Biip {
    /// Creates a new `Biip` instance with a default set of redactors.
    ///
    /// The order of redactors is important to prevent conflicts (e.g., a MAC address
    /// being mistaken for a partial IPv6 address). The order is generally:
    /// 1. User and environment-specific (most specific).
    /// 2. Networking patterns with specific formats.
    /// 3. Generic patterns like JWTs and UUIDs.
    pub fn new() -> Biip {
        let redactors = vec![
            // User-specific redactors
            redactors::home_redactor,
            redactors::username_redactor,
            // Environment and secrets
            redactors::secrets_redactor,
            redactors::custom_patterns_redactor,
            // Networking patterns (order is important here)
            redactors::url_credentials_redactor,
            redactors::email_redactor,
            redactors::mac_address_redactor,
            redactors::ipv4_redactor,
            redactors::ipv6_redactor,
            // Generic and vendor-specific patterns
            redactors::jwt_redactor,
            redactors::credit_card_redactor,
            redactors::phone_number_redactor,
            redactors::uuid_redactor,
            redactors::cloud_keys_redactor,
        ]
        .iter()
        .filter_map(|&redactor| redactor())
        .collect();
        Biip { redactors }
    }

    /// Processes a string, applying all configured redactors to it.
    pub fn process(self: &Self, string: &str) -> String {
        let mut current_text = Cow::Borrowed(string);

        for r in &self.redactors {
            let redacted_cow = r.redact(&current_text);

            // If the redactor returned an owned string, it means a change was made.
            // We update `current_text` to hold this new owned string for the next iteration.
            // If it returned a borrowed slice, no change was made, and we continue
            // operating on the same text.
            if let Cow::Owned(owned) = redacted_cow {
                current_text = Cow::Owned(owned);
            }
        }

        current_text.into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_biip() {
        unsafe {
            env::set_var("USER", "awesome-user");
            env::set_var("HOME", "/home/awesome-user");
            env::set_var("MY_SECRET", "my-awesome-secret")
        }

        let input = [
            "Home: /home/awesome-user/Documents",
            "Username: Awesome-user",
            "Email: user@example.com",
            "IPv4: 192.168.0.1",
            "IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "Secret: my-awesome-secret",
        ]
        .join("\n");
        let expected = [
            "Home: ~/Documents",
            "Username: user",
            "Email: •••@•••",
            "IPv4: 192.168.0.1",
            "IPv6: ••:••:••:••:••:••:••:••",
            "Secret: ••••⚿•",
        ]
        .join("\n");

        let biip = Biip::new();
        assert_eq!(biip.process(&input), expected);
    }
}
