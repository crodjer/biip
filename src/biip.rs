use crate::redactor;
use crate::redactors;

/// The main struct for `biip`, responsible for holding the redactors and processing text.
pub struct Biip {
    redactors: Vec<redactor::Redactor>,
}

impl Biip {
    /// Creates a new `Biip` instance with a default set of redactors.
    ///
    /// The default redactors include:
    /// - `home_redactor`: Redacts the user's home directory.
    /// - `username_redactor`: Redacts the current user's username.
    /// - `secrets_redactor`: Redacts sensitive environment variables.
    /// - `email_redactor`: Redacts email addresses.
    /// - `ipv4_redactor`: Redacts IPv4 addresses.
    /// - `ipv6_redactor`: Redacts IPv6 addresses.
    pub fn new() -> Biip {
        let redactors = vec![
            redactors::home_redactor,
            redactors::username_redactor,
            redactors::secrets_redactor,
            redactors::email_redactor,
            redactors::ipv4_redactor,
            redactors::ipv6_redactor,
        ]
        .iter()
        .filter_map(|&redactor| redactor())
        .collect();
        Biip { redactors }
    }

    /// Processes a string, applying all configured redactors to it.
    pub fn process(self: &Self, string: &str) -> String {
        let mut redacted = string.to_string();
        for r in &self.redactors {
            redacted = r.redact(&redacted);
        }
        redacted
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
            "IPv4: IPv4<••.••.••.••>",
            "IPv6: IPv6<••:••:••:••:••:••:••:••>",
            "Secret: ••••••••",
        ]
        .join("\n");

        let biip = Biip::new();
        assert_eq!(biip.process(&input), expected);
    }
}
