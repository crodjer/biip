use std::borrow::Cow;

use crate::{redactor, redactors};

/// The main struct for `biip`, responsible for holding the redactors and
/// processing text.
pub struct Biip {
    redactors: Vec<redactor::Redactor>,
}

/// A redaction region in the original input, expressed as a UTF-8 byte range.
#[derive(Debug, PartialEq, Eq)]
pub struct RedactionMatch {
    pub start: usize,
    pub end: usize,
}

impl Biip {
    /// Creates a new `Biip` instance with a default set of redactors.
    ///
    /// The order of redactors is important to prevent conflicts (e.g., a MAC
    /// address being mistaken for a partial IPv6 address). The order is
    /// generally:
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
            redactors::uuid_redactor,
            redactors::cloud_keys_redactor,
        ]
        .iter()
        .filter_map(|&redactor| redactor())
        .collect();
        Biip { redactors }
    }

    /// Returns non-overlapping redaction regions in original-input byte offsets.
    ///
    /// Regions follow configured redactor priority. A later match that overlaps
    /// an earlier match is omitted, matching the existing pipeline where an
    /// earlier replacement prevents later redactors from seeing that content.
    pub fn matches(&self, string: &str) -> Vec<RedactionMatch> {
        // Keep an original-byte provenance range for every byte of the evolving
        // text. A replacement inherits the complete original range it replaces;
        // this is deliberately conservative when a later redactor matches text
        // made adjacent by an earlier replacement.
        let mut text = string.to_owned();
        let mut provenance: Vec<Vec<std::ops::Range<usize>>> = (0..string
            .len())
            .map(|index| vec![index..index + 1])
            .collect();
        let mut redacted = Vec::new();

        for redactor in &self.redactors {
            let ranges = redactor.matches(&text);
            if ranges.is_empty() {
                continue;
            }

            for range in &ranges {
                redacted.extend(
                    provenance[range.clone()].iter().flatten().cloned(),
                );
            }

            let mut next_text = String::new();
            let mut next_provenance = Vec::new();
            let mut cursor = 0;
            for range in ranges {
                next_text.push_str(&text[cursor..range.start]);
                next_provenance
                    .extend_from_slice(&provenance[cursor..range.start]);

                let replacement =
                    redactor.redact(&text[range.clone()]).into_owned();
                let inherited: Vec<_> = provenance[range.clone()]
                    .iter()
                    .flatten()
                    .cloned()
                    .collect();
                next_provenance.extend(
                    std::iter::repeat(inherited).take(replacement.len()),
                );
                next_text.push_str(&replacement);
                cursor = range.end;
            }
            next_text.push_str(&text[cursor..]);
            next_provenance.extend_from_slice(&provenance[cursor..]);
            text = next_text;
            provenance = next_provenance;
        }

        redacted.sort_by_key(|range| range.start);
        let mut merged: Vec<RedactionMatch> = Vec::new();
        for range in redacted {
            if let Some(last) = merged.last_mut() {
                if range.start <= last.end {
                    last.end = last.end.max(range.end);
                    continue;
                }
            }
            merged.push(RedactionMatch {
                start: range.start,
                end: range.end,
            });
        }
        merged
    }

    /// Processes a string, applying all configured redactors to it.
    pub fn process(self: &Self, string: &str) -> String {
        let mut current_text = Cow::Borrowed(string);

        for r in &self.redactors {
            let redacted_cow = r.redact(&current_text);

            // If the redactor returned an owned string, it means a change was
            // made. We update `current_text` to hold this new owned
            // string for the next iteration. If it returned a
            // borrowed slice, no change was made, and we continue
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
    use std::env;

    use regex::Regex;

    use super::*;

    #[test]
    fn reports_original_utf8_byte_spans_in_priority_order() {
        let input = "é key sk-abcdefghijklmnopqrstuvwxyz1234567890ABCD and email user@example.com";
        let biip = Biip::new();

        assert_eq!(
            biip.matches(input),
            vec![
                RedactionMatch { start: 7, end: 50 },
                RedactionMatch { start: 61, end: 77 },
            ]
        );
    }

    #[test]
    fn spans_cover_keys_exposed_after_an_earlier_replacement() {
        unsafe {
            env::set_var("MY_SECRET", "prefix");
        }
        let input = "prefixsk-abcdefghijklmnopqrstuvwxyz123456";
        let biip = Biip::new();

        assert_eq!(biip.process(input), "••••⚿•••••☁️•");
        assert_eq!(
            biip.matches(input),
            vec![RedactionMatch {
                start: 0,
                end: input.len(),
            }]
        );
    }

    #[test]
    fn overlaps_keep_the_first_redactor_match() {
        let biip = Biip {
            redactors: vec![
                redactor::Redactor::regex(
                    Regex::new("secret-value").unwrap(),
                    None,
                ),
                redactor::Redactor::regex(Regex::new("value").unwrap(), None),
            ],
        };

        assert_eq!(
            biip.matches("secret-value"),
            vec![RedactionMatch { start: 0, end: 12 }]
        );
    }

    #[test]
    fn validated_matches_exclude_private_ip_addresses() {
        let biip = Biip {
            redactors: vec![redactors::ipv4_redactor().unwrap()],
        };

        assert!(biip.matches("192.168.1.1").is_empty());
        assert_eq!(
            biip.matches("8.8.8.8"),
            vec![RedactionMatch { start: 0, end: 7 }]
        );
    }

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
