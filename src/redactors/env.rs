use regex::{Regex, RegexBuilder};

use crate::redactor::Redactor;
use std::env;

const ENV_SECRET_PATTERNS: &[&str] = &["password", "secret", "token", "key", "username", "email"];

/// Creates a `Redactor` for sensitive environment variables.
///
/// This function scans all environment variables and creates a regex pattern
/// to match the values of variables whose keys contain sensitive keywords
/// (e.g., "password", "secret", "token", "key").
///
/// The matched values are replaced with `••••⚿•`.
///
/// Returns `None` if no such environment variables are found.
pub fn secrets_redactor() -> Option<Redactor> {
    let env_vars: Vec<String> = env::vars()
        .filter(|(key, value)| {
            ENV_SECRET_PATTERNS
                .iter()
                .any(|pattern| key.to_lowercase().contains(pattern))
                && value.trim().len() > 0
        })
        .map(|(_, value)| regex::escape(value.trim()))
        .collect();
    let pattern = env_vars.join("|");

    if pattern.is_empty() {
        None
    } else {
        Regex::new(&pattern)
            .ok()
            .map(|regex| Redactor::regex(regex, Some(String::from("••••⚿•"))))
    }
}

/// Creates a `Redactor` for any environment variables whose names start with "BIIP".
///
/// This lets users define custom variables like `BIIP_PERSONAL_PATTERNS`,
/// `BIIP_SENSITIVE`, etc., and have their values redacted from output.
///
/// Returns `None` if no such environment variables are found.
pub fn custom_patterns_redactor() -> Option<Redactor> {
    // Collect raw regex patterns from BIIP_* env vars (case-insensitive matching)
    let raw_patterns: Vec<String> = env::vars()
        .filter(|(key, value)| key.to_uppercase().starts_with("BIIP") && !value.trim().is_empty())
        .map(|(_, value)| value.trim().to_string())
        .collect();

    if raw_patterns.is_empty() {
        return None;
    }

    // Validate each pattern individually; warn on invalid ones and skip them.
    let valid_parts: Vec<String> = raw_patterns
        .into_iter()
        .filter_map(|p| match RegexBuilder::new(&p).case_insensitive(true).build() {
            Ok(_) => Some(p),
            Err(err) => {
                eprintln!("[biip] Warning: invalid BIIP_* regex '{}': {}", p, err);
                None
            }
        })
        .collect();

    if valid_parts.is_empty() {
        return None;
    }

    let combined = format!("(?:{})", valid_parts.join("|"));
    match RegexBuilder::new(&combined).case_insensitive(true).build() {
        Ok(re) => Some(Redactor::regex(re, Some(String::from("••••⚙•")))),
        Err(err) => {
            eprintln!(
                "[biip] Warning: failed to build combined BIIP_* regex: {}",
                err
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secrets_redactor() {
        unsafe {
            env::set_var("TEST_PASSWORD", "my-awesome-secret");
            env::set_var("SECRET_TEST", "my-awesome-password");
            env::set_var("TOKEN_FOR_BIIP_TEST", "my-awesome-token");
            env::set_var("A_KEY_FOR_TEST_WITH_BIIP", "my-awesome-key");
            env::set_var("SAFE_ENV_VAR", "safe-var");
        }

        let redactor = secrets_redactor().unwrap();

        assert_eq!(
            redactor.redact("password: my-awesome-secret"),
            "password: ••••⚿•"
        );
        assert_eq!(
            redactor.redact("secret: my-awesome-password"),
            "secret: ••••⚿•"
        );
        assert_eq!(
            redactor.redact("token: my-awesome-token"),
            "token: ••••⚿•"
        );
        assert_eq!(redactor.redact("key: my-awesome-key"), "key: ••••⚿•");
        assert_eq!(
            redactor.redact("key: my-awesome-key, Var: safe-var"),
            "key: ••••⚿•, Var: safe-var"
        );
    }

    #[test]
    fn test_secrets_redactor_with_special_chars() {
        unsafe {
            env::set_var("S3_SECRET", "invalid+S3+Key/withReChars");
        }

        let redactor = secrets_redactor().unwrap();

        assert_eq!(
            redactor.redact("secret: invalid+S3+Key/withReChars"),
            "secret: ••••⚿•"
        );
    }

    #[test]
    fn test_custom_patterns_redactor() {
        unsafe {
            // Valid alternation pattern, case-insensitive
            env::set_var("BIIP_CUSTOM", "foo|bar|baz");
            env::set_var("NOT_BIIP", "should-not-be-captured");
        }

        let redactor = custom_patterns_redactor().unwrap();

        let input = "A Foo\nAnother Bar\nAnd Baz\nControl: should-not-be-captured";
        let expected = "A ••••⚙•\nAnother ••••⚙•\nAnd ••••⚙•\nControl: should-not-be-captured";
        assert_eq!(redactor.redact(input), expected);
    }

    #[test]
    fn test_custom_patterns_ignores_invalid_patterns() {
        unsafe {
            // Invalid regex plus a valid one; should warn and still redact using the valid one
            env::set_var("BIIP_BAD", "(");
            env::set_var("BIIP_OK", "qux");
        }

        let redactor = custom_patterns_redactor().unwrap();
        assert_eq!(redactor.redact("X Qux Y"), "X ••••⚙• Y");
    }
}
