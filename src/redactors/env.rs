use regex::Regex;

use crate::redactor::Redactor;
use std::env;

const ENV_SECRET_PATTERNS: &[&str] = &["password", "secret", "token", "key", "username", "email"];

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
            .map(|regex| Redactor::regex(regex, Some(String::from("**secret**"))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secrets_redactor() {
        unsafe {
            env::set_var("BIIP_TEST_PASSWORD", "my-awesome-secret");
            env::set_var("BIIP_SECRET_TEST", "my-awesome-password");
            env::set_var("TOKEN_FOR_BIIP_TEST", "my-awesome-token");
            env::set_var("A_KEY_FOR_TEST_WITH_BIIP", "my-awesome-key");
            env::set_var("SAFE_ENV_VAR", "safe-var");
        }

        let redactor = secrets_redactor().unwrap();

        assert_eq!(
            redactor.redact("password: my-awesome-secret"),
            "password: **secret**"
        );
        assert_eq!(
            redactor.redact("secret: my-awesome-password"),
            "secret: **secret**"
        );
        assert_eq!(
            redactor.redact("token: my-awesome-token"),
            "token: **secret**"
        );
        assert_eq!(redactor.redact("key: my-awesome-key"), "key: **secret**");
        assert_eq!(
            redactor.redact("key: my-awesome-key, Var: safe-var"),
            "key: **secret**, Var: safe-var"
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
            "secret: **secret**"
        );
    }
}
