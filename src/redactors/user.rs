use std::env;

use regex::RegexBuilder;

use crate::redactor::Redactor;

/// Creates a `Redactor` for the current user's username.
///
/// This function reads the `USER` environment variable and creates a
/// case-insensitive regex to replace occurrences of the username with `user`.
///
/// Returns `None` if the `USER` environment variable is not set.
pub fn username_redactor() -> Option<Redactor> {
    match env::var("USER") {
        Ok(user) => Some(Redactor::regex(
            RegexBuilder::new(&format!(r"\b{}\b", regex::escape(&user)))
                .case_insensitive(true)
                .build()
                .ok()?,
            Some("user".to_string()),
        )),
        Err(_) => None,
    }
}

/// Creates a `Redactor` for the user's home directory.
///
/// This function gets the user's home directory path and creates a `Redactor`
/// to replace it with `~`.
///
/// Returns `None` if the home directory path cannot be determined.
pub fn home_redactor() -> Option<Redactor> {
    match env::home_dir() {
        Some(path) => path
            .into_os_string()
            .into_string()
            .map(|path_str| Redactor::simple(path_str, Some("~".to_string())))
            .ok(),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_username_redactor() {
        unsafe {
            env::set_var("USER", "awesome-user");
        }
        let redactor = username_redactor().unwrap();
        assert_eq!(redactor.redact("I am: awesome-user"), "I am: user");
        assert_eq!(redactor.redact("I am: Awesome-user"), "I am: user");
    }

    #[test]
    fn test_home_redactor() {
        unsafe {
            env::set_var("HOME", "/home/awesome-user");
        }
        let redactor = home_redactor().unwrap();
        assert_eq!(
            redactor.redact("My home directory is: /home/awesome-user"),
            "My home directory is: ~"
        );
    }
}
