use regex::RegexBuilder;

use crate::redactor::Redactor;
use std::env;

pub fn username_redactor() -> Option<Redactor> {
    match env::var("USER") {
        Ok(user) => Some(Redactor::regex(
            RegexBuilder::new(&format!(r"\b{}\b", user))
                .case_insensitive(true)
                .build()
                .ok()?,
            Some("user".to_string()),
        )),
        Err(_) => None,
    }
}

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
