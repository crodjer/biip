use crate::redactor::Redactor;
use std::env;

pub fn username_redactor() -> Option<Redactor> {
    match env::var("USER") {
        Ok(user) => Some(Redactor::new(user, Some("user".to_string()))),
        Err(_) => None,
    }
}

pub fn home_redactor() -> Option<Redactor> {
    match env::home_dir() {
        Some(path) => path
            .into_os_string()
            .into_string()
            .map(|path_str| Redactor::new(path_str, Some("~".to_string())))
            .ok(),
        None => None
    }
}
