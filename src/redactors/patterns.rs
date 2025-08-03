use crate::redactor::Redactor;
use regex::Regex;

pub fn email_redactor() -> Option<Redactor> {
    Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
        .ok()
        .map(|regex| Redactor::regex(regex, Some("****@****".to_owned())))
}

pub fn ipv4_redactor() -> Option<Redactor> {
    Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        .ok()
        .map(|regex| Redactor::regex(regex, Some("***.***.***.***".to_owned())))
}

pub fn ipv6_redactor() -> Option<Redactor> {
    let patterns = [
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b", // Uncompressed
        r"\b(?:[0-9a-fA-F]{1,4}:){1,6}(?::[0-9a-fA-F]{1,4}){0,6}\b", // Compressed
    ];
    Regex::new(&patterns.join("|"))
        .inspect_err(|err| println!("Got error in Foo: {err:#?}"))
        .ok()
        .map(|regex| Redactor::regex(regex, Some("***:****:***".to_owned())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_redactor() {
        let redactor = email_redactor().unwrap();
        assert_eq!(redactor.redact("john.doe@example.com"), "****@****");
    }

    #[test]
    fn test_ipv4_redactor() {
        let redactor = ipv4_redactor().unwrap();
        assert_eq!(redactor.redact("192.168.0.1"), "***.***.***.***");
        assert_eq!(redactor.redact("10.0.0.1"), "***.***.***.***");
    }

    #[test]
    fn test_ipv6_redactor() {
        let redactor = ipv6_redactor().unwrap();
        assert_eq!(
            redactor.redact("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            "***:****:***"
        );
        assert_eq!(
            redactor.redact("2001:0db8:85a3:1234::8a2e:0370:7334"),
            "***:****:***"
        );
    }
}
