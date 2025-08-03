pub mod redactor;
pub mod redactors;

pub struct Biip {
    redactors: Vec<redactor::Redactor>,
}

impl Biip {
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

    pub fn process(self: &Self, string: &str) -> String {
        let mut redacted = string.to_string();
        for r in &self.redactors {
            redacted = r.redact(&redacted);
        }
        redacted
    }
}
