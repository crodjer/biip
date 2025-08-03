use regex::Regex;

pub enum Redactor {
    Simple(String, String),
    Re(Regex, String),
}

impl Redactor {
    pub fn simple(pattern: String, beep: Option<String>) -> Self {
        let replacer = beep.clone().unwrap_or(String::from("***"));
        Redactor::Simple(pattern, replacer)
    }

    pub fn regex(pattern: Regex, beep: Option<String>) -> Self {
        let replacer = beep.clone().unwrap_or(String::from("***"));
        Redactor::Re(pattern, replacer)
    }

    pub fn redact(&self, text: &str) -> String {
        match self {
            Redactor::Simple(pattern, replacer) => text.to_string().replace(pattern, replacer),
            Redactor::Re(pattern, replacer) => {
                // println!("{} matches: {}", pattern, pattern.find_iter(text).count());
                pattern.replace_all(text, replacer).to_string()
            }
        }
    }
}
