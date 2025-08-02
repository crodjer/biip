pub struct Redactor {
    pub pattern: String,
    pub beep: Option<String>,
    replacer: String,
}

impl Redactor {
    pub fn new(pattern: String, beep: Option<String>) -> Self {
        let replacer = beep.clone().unwrap_or(String::from("*****"));
        Redactor { pattern, replacer, beep }
    }

    pub fn redact(&self, text: &str) -> String {
        text.to_string().replace(
            &self.pattern,
            &self.replacer
        )
    }
}
