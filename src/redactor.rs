use regex::Regex;

/// An enum representing a redaction rule.
///
/// A `Redactor` can be a simple string replacement or a more complex regex-based replacement.
pub enum Redactor {
    /// A simple string-for-string replacement.
    /// The first `String` is the pattern to find, and the second is the replacement.
    Simple(String, String),
    /// A regex-based replacement.
    /// The `Regex` is the pattern to find, and the `String` is the replacement.
    Re(Regex, String),
}

impl Redactor {
    /// Creates a new `Redactor::Simple` variant.
    ///
    /// # Arguments
    ///
    /// * `pattern` - The string pattern to search for.
    /// * `beep` - An optional replacement string. If `None`, a default replacer will be used.
    pub fn simple(pattern: String, beep: Option<String>) -> Self {
        let replacer = beep.clone().unwrap_or(String::from("***"));
        Redactor::Simple(pattern, replacer)
    }

    /// Creates a new `Redactor::Re` variant.
    ///
    /// # Arguments
    ///
    /// * `pattern` - The regex pattern to search for.
    /// * `beep` - An optional replacement string. If `None`, a default replacer will be used.
    pub fn regex(pattern: Regex, beep: Option<String>) -> Self {
        let replacer = beep.clone().unwrap_or(String::from("***"));
        Redactor::Re(pattern, replacer)
    }

    /// Applies the redactor to a given text.
    ///
    /// # Arguments
    ///
    /// * `text` - The text to be redacted.
    ///
    /// # Returns
    ///
    /// A new `String` with the redactions applied.
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
