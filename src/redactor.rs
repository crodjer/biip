use regex::{Captures, Regex};

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
    /// A regex-based replacement that uses capture groups.
    /// The `Regex` is the pattern, and the `String` is the replacement
    /// which can include capture group references like `$1`, `$2`.
    ReWithCapture(Regex, String),
    /// A regex that finds candidates, which are then passed to a validator function.
    /// Only if the validator returns true is the match redacted.
    Validated(Regex, fn(&str) -> bool, String),
}

impl Redactor {
    /// Creates a new `Redactor::Simple` variant.
    ///
    /// # Arguments
    ///
    /// * `pattern` - The string pattern to search for.
    /// * `beep` - An optional replacement string. If `None`, a default replacer will be used.
    pub fn simple(pattern: String, beep: Option<String>) -> Self {
        let replacer = beep.clone().unwrap_or(String::from("•••"));
        Redactor::Simple(pattern, replacer)
    }

    /// Creates a new `Redactor::Re` variant.
    ///
    /// # Arguments
    ///
    /// * `pattern` - The regex pattern to search for.
    /// * `beep` - An optional replacement string. If `None`, a default replacer will be used.
    pub fn regex(pattern: Regex, beep: Option<String>) -> Self {
        let replacer = beep.clone().unwrap_or(String::from("•••"));
        Redactor::Re(pattern, replacer)
    }

    /// Creates a new `Redactor::ReWithCapture` variant.
    ///
    /// # Arguments
    ///
    /// * `pattern` - The regex pattern to search for.
    /// * `replacer` - The replacement string with capture groups.
    pub fn regex_with_capture(pattern: Regex, replacer: String) -> Self {
        Redactor::ReWithCapture(pattern, replacer)
    }

    /// Creates a new `Redactor::Validated` variant.
    ///
    /// # Arguments
    ///
    /// * `pattern` - The regex pattern to search for.
    /// * `validator` - A function to validate the redacted text.
    /// * `beep` - An optional replacement string. If `None`, a default replacer will be used.
    pub fn validated(pattern: Regex, validator: fn(&str) -> bool, beep: Option<String>) -> Self {
        let replacer = beep.clone().unwrap_or(String::from("•••"));
        Redactor::Validated(pattern, validator, replacer)
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
            Redactor::Re(pattern, replacer) => pattern.replace_all(text, replacer).to_string(),
            Redactor::ReWithCapture(pattern, replacer) => {
                pattern.replace_all(text, replacer.as_str()).to_string()
            }
            Redactor::Validated(pattern, validator, replacer) => {
                pattern
                    .replace_all(text, |caps: &Captures| {
                        if validator(&caps[0]) {
                            replacer.clone()
                        } else {
                            // If invalid, return the original string for this match.
                            caps[0].to_string()
                        }
                    })
                    .to_string()
            }
        }
    }
}
