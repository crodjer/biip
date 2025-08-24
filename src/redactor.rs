use std::borrow::Cow;

use regex::{Regex};

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
    pub fn redact<'a>(&self, text: &'a str) -> Cow<'a, str> {
        match self {
            Redactor::Simple(pattern, replacer) => {
                if text.contains(pattern) {
                    Cow::Owned(text.replace(pattern, replacer))
                } else {
                    Cow::Borrowed(text)
                }
            }
            Redactor::Re(pattern, replacer) | Redactor::ReWithCapture(pattern, replacer) => {
                pattern.replace_all(text, replacer.as_str())
            }
            Redactor::Validated(pattern, validator, replacer) => {
                let mut owned: Option<String> = None;
                let mut last_end = 0;

                for m in pattern.find_iter(text) {
                    if validator(m.as_str()) {
                        // First time we find a valid match, we must allocate.
                        if owned.is_none() {
                            owned = Some(String::with_capacity(text.len()));
                        }
                        let owned_str = owned.as_mut().unwrap();

                        // Append the text from the end of the last match to the start of this one.
                        owned_str.push_str(&text[last_end..m.start()]);
                        // Append the replacement string.
                        owned_str.push_str(replacer);
                        // Update our position.
                        last_end = m.end();
                    }
                }

                // If `owned` is Some, it means we performed at least one redaction.
                // We finish by appending the remainder of the original string.
                match owned {
                    Some(mut s) => {
                        s.push_str(&text[last_end..]);
                        Cow::Owned(s)
                    }
                    // If `owned` is None, no valid matches were found, so we can
                    // return the original string slice without any allocation.
                    None => Cow::Borrowed(text),
                }
            }
        }
    }
}
