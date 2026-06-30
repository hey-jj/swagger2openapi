//! The crate error type and the throw-or-warn policy.

use std::error::Error;
use std::fmt;

/// The single error type raised by the converter.
///
/// The JavaScript source names this error `S2OError`. The name carries through
/// so test harnesses and callers can match on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S2OError {
    /// Human-readable description of the problem.
    pub message: String,
}

impl S2OError {
    /// Build an error with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        S2OError {
            message: message.into(),
        }
    }

    /// The error name. Always `"S2OError"`.
    pub fn name(&self) -> &'static str {
        "S2OError"
    }
}

impl fmt::Display for S2OError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for S2OError {}
