//! The crate error type and the throw-or-warn policy.

use std::error::Error;
use std::fmt;

use serde_json::Value;

use crate::options::Options;

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

/// Build an error. The name mirrors the throw site in the algorithm.
pub fn throw_error(message: impl Into<String>) -> S2OError {
    S2OError::new(message)
}

/// Either warn into a container or raise an error.
///
/// When `warn_only` is set, the message is written into `container` under the
/// configured warning property and `Ok(())` is returned. Otherwise the message
/// becomes an error.
pub fn throw_or_warn(
    message: impl Into<String>,
    container: &mut Value,
    options: &Options,
) -> Result<(), S2OError> {
    let message = message.into();
    if options.warn_only {
        let prop = if options.warn_property.is_empty() {
            crate::options::DEFAULT_WARN_PROPERTY.to_string()
        } else {
            options.warn_property.clone()
        };
        if let Some(map) = container.as_object_mut() {
            map.insert(prop, Value::String(message));
        }
        Ok(())
    } else {
        Err(S2OError::new(message))
    }
}
