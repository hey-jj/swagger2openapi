//! The crate error type and the throw-or-warn policy.

use std::error::Error;
use std::fmt;

use serde_json::Value;

use crate::options::Options;

/// The single error type raised by the converter.
///
/// The name keeps the `S2O` (Swagger to OpenAPI) prefix so callers have a stable
/// type to match on.
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
}

impl fmt::Display for S2OError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for S2OError {}

/// Either warn into a container or raise an error.
///
/// When `warn_only` is set, the message is written into `container` under the
/// configured warning property and `Ok(())` is returned. Otherwise the message
/// becomes an error.
pub fn warn_or_error(
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
