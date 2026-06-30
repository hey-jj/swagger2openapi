//! Deep clone helpers over [`serde_json::Value`].
//!
//! A [`serde_json::Value`] tree cannot hold cycles, so a deep clone is enough.
//! Both helpers exist to keep call sites readable next to the algorithm they
//! mirror.

use serde_json::Value;

/// Deep clone a value.
pub fn clone(value: &Value) -> Value {
    value.clone()
}

/// Deep clone a value with cycle safety.
///
/// A [`serde_json::Value`] cannot contain cycles, so this is a plain deep clone.
pub fn circular_clone(value: &Value) -> Value {
    value.clone()
}
