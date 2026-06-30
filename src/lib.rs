//! Convert Swagger 2.0 (OpenAPI v2.0) API definitions to OpenAPI 3.0.x.
//!
//! The entry points take a Swagger 2.0 document and return an OpenAPI 3.0.x
//! document. The work is a pure data transform over [`serde_json::Value`].
//! Parameters become request bodies, `securityDefinitions` becomes
//! `components.securitySchemes`, `definitions` becomes `components.schemas`,
//! and `host`/`basePath`/`schemes` become `servers`. Non-compliant JSON Schema
//! constructs are repaired in place.
//!
//! # Entry points
//!
//! - [`convert_obj`] and its alias [`convert`] take a parsed value.
//! - [`convert_str`] parses JSON or YAML text first.
//! - [`convert_file`] reads a path, [`convert_stream`] drains a reader.
//!
//! Each writes the result into [`Options::openapi`] and returns `Result<(),
//! S2OError>`. [`Options`] also carries the input flags and the conversion
//! outputs such as the patch count and the `$ref` rewrite map.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub(crate) mod common;
pub(crate) mod convert;
pub(crate) mod error;
pub(crate) mod fixup;
pub(crate) mod jptr;
pub(crate) mod options;
pub(crate) mod recurse;
pub(crate) mod resolver;
pub(crate) mod schema_walker;
pub(crate) mod yaml;

#[cfg(test)]
mod corpus_tests;

pub use convert::convert_obj;
pub use error::S2OError;
pub use options::{Options, RefSiblings};

use serde_json::Value;

/// Default `openapi` version string emitted unless `options.target_version`
/// overrides it.
pub const TARGET_VERSION: &str = "3.0.0";

/// Convert a Swagger 2.0 object, an alias for [`convert_obj`].
///
/// On success `options.openapi` holds the OpenAPI 3.0 document.
pub fn convert(swagger: &Value, options: &mut Options) -> Result<(), S2OError> {
    convert_obj(swagger, options)
}

/// Convert a JSON or YAML string.
///
/// JSON is tried first, then YAML. `options.text` records the source text and
/// `options.source_yaml` is set when the YAML parser handled the input. A parse
/// failure for both formats returns an error.
pub fn convert_str(text: &str, options: &mut Options) -> Result<(), S2OError> {
    let value = match serde_json::from_str::<Value>(text) {
        Ok(mut v) => {
            options.text = serde_json::to_string_pretty(&v).unwrap_or_default();
            yaml::normalise_numbers(&mut v);
            v
        }
        Err(_) => {
            let v = yaml::parse_yaml(text)?;
            options.source_yaml = true;
            options.text = text.to_string();
            options.had_anchors = yaml::has_alias(text);
            v
        }
    };
    convert_obj(&value, options)
}

/// Convert a document read from a file.
///
/// The file is read as UTF-8. `options.source_file` records the path, and
/// `options.source` is set to the path for `$ref` resolution unless the caller
/// already supplied a base.
pub fn convert_file(path: &str, options: &mut Options) -> Result<(), S2OError> {
    let text = std::fs::read_to_string(path).map_err(|e| S2OError::new(format!("{path}: {e}")))?;
    options.source_file = Some(path.to_string());
    if options.source.is_none() {
        options.source = Some(path.to_string());
    }
    convert_str(&text, options)
}

/// Convert a document read from any reader.
///
/// The reader is drained to a string, then handed to [`convert_str`].
pub fn convert_stream<R: std::io::Read>(
    mut reader: R,
    options: &mut Options,
) -> Result<(), S2OError> {
    let mut text = String::new();
    reader
        .read_to_string(&mut text)
        .map_err(|e| S2OError::new(e.to_string()))?;
    convert_str(&text, options)
}
