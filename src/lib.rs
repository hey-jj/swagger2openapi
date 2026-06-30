//! Convert Swagger 2.0 (OpenAPI v2.0) API definitions to OpenAPI 3.0.x.
//!
//! The entry points take a Swagger 2.0 document and return an OpenAPI 3.0.x
//! document. The work is a pure data transform over [`serde_json::Value`].
//! Parameters become request bodies, `securityDefinitions` becomes
//! `components.securitySchemes`, `definitions` becomes `components.schemas`,
//! and `host`/`basePath`/`schemes` become `servers`. Non-compliant JSON Schema
//! constructs are repaired in place.
//!
//! The [`Options`] struct carries both inputs and outputs and is mutated as the
//! conversion runs. Errors surface as [`S2OError`].
//!
//! # Layout
//!
//! - [`error`]: the [`S2OError`] type and the throw-or-warn policy.
//! - [`options`]: the [`Options`] input and output bag.
//! - [`common`]: string helpers, the 32-bit hash, and the constant tables.
//! - [`jptr`]: RFC 6901 JSON pointer get and set over a [`serde_json::Value`].
//! - [`recurse`]: order-preserving depth-first traversal with path state.
//! - [`clone`]: deep clone helpers.
//! - [`schema_walker`]: schema and subschema traversal.
//! - [`fixup`]: JSON Schema repair passes.
//! - [`status_codes`]: HTTP status reason phrases.
//! - [`convert`]: the conversion orchestration and the process helpers.
//! - [`resolver`]: optional external and internal `$ref` resolution.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod clone;
pub mod common;
pub mod convert;
pub mod error;
pub mod fixup;
pub mod jptr;
pub mod options;
pub mod recurse;
pub mod resolver;
pub mod schema_walker;
pub mod status_codes;
pub mod yaml;

pub use convert::convert_obj;
pub use error::S2OError;
pub use options::Options;

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
/// The file is read with UTF-8 unless `options.encoding` overrides it (only
/// `utf8` is supported). `options.source_file` records the path.
pub fn convert_file(path: &str, options: &mut Options) -> Result<(), S2OError> {
    let text = std::fs::read_to_string(path).map_err(|e| S2OError::new(format!("{path}: {e}")))?;
    options.source_file = Some(path.to_string());
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
