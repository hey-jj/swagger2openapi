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

pub use error::S2OError;
pub use options::Options;

/// Default `openapi` version string emitted unless `options.target_version`
/// overrides it.
pub const TARGET_VERSION: &str = "3.0.0";
