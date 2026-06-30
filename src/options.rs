//! The [`Options`] input and output bag.
//!
//! `Options` carries the behavioural inputs (`patch`, `warn_only`, and so on)
//! and the values the converter writes back (`openapi`, `patches`, `refmap`).
//! The converter mutates it in place.

use serde_json::Value;

/// Default property name used to store warnings when `warn_only` is set.
pub const DEFAULT_WARN_PROPERTY: &str = "x-s2o-warning";

/// How to handle a `$ref` object that carries sibling properties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RefSiblings {
    /// Drop the siblings and keep only the `$ref`. This is the default.
    #[default]
    Remove,
    /// Keep the siblings next to the `$ref`.
    Preserve,
    /// Wrap the `$ref` and its siblings in an `allOf` when inside a schema.
    AllOf,
}

/// Inputs and outputs for a conversion run.
///
/// Fields are filled in as the converter and the test harness mature. The
/// struct is mutated in place during conversion.
#[derive(Debug, Default)]
pub struct Options {
    /// Repair small patchable errors instead of returning an error.
    pub patch: bool,
    /// Never error on non-patchable problems. Write a warning extension into
    /// the offending container instead.
    pub warn_only: bool,
    /// Property name used to store warnings when `warn_only` is set.
    pub warn_property: String,
    /// Keep deleted parameters and add debug markers.
    pub debug: bool,
    /// Output `openapi` version string, used when it starts with `3.`.
    pub target_version: Option<String>,
    /// Resolve external `$ref`s.
    pub resolve: bool,
    /// Resolve internal `$ref`s. Disables shared request body extraction.
    pub resolve_internal: bool,
    /// How to handle `$ref` siblings.
    pub ref_siblings: RefSiblings,
    /// Extension key under which to preserve body parameter names. Empty
    /// disables the feature.
    pub rbname: String,
    /// Add an `x-origin` provenance entry when set.
    pub origin: bool,
    /// Source URL or path. Used for provenance and as a resolver base.
    pub source: Option<String>,
    /// Allow YAML anchors and shared object references.
    pub anchors: bool,
    /// Return the bare `openapi` document instead of the options bag.
    pub direct: bool,
    /// The converted output document.
    pub openapi: Value,
    /// Count of patches applied.
    pub patches: u64,
}

impl Options {
    /// Build an options bag with default settings.
    pub fn new() -> Self {
        Options {
            warn_property: DEFAULT_WARN_PROPERTY.to_string(),
            ..Default::default()
        }
    }
}
