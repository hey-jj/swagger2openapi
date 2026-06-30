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
/// The struct holds three kinds of field, kept apart below: inputs the caller
/// sets before a run, outputs the converter writes for the caller to read, and
/// internal scratch the converter uses during a run. The entry points mutate it
/// in place. The caller sets the inputs, then reads `openapi` and the other
/// outputs after the call returns.
#[derive(Debug, Default)]
pub struct Options {
    // --- inputs: set these before calling an entry point ---
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
    /// File read encoding. Only `utf8` is supported.
    pub encoding: Option<String>,

    // --- outputs: read these after the call returns ---
    /// The converted OpenAPI 3.0 document. This is the conversion result.
    pub openapi: Value,
    /// Count of patches applied.
    pub patches: u64,
    /// Textual source recorded during conversion. The string entry points set
    /// it from the source text. `convert_obj` sets it to the YAML form of the
    /// input value when no entry point set it first.
    pub text: String,
    /// Set when the input parsed as YAML rather than JSON.
    pub source_yaml: bool,
    /// The file path passed to the file entry point.
    pub source_file: Option<String>,
    /// The `$ref` rewrite map produced during conversion.
    pub refmap: Value,

    // --- internal: set and read by the converter, not by callers ---
    /// Set by YAML entry points when the source used an anchor and alias.
    ///
    /// The converter rejects anchors unless `anchors` is set. The parsed value
    /// no longer carries the shared identity, so the flag preserves the signal.
    /// Private to the crate so a caller cannot forge the anchor signal.
    pub(crate) had_anchors: bool,
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
