//! RFC 6901 JSON pointer get and set over a [`serde_json::Value`].
//!
//! This module will hold `jptr` get and set, `jpescape`, and `jpunescape`,
//! matching the miss-returns-false, `-` append, and `~0`/`~1` semantics the
//! converter depends on.
