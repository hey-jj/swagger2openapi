//! YAML and JSON parsing into a [`serde_json::Value`].
//!
//! The string, file, and stream entry points accept either JSON or YAML. JSON
//! is tried first, then YAML. Map keys that parse as integers, such as response
//! status codes, are normalised to strings so the document model stays uniform.

use serde_json::Value;

use crate::error::S2OError;

/// Parse `text` as JSON, then YAML.
///
/// Returns the parsed value, or an error when neither parse yields a value.
pub fn parse(text: &str) -> Result<Value, S2OError> {
    if let Ok(mut value) = serde_json::from_str::<Value>(text) {
        normalise_numbers(&mut value);
        return Ok(value);
    }
    parse_yaml(text)
}

/// Collapse integer-valued floats to integers throughout a value.
///
/// JSON keeps `1.0` as a float, but the converter follows JavaScript where it is
/// the integer `1`. This walks the tree so structural comparisons match.
pub fn normalise_numbers(value: &mut Value) {
    match value {
        Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                if !n.is_i64()
                    && !n.is_u64()
                    && f.fract() == 0.0
                    && f >= i64::MIN as f64
                    && f <= i64::MAX as f64
                {
                    *n = (f as i64).into();
                }
            }
        }
        Value::Array(arr) => arr.iter_mut().for_each(normalise_numbers),
        Value::Object(map) => map.values_mut().for_each(normalise_numbers),
        _ => {}
    }
}

/// Parse `text` as YAML only.
pub fn parse_yaml(text: &str) -> Result<Value, S2OError> {
    let yaml_value: serde_yaml::Value =
        serde_yaml::from_str(text).map_err(|e| S2OError::new(e.to_string()))?;
    Ok(to_json(yaml_value))
}

/// Whether the YAML text uses an anchor that an alias later references.
///
/// The deserializer expands aliases into independent copies, so the shared
/// identity that an anchor creates is gone by the time the document is a
/// [`serde_json::Value`]. This text scan recovers the signal the converter needs
/// to reject anchors when they are not allowed. It looks for an anchor `&name`
/// paired with a matching alias `*name`, skipping flow scalars and comments at a
/// coarse level.
pub fn has_alias(text: &str) -> bool {
    let mut anchors: Vec<String> = Vec::new();
    let mut aliases: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = strip_comment(line);
        collect_tokens(line, '&', &mut anchors);
        collect_tokens(line, '*', &mut aliases);
    }
    aliases.iter().any(|a| anchors.contains(a))
}

/// Drop an inline `#` comment, ignoring `#` inside quotes.
fn strip_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    for (i, ch) in line.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => return &line[..i],
            _ => {}
        }
    }
    line
}

/// Collect names that follow `marker`, like `&name` or `*name`.
fn collect_tokens(line: &str, marker: char, out: &mut Vec<String>) {
    let bytes: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == marker {
            let prev_ok = i == 0
                || bytes[i - 1].is_whitespace()
                || bytes[i - 1] == '['
                || bytes[i - 1] == '{'
                || bytes[i - 1] == ',';
            if prev_ok {
                let mut j = i + 1;
                while j < bytes.len()
                    && (bytes[j].is_alphanumeric() || bytes[j] == '-' || bytes[j] == '_')
                {
                    j += 1;
                }
                if j > i + 1 {
                    out.push(bytes[i + 1..j].iter().collect());
                }
                i = j;
                continue;
            }
        }
        i += 1;
    }
}

/// Serialize a value to YAML text.
pub fn stringify(value: &Value) -> String {
    serde_yaml::to_string(value).unwrap_or_default()
}

/// Convert a [`serde_yaml::Value`] into a [`serde_json::Value`].
///
/// Mapping keys are coerced to strings. Numeric and boolean keys become their
/// textual form, matching how JSON objects key everything by string.
fn to_json(value: serde_yaml::Value) -> Value {
    match value {
        serde_yaml::Value::Null => Value::Null,
        serde_yaml::Value::Bool(b) => Value::Bool(b),
        serde_yaml::Value::Number(n) => number_to_json(n),
        serde_yaml::Value::String(s) => Value::String(s),
        serde_yaml::Value::Sequence(seq) => Value::Array(seq.into_iter().map(to_json).collect()),
        serde_yaml::Value::Mapping(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                out.insert(key_to_string(k), to_json(v));
            }
            Value::Object(out)
        }
        serde_yaml::Value::Tagged(tagged) => to_json(tagged.value),
    }
}

/// Render a YAML number as a JSON number.
///
/// Integer-valued floats such as `1.0` collapse to integers. JavaScript has one
/// number type, so the converter treats `1.0` and `1` as the same value. The
/// collapse keeps structural comparisons aligned with that behaviour.
fn number_to_json(n: serde_yaml::Number) -> Value {
    if let Some(i) = n.as_i64() {
        Value::Number(i.into())
    } else if let Some(u) = n.as_u64() {
        Value::Number(u.into())
    } else if let Some(f) = n.as_f64() {
        if f.fract() == 0.0 && f >= i64::MIN as f64 && f <= i64::MAX as f64 {
            Value::Number((f as i64).into())
        } else {
            serde_json::Number::from_f64(f)
                .map(Value::Number)
                .unwrap_or(Value::Null)
        }
    } else {
        Value::Null
    }
}

/// Convert a YAML mapping key to its string form.
fn key_to_string(key: serde_yaml::Value) -> String {
    match key {
        serde_yaml::Value::String(s) => s,
        serde_yaml::Value::Bool(b) => b.to_string(),
        serde_yaml::Value::Number(n) => n.to_string(),
        serde_yaml::Value::Null => "null".to_string(),
        other => serde_yaml::to_string(&other)
            .unwrap_or_default()
            .trim()
            .to_string(),
    }
}
