//! String helpers, the 32-bit hash, and the constant tables.
//!
//! These match the small set of helpers the converter relies on: name
//! sanitisation, a JavaScript-compatible string hash, camel casing, and the
//! property name tables that drive parameter and schema fixups.

/// Properties that move from a 2.0 parameter or header onto its schema.
pub const PARAMETER_TYPE_PROPERTIES: &[&str] = &[
    "format",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "minLength",
    "maxLength",
    "multipleOf",
    "minItems",
    "maxItems",
    "uniqueItems",
    "minProperties",
    "maxProperties",
    "additionalProperties",
    "pattern",
    "enum",
    "default",
];

/// Array-shaped schema keywords.
pub const ARRAY_PROPERTIES: &[&str] = &["items", "minItems", "maxItems", "uniqueItems"];

/// HTTP methods recognised as operation keys on a path item.
pub const HTTP_METHODS: &[&str] = &[
    "get", "post", "put", "delete", "patch", "head", "options", "trace",
];

/// Sanitise a component name.
///
/// Only the first path segment, the part before the first `/`, is character
/// scrubbed. Any run of characters outside `[A-Za-z0-9_\-.]` or any whitespace
/// run collapses to a single `_`. A leading literal `[]` becomes `Array` first.
pub fn sanitise(s: &str) -> String {
    let s = replace_first(s, "[]", "Array");
    let mut components: Vec<String> = s.split('/').map(|c| c.to_string()).collect();
    if let Some(first) = components.first_mut() {
        *first = scrub_first_component(first);
    }
    components.join("/")
}

/// Sanitise a name as a single component.
///
/// Replaces every `/` with `_`, then sanitises the whole thing as one segment.
pub fn sanitise_all(s: &str) -> String {
    let joined = s.split('/').collect::<Vec<_>>().join("_");
    sanitise(&joined)
}

/// Replace the first occurrence of `from` with `to`.
fn replace_first(s: &str, from: &str, to: &str) -> String {
    match s.find(from) {
        Some(idx) => {
            let mut out = String::with_capacity(s.len() - from.len() + to.len());
            out.push_str(&s[..idx]);
            out.push_str(to);
            out.push_str(&s[idx + from.len()..]);
            out
        }
        None => s.to_string(),
    }
}

/// Collapse every run of disallowed characters or whitespace to one `_`.
///
/// Allowed characters are ASCII letters, digits, `_`, `-`, and `.`. This mirrors
/// the regex `[^A-Za-z0-9_\-\.]+|\s+` applied with a single underscore.
fn scrub_first_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_run = false;
    for ch in s.chars() {
        let allowed =
            (ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.')) && !ch.is_whitespace();
        if allowed {
            out.push(ch);
            in_run = false;
        } else if !in_run {
            out.push('_');
            in_run = true;
        }
    }
    out
}

/// JavaScript-compatible string hash.
///
/// Iterates over UTF-16 code units and uses wrapping 32-bit signed arithmetic,
/// matching `charCodeAt` plus `hash |= 0`. The result is used only as a cache
/// key for request body deduplication, but the exact value affects naming and
/// ordering of shared request bodies.
pub fn hash(s: &str) -> i32 {
    let mut h: i32 = 0;
    for unit in s.encode_utf16() {
        h = h.wrapping_shl(5).wrapping_sub(h).wrapping_add(unit as i32);
    }
    h
}

/// Lowercase the string, then drop each `- _ space / .` separator and uppercase
/// the character that follows it.
pub fn to_camel_case(s: &str) -> String {
    let lower = s.to_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut chars = lower.chars().peekable();
    while let Some(ch) = chars.next() {
        if matches!(ch, '-' | '_' | ' ' | '/' | '.') {
            if let Some(&next) = chars.peek() {
                chars.next();
                out.extend(next.to_uppercase());
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Keep only first occurrences, preserving order.
pub fn unique_only(values: &[String]) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for v in values {
        if !seen.iter().any(|e| e == v) {
            seen.push(v.clone());
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitise_scrubs_first_component_only() {
        assert_eq!(sanitise("foo bar/baz qux"), "foo_bar/baz qux");
        assert_eq!(sanitise("a@b/c@d"), "a_b/c@d");
        assert_eq!(sanitise("name[]"), "nameArray");
    }

    #[test]
    fn sanitise_all_joins_then_scrubs() {
        assert_eq!(sanitise_all("a/b c"), "a_b_c");
    }

    #[test]
    fn hash_matches_javascript() {
        // Verified against the JavaScript implementation.
        assert_eq!(hash(""), 0);
        assert_eq!(hash("a"), 97);
        assert_eq!(hash("hello"), 99162322);
    }

    #[test]
    fn camel_case_drops_separators() {
        assert_eq!(to_camel_case("_body"), "Body");
        assert_eq!(to_camel_case("add-pet item"), "addPetItem");
    }

    #[test]
    fn unique_keeps_first() {
        let input = vec!["a".into(), "b".into(), "a".into(), "c".into()];
        assert_eq!(unique_only(&input), vec!["a", "b", "c"]);
    }
}
