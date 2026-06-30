//! RFC 6901 JSON pointer get and set over a [`serde_json::Value`].
//!
//! [`get`] reads the pointed-to value or returns `None` on a miss, matching the
//! JavaScript `false` return. [`set`] writes a value, creating intermediate
//! containers as needed. Both honour JSON Reference fragments (`#/...`), the
//! `~0`/`~1` escapes, and the array append token `-`.

use serde_json::Value;

/// Escape a path component for use in a JSON pointer.
///
/// `~` becomes `~0` and `/` becomes `~1`.
pub fn jpescape(s: &str) -> String {
    s.replace('~', "~0").replace('/', "~1")
}

/// Reverse [`jpescape`].
///
/// `~1` becomes `/` and `~0` becomes `~`. Order matters for the round trip.
pub fn jpunescape(s: &str) -> String {
    s.replace("~1", "/").replace("~0", "~")
}

/// Split a pointer into normalised path components.
///
/// Returns `None` when the pointer addresses the whole document (empty or `#`),
/// or `Some(Err(()))` when a non-empty URI precedes the fragment, which signals
/// an external reference this resolver declines.
fn components(prop: &str) -> Result<Option<Vec<String>>, ()> {
    if prop.is_empty() || prop == "#" {
        return Ok(None);
    }

    let mut prop = prop.to_string();
    if prop.contains('#') {
        let mut parts = prop.splitn(2, '#');
        let uri = parts.next().unwrap_or("");
        if !uri.is_empty() {
            return Err(()); // internal resolution only
        }
        let frag = parts.next().unwrap_or("");
        // frag includes the leading '/', drop it then decode '+' to space and
        // percent-decode the remainder.
        let after_hash = frag.strip_prefix('/').unwrap_or(frag);
        prop = decode_uri_component(&after_hash.replace('+', " "));
    }

    let prop = prop.strip_prefix('/').unwrap_or(&prop);
    Ok(Some(prop.split('/').map(jpunescape).collect()))
}

/// Minimal `decodeURIComponent`, decoding `%XX` byte escapes as UTF-8.
fn decode_uri_component(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether a component selects an array element by index.
///
/// Returns the parsed index only when `value` is an array and the component is a
/// canonical base-10 integer that round-trips to the same string.
fn array_index(value: &Value, component: &str) -> Option<usize> {
    if !value.is_array() {
        return None;
    }
    let idx: i64 = component.parse().ok()?;
    if idx < 0 || idx.to_string() != component {
        return None;
    }
    Some(idx as usize)
}

/// Read the value at `prop`.
///
/// Returns `None` on any miss, matching the JavaScript `false` sentinel.
pub fn get<'a>(obj: &'a Value, prop: &str) -> Option<&'a Value> {
    let comps = match components(prop) {
        Ok(Some(c)) => c,
        Ok(None) => return Some(obj),
        Err(()) => return None,
    };

    let mut cur = obj;
    for comp in &comps {
        if let Some(idx) = array_index(cur, comp) {
            cur = cur.as_array().unwrap().get(idx)?;
        } else if comp == "-" && cur.is_array() {
            // Append token on read addresses nothing.
            return None;
        } else {
            cur = cur.as_object()?.get(comp)?;
        }
    }
    Some(cur)
}

/// Whether `prop` resolves to an existing value.
pub fn exists(obj: &Value, prop: &str) -> bool {
    get(obj, prop).is_some()
}

/// Write `new_value` at `prop`, creating intermediate containers as needed.
///
/// Returns the value that was set, or `None` if the path could not be built (for
/// example writing into a scalar). Matches the JavaScript create-on-set rule:
/// a missing intermediate becomes an array when the next component is `0` or
/// `-`, otherwise an object.
pub fn set(obj: &mut Value, prop: &str, new_value: Value) -> Option<Value> {
    let comps = match components(prop) {
        Ok(Some(c)) => c,
        Ok(None) => {
            *obj = new_value.clone();
            return Some(new_value);
        }
        Err(()) => return None,
    };

    set_components(obj, &comps, new_value)
}

/// Recursive set walking `comps` from `cur`.
fn set_components(cur: &mut Value, comps: &[String], new_value: Value) -> Option<Value> {
    let comp = &comps[0];
    let last = comps.len() == 1;

    // Array append token.
    if comp == "-" && cur.is_array() {
        if last {
            cur.as_array_mut().unwrap().push(new_value.clone());
            return Some(new_value);
        }
        // A non-terminal append has no addressable slot.
        return None;
    }

    // Array index.
    if let Some(idx) = array_index(cur, comp) {
        let arr = cur.as_array_mut().unwrap();
        if idx >= arr.len() {
            return None;
        }
        if last {
            arr[idx] = new_value.clone();
            return Some(new_value);
        }
        return set_components(&mut arr[idx], &comps[1..], new_value);
    }

    // Object key.
    if let Value::Object(map) = cur {
        if last {
            map.insert(comp.clone(), new_value.clone());
            return Some(new_value);
        }
        if !map.contains_key(comp) {
            let next = &comps[1];
            let fresh = if next == "0" || next == "-" {
                Value::Array(Vec::new())
            } else {
                Value::Object(serde_json::Map::new())
            };
            map.insert(comp.clone(), fresh);
        }
        let child = map.get_mut(comp).unwrap();
        return set_components(child, &comps[1..], new_value);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rfc6901_pointers() {
        let doc = json!({
            "foo": ["bar", "baz"],
            "": 0,
            "a/b": 1,
            "c%d": 2,
            "m~n": 8
        });
        assert_eq!(get(&doc, ""), Some(&doc));
        assert_eq!(get(&doc, "/foo/0"), Some(&json!("bar")));
        assert_eq!(get(&doc, "/"), Some(&json!(0)));
        assert_eq!(get(&doc, "/a~1b"), Some(&json!(1)));
        assert_eq!(get(&doc, "/m~0n"), Some(&json!(8)));
    }

    #[test]
    fn fragment_percent_decode() {
        let doc = json!({ "c%d": 2, " ": 7 });
        assert_eq!(get(&doc, "#/c%25d"), Some(&json!(2)));
        assert_eq!(get(&doc, "#/%20"), Some(&json!(7)));
    }

    #[test]
    fn external_uri_is_declined() {
        let doc = json!({ "a": 1 });
        assert_eq!(get(&doc, "/#/"), None);
    }

    #[test]
    fn array_append_and_create() {
        let mut doc = json!({ "array": ["b"] });
        assert_eq!(set(&mut doc, "#/array/-", json!("d")), Some(json!("d")));
        assert_eq!(get(&doc, "#/array/1"), Some(&json!("d")));

        let mut doc2 = json!({});
        set(&mut doc2, "#/newly/created/0", json!("x"));
        assert!(get(&doc2, "#/newly/created").unwrap().is_array());
    }
}
