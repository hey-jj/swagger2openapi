//! Order-preserving depth-first traversal with path state.
//!
//! [`recurse`] visits every own property of a value, calling the callback with
//! the container, the current key, and a [`RecurseState`]. The callback may
//! mutate the container in place: change `container[key]`, replace the container
//! itself through `*container`, or delete a key. After the callback runs, the
//! traversal descends into `container[key]` when it is still an object or array.
//!
//! [`is_ref`] reports whether a key names a string `$ref`.

use serde_json::Value;

use crate::jptr::jpescape;

/// Per-visit state passed to the recurse callback.
pub struct RecurseState {
    /// JSON-pointer-ish path to the current key, built with `#/a/b`.
    pub path: String,
}

/// Visit every property of `object` depth first.
///
/// `parent_path` is the path of the container. Pass `"#"` to start at the
/// document root.
pub fn recurse<F>(object: &mut Value, parent_path: &str, callback: &mut F)
where
    F: FnMut(&mut Value, &str, &RecurseState),
{
    let keys: Vec<String> = match object {
        Value::Object(map) => map.keys().cloned().collect(),
        Value::Array(arr) => (0..arr.len()).map(|i| i.to_string()).collect(),
        _ => return,
    };

    for key in keys {
        // The key may have been deleted by an earlier callback in this loop.
        if !contains_key(object, &key) {
            continue;
        }
        let path = format!("{}/{}", parent_path, encode_uri_component(&jpescape(&key)));
        let state = RecurseState { path: path.clone() };
        callback(object, &key, &state);

        // Re-read after the callback, which may have replaced or removed the
        // value or even the container itself.
        if let Some(child) = get_child_mut(object, &key) {
            if child.is_object() || child.is_array() {
                recurse(child, &path, callback);
            }
        }
    }
}

/// Whether `object` still holds `key`.
fn contains_key(object: &Value, key: &str) -> bool {
    match object {
        Value::Object(map) => map.contains_key(key),
        Value::Array(arr) => key.parse::<usize>().map(|i| i < arr.len()).unwrap_or(false),
        _ => false,
    }
}

/// Mutable access to `object[key]` for either maps or arrays.
fn get_child_mut<'a>(object: &'a mut Value, key: &str) -> Option<&'a mut Value> {
    match object {
        Value::Object(map) => map.get_mut(key),
        Value::Array(arr) => key.parse::<usize>().ok().and_then(move |i| arr.get_mut(i)),
        _ => None,
    }
}

/// Minimal `encodeURIComponent` for path building.
///
/// Encodes the bytes that `encodeURIComponent` escapes, leaving the unreserved
/// set and the few extra marks it keeps.
fn encode_uri_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        let keep = byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
            );
        if keep {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

/// Whether `key` is `$ref` and `obj[key]` is a string.
pub fn is_ref(obj: &Value, key: &str) -> bool {
    key == "$ref"
        && obj
            .as_object()
            .and_then(|m| m.get(key))
            .map(Value::is_string)
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn visits_in_order_with_paths() {
        let mut input = json!({
            "container": {
                "child": { "value": true, "string": "1234" },
                "child2": { "value": false, "{id}": { "test": "abc" } }
            }
        });
        let mut seen: Vec<(String, String)> = Vec::new();
        recurse(&mut input, "#", &mut |_obj, key, state| {
            seen.push((key.to_string(), state.path.clone()));
        });
        assert_eq!(seen.len(), 8);
        assert_eq!(seen[0], ("container".into(), "#/container".into()));
        // The path includes the current key. The reference test object aliases
        // a single mutated state, so its stored paths reflect the restored
        // parent path. The value here is the path at callback time.
        assert_eq!(
            seen[7],
            ("test".into(), "#/container/child2/%7Bid%7D/test".into())
        );
    }

    #[test]
    fn does_not_traverse_scalars() {
        let mut calls = 0;
        for mut v in [json!("hello"), json!(true), json!(1), json!(null)] {
            recurse(&mut v, "#", &mut |_, _, _| calls += 1);
        }
        assert_eq!(calls, 0);
    }

    #[test]
    fn traverses_arrays() {
        let mut calls = 0;
        let mut v = json!([0, 1, 2]);
        recurse(&mut v, "#", &mut |_, _, _| calls += 1);
        assert_eq!(calls, 3);
    }

    #[test]
    fn callback_can_delete() {
        let mut v = json!({ "a": 1, "b": 2 });
        recurse(&mut v, "#", &mut |obj, key, _| {
            if key == "a" {
                obj.as_object_mut().unwrap().remove("a");
            }
        });
        assert_eq!(v, json!({ "b": 2 }));
    }

    #[test]
    fn is_ref_detects_string_ref() {
        assert!(is_ref(&json!({ "$ref": "#/" }), "$ref"));
        assert!(!is_ref(&json!({ "$ref": true }), "$ref"));
        assert!(!is_ref(&json!({ "x": "y" }), "$ref"));
    }
}
