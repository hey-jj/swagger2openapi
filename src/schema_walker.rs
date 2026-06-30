//! Schema and subschema traversal.
//!
//! [`walk_schema`] visits a schema and every subschema, calling the callback
//! with each. A subschema that holds a `$ref` short-circuits: the callback runs
//! on a throwaway `{ "$ref": ... }` copy and the real subschema keeps its other
//! members untouched. Child order follows `items`, `additionalItems`,
//! `additionalProperties`, `properties`, `patternProperties`, `allOf`, `anyOf`,
//! `oneOf`, then `not`.

use serde_json::{Map, Value};

/// Walk `schema` and its subschemas, applying `callback` to each.
///
/// The callback receives the schema being visited and its parent. The parent is
/// `None` at the root. Both are mutable so the callback can repair them.
pub fn walk_schema<F>(schema: &mut Value, callback: &mut F)
where
    F: FnMut(&mut Value, Option<&mut Value>),
{
    walk(schema, None, callback);
}

/// Recursive worker. `parent` is the schema one level up, when present.
fn walk<F>(schema: &mut Value, parent: Option<&mut Value>, callback: &mut F)
where
    F: FnMut(&mut Value, Option<&mut Value>),
{
    if !schema.is_object() && !schema.is_array() {
        return;
    }

    // A $ref short-circuits: visit a throwaway copy, ignore other members.
    if let Some(reference) = schema.get("$ref").filter(|v| v.is_string()).cloned() {
        let mut temp = Value::Object({
            let mut m = Map::new();
            m.insert("$ref".to_string(), reference);
            m
        });
        callback(&mut temp, parent);
        return;
    }

    callback(schema, parent);

    // Visit children in the fixed order. Each child is detached so the parent
    // can be handed to the callback by mutable reference, then written back.
    visit_named(schema, "items", callback);
    visit_object_only(schema, "additionalItems", callback);
    visit_object_only(schema, "additionalProperties", callback);
    visit_map(schema, "properties", callback);
    visit_map(schema, "patternProperties", callback);
    visit_array(schema, "allOf", callback);
    visit_array(schema, "anyOf", callback);
    visit_array(schema, "oneOf", callback);
    visit_named(schema, "not", callback);
}

/// Walk a single named child schema when present.
fn visit_named<F>(schema: &mut Value, key: &str, callback: &mut F)
where
    F: FnMut(&mut Value, Option<&mut Value>),
{
    let Some(mut child) = take(schema, key) else {
        return;
    };
    walk(&mut child, Some(schema), callback);
    put(schema, key, child);
}

/// Walk a named child only when it is an object or array, matching the
/// `typeof === 'object'` guard for `additionalItems` and `additionalProperties`.
fn visit_object_only<F>(schema: &mut Value, key: &str, callback: &mut F)
where
    F: FnMut(&mut Value, Option<&mut Value>),
{
    let truthy_object = schema
        .get(key)
        .map(|v| (v.is_object() || v.is_array()) && !is_falsy(v))
        .unwrap_or(false);
    if !truthy_object {
        return;
    }
    visit_named(schema, key, callback);
}

/// Walk every value of a child map (`properties`, `patternProperties`).
fn visit_map<F>(schema: &mut Value, key: &str, callback: &mut F)
where
    F: FnMut(&mut Value, Option<&mut Value>),
{
    let Some(mut child) = take(schema, key) else {
        return;
    };
    if let Value::Object(map) = &mut child {
        let names: Vec<String> = map.keys().cloned().collect();
        for name in names {
            if let Some(mut sub) = map.remove(&name) {
                walk(&mut sub, Some(schema), callback);
                map.insert(name, sub);
            }
        }
    }
    put(schema, key, child);
}

/// Walk every element of a child array (`allOf`, `anyOf`, `oneOf`).
fn visit_array<F>(schema: &mut Value, key: &str, callback: &mut F)
where
    F: FnMut(&mut Value, Option<&mut Value>),
{
    let Some(mut child) = take(schema, key) else {
        return;
    };
    if let Value::Array(arr) = &mut child {
        for sub in arr.iter_mut() {
            walk(sub, Some(schema), callback);
        }
    }
    put(schema, key, child);
}

/// Detach `schema[key]` so the parent can be borrowed mutably.
fn take(schema: &mut Value, key: &str) -> Option<Value> {
    schema.as_object_mut().and_then(|m| m.remove(key))
}

/// Reattach `value` under `schema[key]`.
fn put(schema: &mut Value, key: &str, value: Value) {
    if let Some(map) = schema.as_object_mut() {
        map.insert(key.to_string(), value);
    }
}

/// Whether a value is JavaScript-falsy for the truthiness guards above.
fn is_falsy(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Bool(b) => !b,
        _ => false,
    }
}
