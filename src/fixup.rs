//! JSON Schema repair passes.
//!
//! [`fix_up_schema`] walks a schema and applies two passes to every subschema:
//! extension promotion ([`fix_up_sub_schema_extensions`]) then keyword repair
//! ([`fix_up_sub_schema`]). The repairs turn Swagger 2.0 schema quirks into
//! valid OpenAPI 3.0 schema constructs.

use serde_json::{Map, Value};

use crate::error::{warn_or_error, S2OError};
use crate::options::Options;
use crate::schema_walker::walk_schema;

/// Repair `schema` and every subschema in place.
pub fn fix_up_schema(schema: &mut Value, options: &mut Options) -> Result<(), S2OError> {
    // The walker callback cannot itself return a Result, so the first error is
    // captured and surfaced after the walk completes.
    let mut error: Option<S2OError> = None;
    walk_schema(schema, &mut |sub, mut parent| {
        if error.is_some() {
            return;
        }
        fix_up_sub_schema_extensions(sub, parent.as_deref_mut());
        if let Err(e) = fix_up_sub_schema(sub, parent, options) {
            error = Some(e);
        }
    });
    match error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Promote `x-` schema extensions to their standard keywords.
pub fn fix_up_sub_schema_extensions(schema: &mut Value, _parent: Option<&mut Value>) {
    let Some(map) = schema.as_object_mut() else {
        return;
    };

    // x-required (array) merges into required.
    if let Some(Value::Array(extra)) = map.get("x-required").cloned() {
        let mut required = match map.remove("required") {
            Some(Value::Array(a)) => a,
            _ => Vec::new(),
        };
        required.extend(extra);
        map.insert("required".to_string(), Value::Array(required));
        map.remove("x-required");
    }

    rename(map, "x-anyOf", "anyOf");
    rename(map, "x-oneOf", "oneOf");
    rename(map, "x-not", "not");

    if let Some(Value::Bool(b)) = map.get("x-nullable").cloned() {
        map.insert("nullable".to_string(), Value::Bool(b));
        map.remove("x-nullable");
    }

    // x-discriminator object with a string propertyName becomes discriminator,
    // rewriting any mapping targets from definitions to schemas.
    let promote = matches!(
        map.get("x-discriminator"),
        Some(Value::Object(d)) if matches!(d.get("propertyName"), Some(Value::String(_)))
    );
    if promote {
        let mut disc = map.remove("x-discriminator").unwrap();
        if let Some(Value::Object(mapping)) = disc.get_mut("mapping") {
            for value in mapping.values_mut() {
                if let Value::String(s) = value {
                    if let Some(rest) = s.strip_prefix("#/definitions/") {
                        *s = format!("#/components/schemas/{rest}");
                    }
                }
            }
        }
        map.insert("discriminator".to_string(), disc);
    }
}

/// Repair JSON Schema keywords that differ between Swagger 2.0 and OpenAPI 3.0.
pub fn fix_up_sub_schema(
    schema: &mut Value,
    mut parent: Option<&mut Value>,
    options: &mut Options,
) -> Result<(), S2OError> {
    if truthy(schema.get("nullable")) {
        options.patches += 1;
    }

    // discriminator string becomes an object.
    if let Some(Value::String(name)) = schema.get("discriminator").cloned() {
        let mut d = Map::new();
        d.insert("propertyName".to_string(), Value::String(name));
        obj(schema).insert("discriminator".to_string(), Value::Object(d));
    }

    // items array collapses to a single schema or an anyOf.
    if let Some(Value::Array(items)) = schema.get("items").cloned() {
        let replacement = match items.len() {
            0 => Value::Object(Map::new()),
            1 => items.into_iter().next().unwrap(),
            _ => {
                let mut m = Map::new();
                m.insert("anyOf".to_string(), Value::Array(items));
                Value::Object(m)
            }
        };
        obj(schema).insert("items".to_string(), replacement);
    }

    // type as an array is only handled under patch.
    if matches!(schema.get("type"), Some(Value::Array(_))) {
        if options.patch {
            fix_type_array(schema, options)?;
        } else {
            return Err(S2OError::new(
                "(Patchable) schema type must not be an array",
            ));
        }
    }

    // type "null" becomes nullable.
    if schema.get("type").and_then(Value::as_str) == Some("null") {
        obj(schema).remove("type");
        obj(schema).insert("nullable".to_string(), Value::Bool(true));
    }

    // array without items gets an empty items schema.
    if schema.get("type").and_then(Value::as_str) == Some("array") && schema.get("items").is_none()
    {
        obj(schema).insert("items".to_string(), Value::Object(Map::new()));
    }

    // file type maps to a binary string.
    if schema.get("type").and_then(Value::as_str) == Some("file") {
        obj(schema).insert("type".to_string(), Value::String("string".to_string()));
        obj(schema).insert("format".to_string(), Value::String("binary".to_string()));
    }

    // boolean required moves the schema name onto the parent's required list.
    if let Some(Value::Bool(required)) = schema.get("required").cloned() {
        if required {
            if let Some(Value::String(name)) = schema.get("name").cloned() {
                if let Some(parent) = parent.as_mut() {
                    if let Some(pmap) = parent.as_object_mut() {
                        let list = pmap
                            .entry("required")
                            .or_insert_with(|| Value::Array(Vec::new()));
                        if let Value::Array(arr) = list {
                            arr.push(Value::String(name));
                        }
                    }
                }
            }
        }
        obj(schema).remove("required");
    }

    // empty xml namespace string is dropped.
    let empty_xml_ns = schema
        .get("xml")
        .and_then(|x| x.get("namespace"))
        .and_then(Value::as_str)
        == Some("");
    if empty_xml_ns {
        if let Some(Value::Object(xml)) = schema.get_mut("xml") {
            xml.remove("namespace");
        }
    }

    // allowEmptyValue is not valid on a schema.
    if schema.get("allowEmptyValue").is_some() {
        options.patches += 1;
        obj(schema).remove("allowEmptyValue");
    }

    Ok(())
}

/// Convert a `type` array into a `oneOf`, matching the patch path.
fn fix_type_array(schema: &mut Value, options: &mut Options) -> Result<(), S2OError> {
    options.patches += 1;
    let types = match schema.get("type") {
        Some(Value::Array(t)) => t.clone(),
        _ => return Ok(()),
    };

    if types.is_empty() {
        obj(schema).remove("type");
        return Ok(());
    }

    let mut one_of: Vec<Value> = match schema.get("oneOf") {
        Some(Value::Array(a)) => a.clone(),
        _ => Vec::new(),
    };

    for ty in &types {
        if ty.as_str() == Some("null") {
            obj(schema).insert("nullable".to_string(), Value::Bool(true));
        } else {
            let mut new_schema = Map::new();
            new_schema.insert("type".to_string(), ty.clone());
            // Array properties such as items and minItems stay on the parent
            // schema. They are not copied onto each split oneOf branch.
            if new_schema.contains_key("type") {
                one_of.push(Value::Object(new_schema));
            }
        }
    }

    obj(schema).remove("type");

    if one_of.is_empty() {
        obj(schema).remove("oneOf");
    } else if one_of.len() < 2 {
        let first = &one_of[0];
        if let Some(ty) = first.get("type").cloned() {
            obj(schema).insert("type".to_string(), ty);
        }
        if first.as_object().map(Map::len).unwrap_or(0) > 1 {
            warn_or_error("Lost properties from oneOf", schema, options)?;
        }
        obj(schema).remove("oneOf");
    } else {
        obj(schema).insert("oneOf".to_string(), Value::Array(one_of));
    }

    // The "do not else this" follow-up: a single-element type array collapses.
    if let Some(Value::Array(t)) = schema.get("type") {
        if t.len() == 1 {
            let only = t[0].clone();
            obj(schema).insert("type".to_string(), only);
        }
    }

    Ok(())
}

/// Rename `from` to `to`, dropping `from`.
fn rename(map: &mut Map<String, Value>, from: &str, to: &str) {
    if let Some(v) = map.remove(from) {
        map.insert(to.to_string(), v);
    }
}

/// Borrow the value as an object map, inserting an empty map first if needed.
fn obj(schema: &mut Value) -> &mut Map<String, Value> {
    if !schema.is_object() {
        *schema = Value::Object(Map::new());
    }
    schema.as_object_mut().unwrap()
}

/// JavaScript truthiness for an optional value.
fn truthy(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::Null) | None => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Some(_) => true,
    }
}
