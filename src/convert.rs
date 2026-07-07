//! The conversion orchestration and the process helpers.
//!
//! [`convert_obj`] builds the OpenAPI 3.0 skeleton from a Swagger 2.0 document,
//! relocates top-level containers under `components`, derives `servers`, and
//! then runs [`main`], which rewrites `$ref`s, converts parameters into request
//! bodies, fixes schemas, and prunes empty buckets.

use serde_json::{Map, Value};

use crate::common::{
    self, decode_uri_component as decode_uri, encode_uri_component, hash, sanitise, sanitise_all,
    to_camel_case, truthy, ARRAY_PROPERTIES, HTTP_METHODS, PARAMETER_TYPE_PROPERTIES,
};
use crate::error::{warn_or_error, S2OError};
use crate::fixup::fix_up_schema;
use crate::jptr::{self, jpescape};
use crate::options::Options;
use crate::recurse::{is_ref, recurse};
use crate::resolver;
use crate::TARGET_VERSION;

/// Provenance version recorded in `x-origin` entries.
const OUR_VERSION: &str = "7.0.8";

// --- small Value helpers -------------------------------------------------

/// Empty JSON object.
fn empty_object() -> Value {
    Value::Object(Map::new())
}

/// Borrow `v` as an object map, replacing a non-object with an empty one.
fn as_object_mut(v: &mut Value) -> &mut Map<String, Value> {
    if !v.is_object() {
        *v = empty_object();
    }
    v.as_object_mut().unwrap()
}

/// Read a nested string value.
fn get_str<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

// --- componentNames bookkeeping -----------------------------------------

/// Maps original schema names to their sanitised, deduplicated names.
#[derive(Default)]
struct ComponentNames {
    schemas: Map<String, Value>,
}

// --- request body cache --------------------------------------------------

/// One cached request body and the document paths that reference it.
struct RbEntry {
    name: String,
    body: Value,
    refs: Vec<String>,
}

/// One cache entry position inside a hash bucket.
struct RbKey {
    hash: i32,
    index: usize,
}

/// Cache indexed by the 32-bit hash, then matched by request body content.
#[derive(Default)]
struct RbCache {
    order: Vec<RbKey>,
    entries: std::collections::HashMap<i32, Vec<RbEntry>>,
}

impl RbCache {
    fn get_or_insert(
        &mut self,
        hash: i32,
        body: &Value,
        make: impl FnOnce() -> RbEntry,
    ) -> &mut RbEntry {
        let bucket = self.entries.entry(hash).or_default();
        if let Some(index) = bucket.iter().position(|entry| entry.body == *body) {
            return bucket.get_mut(index).unwrap();
        }

        let index = bucket.len();
        self.order.push(RbKey { hash, index });
        bucket.push(make());
        bucket.last_mut().unwrap()
    }
}

// --- security ------------------------------------------------------------

/// Rename security requirement keys to their sanitised form.
fn process_security(security: &mut Value) {
    let Some(arr) = security.as_array_mut() else {
        return;
    };
    for entry in arr {
        let Some(map) = entry.as_object_mut() else {
            continue;
        };
        let keys: Vec<String> = map.keys().cloned().collect();
        for k in keys {
            let sname = sanitise(&k);
            if k != sname {
                if let Some(v) = map.remove(&k) {
                    map.insert(sname, v);
                }
            }
        }
    }
}

/// Convert a single security scheme from 2.0 to 3.0 shape.
fn process_security_scheme(scheme: &mut Value, options: &mut Options) -> Result<(), S2OError> {
    if get_str(scheme, "type") == Some("basic") {
        let m = as_object_mut(scheme);
        m.insert("type".into(), Value::String("http".into()));
        m.insert("scheme".into(), Value::String("basic".into()));
    }
    if get_str(scheme, "type") == Some("oauth2") {
        let mut flow = Map::new();
        let flow_name = match get_str(scheme, "flow") {
            Some("application") => "clientCredentials".to_string(),
            Some("accessCode") => "authorizationCode".to_string(),
            Some(other) => other.to_string(),
            None => "undefined".to_string(),
        };
        if let Some(url) = get_str(scheme, "authorizationUrl") {
            flow.insert("authorizationUrl".into(), Value::String(trim_url(url)));
        }
        if let Some(url) = get_str(scheme, "tokenUrl") {
            flow.insert("tokenUrl".into(), Value::String(trim_url(url)));
        }
        let scopes = scheme.get("scopes").cloned().unwrap_or_else(empty_object);
        flow.insert("scopes".into(), scopes);

        let mut flows = Map::new();
        flows.insert(flow_name, Value::Object(flow));
        let m = as_object_mut(scheme);
        m.insert("flows".into(), Value::Object(flows));
        m.remove("flow");
        m.remove("authorizationUrl");
        m.remove("tokenUrl");
        m.remove("scopes");

        if scheme.get("name").is_some() {
            if options.patch {
                options.patches += 1;
                as_object_mut(scheme).remove("name");
            } else {
                return Err(S2OError::new(
                    "(Patchable) oauth2 securitySchemes should not have name property",
                ));
            }
        }
    }
    Ok(())
}

/// Strip the query and trailing whitespace from an OAuth2 URL, default `/`.
fn trim_url(url: &str) -> String {
    let head = url.split('?').next().unwrap_or("").trim();
    if head.is_empty() {
        "/".to_string()
    } else {
        head.to_string()
    }
}

// --- headers -------------------------------------------------------------

/// Convert a 2.0 response header to 3.0 shape.
fn process_header(header: &mut Value, options: &mut Options) -> Result<(), S2OError> {
    if header.get("$ref").is_some() {
        if let Some(s) = get_str(header, "$ref") {
            let new = s.replace("#/responses/", "#/components/responses/");
            as_object_mut(header).insert("$ref".into(), Value::String(new));
        }
        return Ok(());
    }

    let header_type = get_str(header, "type").map(str::to_string);
    if header_type.is_some() && header.get("schema").is_none() {
        as_object_mut(header).insert("schema".into(), empty_object());
    }
    if let Some(t) = &header_type {
        as_object_mut(header)
            .entry("schema")
            .or_insert_with(empty_object);
        if let Some(schema) = header.get_mut("schema") {
            as_object_mut(schema).insert("type".into(), Value::String(t.clone()));
        }
    }

    let items_type = header
        .get("items")
        .and_then(|i| get_str(i, "type"))
        .map(str::to_string);
    if header.get("items").is_some() && items_type.as_deref() != Some("array") {
        let header_cf = get_str(header, "collectionFormat").map(str::to_string);
        let items_cf = header
            .get("items")
            .and_then(|i| get_str(i, "collectionFormat"))
            .map(str::to_string);
        if items_cf != header_cf {
            warn_or_error(
                "Nested collectionFormats are not supported",
                header,
                options,
            )?;
        }
        if let Some(items) = header.get_mut("items") {
            as_object_mut(items).remove("collectionFormat");
        }
    }

    if header_type.as_deref() == Some("array") {
        let cf = get_str(header, "collectionFormat").map(str::to_string);
        match cf.as_deref() {
            Some("ssv") => warn_or_error(
                "collectionFormat:ssv is no longer supported for headers",
                header,
                options,
            )?,
            Some("pipes") => warn_or_error(
                "collectionFormat:pipes is no longer supported for headers",
                header,
                options,
            )?,
            Some("multi") => {
                as_object_mut(header).insert("explode".into(), Value::Bool(true));
            }
            Some("tsv") => {
                warn_or_error(
                    "collectionFormat:tsv is no longer supported",
                    header,
                    options,
                )?;
                as_object_mut(header)
                    .insert("x-collectionFormat".into(), Value::String("tsv".into()));
            }
            _ => {
                as_object_mut(header).insert("style".into(), Value::String("simple".into()));
            }
        }
        as_object_mut(header).remove("collectionFormat");
    } else if header.get("collectionFormat").is_some() {
        if options.patch {
            options.patches += 1;
            as_object_mut(header).remove("collectionFormat");
        } else {
            return Err(S2OError::new(
                "(Patchable) collectionFormat is only applicable to header.type array",
            ));
        }
    }

    as_object_mut(header).remove("type");
    move_props_to_schema(header, PARAMETER_TYPE_PROPERTIES);
    move_props_to_schema(header, ARRAY_PROPERTIES);
    Ok(())
}

/// Move each listed property from `container` onto `container.schema`.
fn move_props_to_schema(container: &mut Value, props: &[&str]) {
    for prop in props {
        let value = container.as_object().and_then(|m| m.get(*prop)).cloned();
        if let Some(value) = value {
            as_object_mut(container)
                .entry("schema")
                .or_insert_with(empty_object);
            if let Some(schema) = container.get_mut("schema") {
                as_object_mut(schema).insert((*prop).to_string(), value);
            }
            as_object_mut(container).remove(*prop);
        }
    }
}

/// Rewrite a parameter `$ref` from 2.0 to 3.0 locations.
fn fix_param_ref(param: &mut Value, options: &mut Options) -> Result<(), S2OError> {
    let Some(ref_str) = get_str(param, "$ref").map(str::to_string) else {
        return Ok(());
    };
    if let Some(idx) = ref_str.find("#/parameters/") {
        let prefix = &ref_str[..idx];
        let rest = &ref_str[idx + "#/parameters/".len()..];
        let new = format!(
            "{prefix}#/components/parameters/{}",
            sanitise_ref_path(rest)
        );
        as_object_mut(param).insert("$ref".into(), Value::String(new));
    }
    if ref_str.contains("#/definitions/") {
        warn_or_error("Definition used as parameter", param, options)?;
    }
    Ok(())
}

/// Decode the first pointer segment before it becomes a component key.
fn sanitise_ref_path(rest: &str) -> String {
    let mut segments = rest.split('/');
    let first = segments.next().unwrap_or("");
    let first = sanitise(&decode_uri(first));
    let tail: Vec<&str> = segments.collect();
    if tail.is_empty() {
        first
    } else {
        format!("{first}/{}", tail.join("/"))
    }
}

// --- request body attachment --------------------------------------------

/// Copy `x-*` extensions, excluding `x-s2o*`, from `src` to `tgt`.
fn copy_extensions(src: &Value, tgt: &mut Value) {
    let Some(src_map) = src.as_object() else {
        return;
    };
    let extras: Vec<(String, Value)> = src_map
        .iter()
        .filter(|(k, _)| k.starts_with("x-") && !k.starts_with("x-s2o"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let tgt_map = as_object_mut(tgt);
    for (k, v) in extras {
        tgt_map.insert(k, v);
    }
}

/// Rebuild an operation so a fresh `requestBody` sits after `parameters`.
fn attach_request_body(op: &Value, options: &Options) -> Value {
    let mut new_op = Map::new();
    if let Some(map) = op.as_object() {
        for (key, value) in map {
            new_op.insert(key.clone(), value.clone());
            if key == "parameters" {
                new_op.insert("requestBody".into(), empty_object());
                if !options.rbname.is_empty() {
                    new_op.insert(options.rbname.clone(), Value::String(String::new()));
                }
            }
        }
    }
    new_op.insert("requestBody".into(), empty_object());
    Value::Object(new_op)
}

/// Compute the effective consumes list for a parameter.
///
/// Prefers the operation's `consumes`, falls back to the document's, and keeps
/// only the first occurrence of each media type.
fn effective_consumes(op: Option<&Value>, openapi: &Value) -> Vec<String> {
    let from_op = op.and_then(|o| o.get("consumes")).and_then(Value::as_array);
    let from_doc = openapi.get("consumes").and_then(Value::as_array);
    let list = from_op.or(from_doc);
    let strings: Vec<String> = list
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    common::unique_only(&strings)
}

/// Convert one parameter, possibly producing a request body on `op`.
///
/// `consumes` is the precomputed media-type list. `openapi` is read only, used
/// to resolve internal parameter `$ref`s. Returns nothing; mutations land on
/// `param` and `op`.
fn process_parameter(
    param: &mut Value,
    mut op: Option<&mut Value>,
    index: &str,
    openapi: &Value,
    consumes: &[String],
    options: &mut Options,
) -> Result<(), S2OError> {
    let mut consumes: Vec<String> = consumes.to_vec();
    let mut result = empty_object();
    let mut singular_request_body = true;
    let mut original_type: Option<String> = None;

    // operation.consumes must be an array.
    if let Some(o) = op.as_deref_mut() {
        if matches!(o.get("consumes"), Some(Value::String(_))) {
            if options.patch {
                options.patches += 1;
                let s = get_str(o, "consumes").unwrap().to_string();
                as_object_mut(o).insert("consumes".into(), Value::Array(vec![Value::String(s)]));
                consumes = effective_consumes(Some(o), openapi);
            } else {
                return Err(S2OError::new(
                    "(Patchable) operation.consumes must be an array",
                ));
            }
        }
    }

    // Internal parameter $ref.
    if matches!(param.get("$ref"), Some(Value::String(_))) {
        fix_param_ref(param, options)?;
        let ref_str = get_str(param, "$ref").unwrap().to_string();
        let ptr = decode_uri(&ref_str.replace("#/components/parameters/", ""));
        let target = openapi
            .get("components")
            .and_then(|c| c.get("parameters"))
            .and_then(|p| p.get(&ptr));
        let target_gone = match target {
            None => true,
            Some(t) => truthy(t.get("x-s2o-delete")),
        };
        let mut rbody = false;
        if target_gone && ref_str.starts_with("#/") {
            as_object_mut(param).insert("x-s2o-delete".into(), Value::Bool(true));
            rbody = true;
        }
        if rbody {
            let new_param = jptr::get(openapi, &ref_str).cloned();
            match new_param {
                None if ref_str.starts_with("#/") => {
                    warn_or_error(
                        format!("Could not resolve reference {ref_str}"),
                        param,
                        options,
                    )?;
                }
                Some(np) => *param = np,
                None => {}
            }
        }
    }

    let is_real = param.get("name").is_some() || param.get("in").is_some();
    if is_real {
        process_real_parameter(param, &mut original_type, openapi, options)?;
    }

    let param_in = get_str(param, "in").map(str::to_string);
    let param_type = get_str(param, "type").map(str::to_string);

    if param_in.as_deref() == Some("formData") {
        singular_request_body = false;
        build_form_data_body(param, &consumes, original_type.as_deref(), &mut result);
    } else if param_type.as_deref() == Some("file") {
        build_file_body(param, &mut result);
    }
    if param_in.as_deref() == Some("body") {
        build_body_request_body(param, op.as_deref(), &consumes, options, &mut result)?;
        if let (Some(o), false, Some(name)) = (
            op.as_deref_mut(),
            options.rbname.is_empty(),
            get_str(param, "name").map(str::to_string),
        ) {
            as_object_mut(o).insert(options.rbname.clone(), Value::String(name));
        }
    }

    if result.as_object().map(|m| !m.is_empty()).unwrap_or(false) {
        as_object_mut(param).insert("x-s2o-delete".into(), Value::Bool(true));
        if let Some(o) = op.as_mut() {
            attach_result_to_op(o, result, singular_request_body, index, options)?;
        }
    }

    // Tidy a parameter that stayed in place.
    if !truthy(param.get("x-s2o-delete")) {
        as_object_mut(param).remove("type");
        for prop in PARAMETER_TYPE_PROPERTIES {
            as_object_mut(param).remove(*prop);
        }
        if get_str(param, "in") == Some("path")
            && param.get("required").and_then(Value::as_bool) != Some(true)
        {
            if options.patch {
                options.patches += 1;
                as_object_mut(param).insert("required".into(), Value::Bool(true));
            } else {
                let name = get_str(param, "name").unwrap_or("");
                return Err(S2OError::new(format!(
                    "(Patchable) path parameters must be required:true [{name} in {index}]"
                )));
            }
        }
    }

    Ok(())
}

/// Apply the real-parameter transforms: deprecation, example, type to schema,
/// collection format to style and explode.
fn process_real_parameter(
    param: &mut Value,
    original_type: &mut Option<String>,
    openapi: &Value,
    options: &mut Options,
) -> Result<(), S2OError> {
    if let Some(Value::Bool(b)) = param.get("x-deprecated").cloned() {
        as_object_mut(param).insert("deprecated".into(), Value::Bool(b));
        as_object_mut(param).remove("x-deprecated");
    }
    if let Some(ex) = param.get("x-example").cloned() {
        as_object_mut(param).insert("example".into(), ex);
        as_object_mut(param).remove("x-example");
    }

    let param_in = get_str(param, "in").map(str::to_string);
    if param_in.as_deref() != Some("body") && param.get("type").is_none() {
        if options.patch {
            options.patches += 1;
            as_object_mut(param).insert("type".into(), Value::String("string".into()));
        } else {
            return Err(S2OError::new(
                "(Patchable) parameter.type is mandatory for non-body parameters",
            ));
        }
    }

    // type as a $ref object.
    if let Some(ty) = param.get("type") {
        if let Some(ref_str) = ty.get("$ref").and_then(Value::as_str) {
            if let Some(resolved) = jptr::get(openapi, ref_str).cloned() {
                as_object_mut(param).insert("type".into(), resolved);
            }
        }
    }

    if get_str(param, "type") == Some("file") {
        as_object_mut(param).insert("x-s2o-originalType".into(), Value::String("file".into()));
        *original_type = Some("file".to_string());
    }

    if let Some(desc) = param.get("description") {
        if let Some(ref_str) = desc.get("$ref").and_then(Value::as_str) {
            if let Some(resolved) = jptr::get(openapi, ref_str).cloned() {
                as_object_mut(param).insert("description".into(), resolved);
            }
        }
    }
    if param.get("description") == Some(&Value::Null) {
        as_object_mut(param).remove("description");
    }

    convert_collection_format(param, options)?;
    convert_type_to_schema(param, options)?;

    if param.get("schema").is_some() {
        if let Some(schema) = param.get_mut("schema") {
            fix_up_schema(schema, options)?;
        }
    }

    if truthy(param.get("x-ms-skip-url-encoding")) && get_str(param, "in") == Some("query") {
        as_object_mut(param).insert("allowReserved".into(), Value::Bool(true));
        as_object_mut(param).remove("x-ms-skip-url-encoding");
    }
    Ok(())
}

/// Map `collectionFormat` to `style`/`explode`.
fn convert_collection_format(param: &mut Value, options: &mut Options) -> Result<(), S2OError> {
    let param_type = get_str(param, "type").map(str::to_string);
    let param_in = get_str(param, "in").map(str::to_string);
    let mut old_cf = get_str(param, "collectionFormat").map(str::to_string);
    if param_type.as_deref() == Some("array") && old_cf.is_none() {
        old_cf = Some("csv".to_string());
    }
    let Some(cf) = old_cf else {
        return Ok(());
    };

    if param_type.as_deref() != Some("array") {
        if options.patch {
            options.patches += 1;
            as_object_mut(param).remove("collectionFormat");
        } else {
            return Err(S2OError::new(
                "(Patchable) collectionFormat is only applicable to param.type array",
            ));
        }
    }

    let in_query = param_in.as_deref() == Some("query");
    let in_cookie = param_in.as_deref() == Some("cookie");
    let in_path = param_in.as_deref() == Some("path");
    let in_header = param_in.as_deref() == Some("header");

    match cf.as_str() {
        "csv" if in_query || in_cookie => {
            let m = as_object_mut(param);
            m.insert("style".into(), Value::String("form".into()));
            m.insert("explode".into(), Value::Bool(false));
        }
        "csv" if in_path || in_header => {
            as_object_mut(param).insert("style".into(), Value::String("simple".into()));
        }
        "ssv" => {
            if in_query {
                as_object_mut(param).insert("style".into(), Value::String("spaceDelimited".into()));
            } else {
                warn_or_error(
                    "collectionFormat:ssv is no longer supported except for in:query parameters",
                    param,
                    options,
                )?;
            }
        }
        "pipes" => {
            if in_query {
                as_object_mut(param).insert("style".into(), Value::String("pipeDelimited".into()));
            } else {
                warn_or_error(
                    "collectionFormat:pipes is no longer supported except for in:query parameters",
                    param,
                    options,
                )?;
            }
        }
        "multi" => {
            as_object_mut(param).insert("explode".into(), Value::Bool(true));
        }
        "tsv" => {
            warn_or_error(
                "collectionFormat:tsv is no longer supported",
                param,
                options,
            )?;
            as_object_mut(param).insert("x-collectionFormat".into(), Value::String("tsv".into()));
        }
        _ => {}
    }
    as_object_mut(param).remove("collectionFormat");
    Ok(())
}

/// Move a non-body, non-formData parameter's `type` and items onto a schema.
fn convert_type_to_schema(param: &mut Value, options: &mut Options) -> Result<(), S2OError> {
    let param_type = get_str(param, "type").map(str::to_string);
    let param_in = get_str(param, "in").map(str::to_string);
    let applies = param_type.is_some()
        && param_type.as_deref() != Some("body")
        && param_in.as_deref() != Some("formData");
    if !applies {
        return Ok(());
    }

    if param.get("items").is_some() && param.get("schema").is_some() {
        warn_or_error("parameter has array,items and schema", param, options)?;
        return Ok(());
    }

    if param.get("schema").is_some() {
        options.patches += 1;
    }
    if !param.get("schema").map(Value::is_object).unwrap_or(false) {
        as_object_mut(param).insert("schema".into(), empty_object());
    }
    let ty = param_type.unwrap();
    if let Some(schema) = param.get_mut("schema") {
        as_object_mut(schema).insert("type".into(), Value::String(ty));
    }

    let old_cf = get_str(param, "collectionFormat").map(str::to_string);
    if let Some(items) = param.get("items").cloned() {
        as_object_mut(param).remove("items");
        let mut items = items;
        strip_nested_collection_format(&mut items, old_cf.as_deref(), param, options)?;
        if let Some(schema) = param.get_mut("schema") {
            as_object_mut(schema).insert("items".into(), items);
        }
    }

    for prop in PARAMETER_TYPE_PROPERTIES {
        let v = param.as_object().and_then(|m| m.get(*prop)).cloned();
        if let Some(v) = v {
            if let Some(schema) = param.get_mut("schema") {
                as_object_mut(schema).insert((*prop).to_string(), v);
            }
        }
        as_object_mut(param).remove(*prop);
    }
    Ok(())
}

/// Recursively delete nested `collectionFormat`, warning on a conflict.
fn strip_nested_collection_format(
    node: &mut Value,
    old_cf: Option<&str>,
    warn_target: &mut Value,
    options: &mut Options,
) -> Result<(), S2OError> {
    let mut conflict = false;
    recurse(node, "#", &mut |obj, key, _| {
        if key == "collectionFormat" {
            if let Some(Value::String(v)) = obj.get(key) {
                if let Some(old) = old_cf {
                    if v != old {
                        conflict = true;
                    }
                }
            }
            if let Some(map) = obj.as_object_mut() {
                map.remove(key);
            }
        }
    });
    if conflict {
        warn_or_error(
            "Nested collectionFormats are not supported",
            warn_target,
            options,
        )?;
    }
    Ok(())
}

/// Build a request body from a `formData` parameter into `result`.
fn build_form_data_body(
    param: &mut Value,
    consumes: &[String],
    original_type: Option<&str>,
    result: &mut Value,
) {
    let content_type = if consumes.iter().any(|c| c == "multipart/form-data") {
        "multipart/form-data"
    } else {
        "application/x-www-form-urlencoded"
    };

    as_object_mut(result).insert("content".into(), empty_object());
    if let Some(content) = result.get_mut("content") {
        as_object_mut(content).insert(content_type.into(), empty_object());
    }

    if let Some(schema) = param.get("schema").cloned() {
        if let Some(ref_str) = schema.get("$ref").and_then(Value::as_str) {
            let name = decode_uri(&ref_str.replace("#/components/schemas/", ""));
            as_object_mut(result).insert("x-s2o-name".into(), Value::String(name));
        }
        if let Some(content) = result.get_mut("content") {
            if let Some(ct) = content.get_mut(content_type) {
                as_object_mut(ct).insert("schema".into(), schema);
            }
        }
        return;
    }

    // Synthesize an object schema with one property named after the param.
    let name = get_str(param, "name").unwrap_or("").to_string();
    let mut target = Map::new();
    if let Some(d) = param.get("description").cloned() {
        target.insert("description".into(), d);
    }
    if let Some(e) = param.get("example").cloned() {
        target.insert("example".into(), e);
    }
    if let Some(t) = param.get("type").cloned() {
        target.insert("type".into(), t);
    }
    for prop in PARAMETER_TYPE_PROPERTIES {
        if let Some(v) = param.get(*prop).cloned() {
            target.insert((*prop).to_string(), v);
        }
    }
    let mut required_added = false;
    if param.get("required").and_then(Value::as_bool) == Some(true) {
        required_added = true;
    }
    if let Some(d) = param.get("default").cloned() {
        target.insert("default".into(), d);
    }
    // The synthesized property schema never carries nested properties, so none
    // are copied here. allOf is carried through.
    if let Some(a) = param.get("allOf").cloned() {
        target.insert("allOf".into(), a);
    }
    if get_str(param, "type") == Some("array") {
        if let Some(items) = param.get("items").cloned() {
            let mut items = items;
            if let Some(map) = items.as_object_mut() {
                map.remove("collectionFormat");
            }
            target.insert("items".into(), items);
        }
    }
    if original_type == Some("file") || get_str(param, "x-s2o-originalType") == Some("file") {
        target.insert("type".into(), Value::String("string".into()));
        target.insert("format".into(), Value::String("binary".into()));
    }

    let mut target_value = Value::Object(target);
    copy_extensions(param, &mut target_value);

    // Assemble schema { type: object, properties: { name: target } }.
    let mut properties = Map::new();
    properties.insert(name.clone(), target_value);
    let mut schema = Map::new();
    schema.insert("type".into(), Value::String("object".into()));
    schema.insert("properties".into(), Value::Object(properties));
    if required_added {
        schema.insert("required".into(), Value::Array(vec![Value::String(name)]));
        as_object_mut(result).insert("required".into(), Value::Bool(true));
    }

    if let Some(content) = result.get_mut("content") {
        if let Some(ct) = content.get_mut(content_type) {
            as_object_mut(ct).insert("schema".into(), Value::Object(schema));
        }
    }
}

/// Build an octet-stream request body from a `file` typed parameter.
fn build_file_body(param: &Value, result: &mut Value) {
    if let Some(req) = param.get("required") {
        if truthy(Some(req)) {
            as_object_mut(result).insert("required".into(), req.clone());
        }
    }
    let mut schema = Map::new();
    schema.insert("type".into(), Value::String("string".into()));
    schema.insert("format".into(), Value::String("binary".into()));
    let mut ct = Map::new();
    ct.insert("schema".into(), Value::Object(schema));
    let mut content = Map::new();
    content.insert("application/octet-stream".into(), Value::Object(ct));
    as_object_mut(result).insert("content".into(), Value::Object(content));
    copy_extensions(param, result);
}

/// Build a request body from a `body` parameter into `result`.
fn build_body_request_body(
    param: &mut Value,
    op: Option<&Value>,
    consumes: &[String],
    options: &mut Options,
    result: &mut Value,
) -> Result<(), S2OError> {
    as_object_mut(result).insert("content".into(), empty_object());

    if let Some(name) = get_str(param, "name") {
        let op_id = op
            .and_then(|o| get_str(o, "operationId"))
            .map(sanitise_all)
            .unwrap_or_default();
        let derived = format!("{op_id}{}", to_camel_case(&format!("_{name}")));
        as_object_mut(result).insert("x-s2o-name".into(), Value::String(derived));
    }
    if let Some(d) = param.get("description").cloned() {
        as_object_mut(result).insert("description".into(), d);
    }
    if let Some(r) = param.get("required") {
        if truthy(Some(r)) {
            as_object_mut(result).insert("required".into(), r.clone());
        }
    }

    // x-s2o-name override from the schema $ref or array-of-$ref.
    if let Some(schema) = param.get("schema") {
        if let Some(ref_str) = schema.get("$ref").and_then(Value::as_str) {
            let name = decode_uri(&ref_str.replace("#/components/schemas/", ""));
            as_object_mut(result).insert("x-s2o-name".into(), Value::String(name));
        } else if get_str(schema, "type") == Some("array") {
            if let Some(items_ref) = schema
                .get("items")
                .and_then(|i| i.get("$ref"))
                .and_then(Value::as_str)
            {
                let name = format!(
                    "{}Array",
                    decode_uri(&items_ref.replace("#/components/schemas/", ""))
                );
                as_object_mut(result).insert("x-s2o-name".into(), Value::String(name));
            }
        }
    }

    let mut consumes = consumes.to_vec();
    if consumes.is_empty() {
        consumes.push("application/json".to_string());
    }

    let schema = param.get("schema").cloned().unwrap_or_else(empty_object);
    for mimetype in &consumes {
        let mut cloned_schema = schema.clone();
        fix_up_schema(&mut cloned_schema, options)?;
        let mut ct = Map::new();
        ct.insert("schema".into(), cloned_schema);
        if let Some(content) = result.get_mut("content") {
            as_object_mut(content).insert(mimetype.clone(), Value::Object(ct));
        }
    }

    copy_extensions(param, result);
    Ok(())
}

/// Attach a built request body `result` to `op`, merging form bodies.
fn attach_result_to_op(
    op: &mut Value,
    result: Value,
    singular_request_body: bool,
    index: &str,
    options: &mut Options,
) -> Result<(), S2OError> {
    if op.get("requestBody").is_some() && singular_request_body {
        if let Some(rb) = op.get_mut("requestBody") {
            as_object_mut(rb).insert("x-s2o-overloaded".into(), Value::Bool(true));
        }
        let op_id = get_str(op, "operationId").unwrap_or(index).to_string();
        warn_or_error(
            format!("Operation {op_id} has multiple requestBodies"),
            op,
            options,
        )?;
        return Ok(());
    }

    if op.get("requestBody").is_none() {
        *op = attach_request_body(op, options);
    }

    let multipart = "multipart/form-data";
    let urlencoded = "application/x-www-form-urlencoded";

    if has_form_properties(op, multipart) && result_has_form_properties(&result, multipart) {
        merge_form_properties(op, &result, multipart);
    } else if has_form_properties(op, urlencoded) && result_has_form_properties(&result, urlencoded)
    {
        merge_form_properties(op, &result, urlencoded);
    } else {
        // Object.assign(op.requestBody, result).
        let rb = op.get("requestBody").cloned().unwrap_or_else(empty_object);
        let mut merged = rb;
        if let Some(rmap) = result.as_object() {
            for (k, v) in rmap {
                as_object_mut(&mut merged).insert(k.clone(), v.clone());
            }
        }
        // Derive x-s2o-name when missing.
        if merged.get("x-s2o-name").is_none() {
            if let Some(ref_str) = merged
                .get("schema")
                .and_then(|s| s.get("$ref"))
                .and_then(Value::as_str)
            {
                let name = decode_uri(&ref_str.replace("#/components/schemas/", ""))
                    .split('/')
                    .collect::<Vec<_>>()
                    .join("");
                as_object_mut(&mut merged).insert("x-s2o-name".into(), Value::String(name));
            } else if let Some(op_id) = get_str(op, "operationId") {
                as_object_mut(&mut merged)
                    .insert("x-s2o-name".into(), Value::String(sanitise_all(op_id)));
            }
        }
        as_object_mut(op).insert("requestBody".into(), merged);
    }
    Ok(())
}

/// Whether `op.requestBody.content[ct].schema.properties` exists.
fn has_form_properties(op: &Value, ct: &str) -> bool {
    op.get("requestBody")
        .and_then(|rb| rb.get("content"))
        .and_then(|c| c.get(ct))
        .and_then(|m| m.get("schema"))
        .and_then(|s| s.get("properties"))
        .is_some()
}

/// Whether `result.content[ct].schema.properties` exists.
fn result_has_form_properties(result: &Value, ct: &str) -> bool {
    result
        .get("content")
        .and_then(|c| c.get(ct))
        .and_then(|m| m.get("schema"))
        .and_then(|s| s.get("properties"))
        .is_some()
}

/// Merge form properties and required arrays from `result` into `op`.
fn merge_form_properties(op: &mut Value, result: &Value, ct: &str) {
    let result_props = result
        .get("content")
        .and_then(|c| c.get(ct))
        .and_then(|m| m.get("schema"))
        .and_then(|s| s.get("properties"))
        .cloned();
    let result_required = result
        .get("content")
        .and_then(|c| c.get(ct))
        .and_then(|m| m.get("schema"))
        .and_then(|s| s.get("required"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let schema = op
        .get_mut("requestBody")
        .and_then(|rb| rb.get_mut("content"))
        .and_then(|c| c.get_mut(ct))
        .and_then(|m| m.get_mut("schema"));
    let Some(schema) = schema else {
        return;
    };

    if let (Some(Value::Object(existing)), Some(Value::Object(incoming))) =
        (schema.get_mut("properties"), result_props.as_ref())
    {
        for (k, v) in incoming {
            existing.insert(k.clone(), v.clone());
        }
    }

    let mut required = schema
        .get("required")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    required.extend(result_required);
    if required.is_empty() {
        as_object_mut(schema).remove("required");
    } else {
        as_object_mut(schema).insert("required".into(), Value::Array(required));
    }
}

// --- responses -----------------------------------------------------------

/// Convert a 2.0 response into 3.0 shape.
///
/// `op` is the owning operation, read to compute the media types for the
/// `content` map via [`compute_produces`].
fn process_response(
    response: &mut Value,
    op: Option<&mut Value>,
    openapi: &Value,
    options: &mut Options,
) -> Result<(), S2OError> {
    if response.is_null() {
        return Ok(());
    }

    if matches!(response.get("$ref"), Some(Value::String(_))) {
        let ref_str = get_str(response, "$ref").unwrap().to_string();
        if ref_str.contains("#/definitions/") {
            warn_or_error(
                format!("definition used as response: {ref_str}"),
                response,
                options,
            )?;
        } else if ref_str.starts_with("#/responses/") {
            let rest = decode_uri(&ref_str.replace("#/responses/", ""));
            let new = format!("#/components/responses/{}", sanitise(&rest));
            as_object_mut(response).insert("$ref".into(), Value::String(new));
        }
        return Ok(());
    }

    // description is mandatory.
    let desc = response.get("description");
    let missing = matches!(desc, None | Some(Value::Null))
        || (desc.and_then(Value::as_str) == Some("") && options.patch);
    if missing {
        if options.patch {
            if response.is_object() {
                options.patches += 1;
                as_object_mut(response).insert("description".into(), Value::String(String::new()));
            }
        } else {
            return Err(S2OError::new(
                "(Patchable) response.description is mandatory",
            ));
        }
    }

    // schema becomes content.
    if response.get("schema").is_some() {
        if let Some(schema) = response.get_mut("schema") {
            fix_up_schema(schema, options)?;
        }
        if let Some(ref_str) = response
            .get("schema")
            .and_then(|s| s.get("$ref"))
            .and_then(Value::as_str)
        {
            if ref_str.starts_with("#/responses/") {
                let rest = decode_uri(&ref_str.replace("#/responses/", ""));
                let new = format!("#/components/responses/{}", sanitise(&rest));
                if let Some(schema) = response.get_mut("schema") {
                    as_object_mut(schema).insert("$ref".into(), Value::String(new));
                }
            }
        }

        // produces wrapping.
        let mut produces = compute_produces(response_op(&op), openapi, options)?;
        if produces.is_empty() {
            produces.push("*/*".to_string());
        }

        let schema = response.get("schema").cloned().unwrap_or_else(empty_object);
        as_object_mut(response).insert("content".into(), empty_object());
        for mimetype in &produces {
            let mut ct = Map::new();
            let mut ct_schema = schema.clone();
            // file type schema becomes binary string.
            if get_str(&ct_schema, "type") == Some("file") {
                ct_schema = {
                    let mut m = Map::new();
                    m.insert("type".into(), Value::String("string".into()));
                    m.insert("format".into(), Value::String("binary".into()));
                    Value::Object(m)
                };
            }
            ct.insert("schema".into(), ct_schema);

            // move a matching example into the content type.
            let example = response
                .get("examples")
                .and_then(|e| e.get(mimetype))
                .cloned();
            if let Some(example) = example {
                let mut ex = Map::new();
                ex.insert("value".into(), example);
                let mut examples = Map::new();
                examples.insert("response".into(), Value::Object(ex));
                ct.insert("examples".into(), Value::Object(examples));
                if let Some(exs) = response.get_mut("examples") {
                    if let Some(map) = exs.as_object_mut() {
                        map.remove(mimetype);
                    }
                }
            }

            if let Some(content) = response.get_mut("content") {
                as_object_mut(content).insert(mimetype.clone(), Value::Object(ct));
            }
        }
        as_object_mut(response).remove("schema");
    }

    // Examples for content types not listed in produces.
    let leftover: Vec<(String, Value)> = response
        .get("examples")
        .and_then(Value::as_object)
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();
    for (mimetype, value) in leftover {
        as_object_mut(response)
            .entry("content")
            .or_insert_with(empty_object);
        if let Some(content) = response.get_mut("content") {
            as_object_mut(content)
                .entry(mimetype.clone())
                .or_insert_with(empty_object);
            if let Some(ct) = content.get_mut(&mimetype) {
                let mut ex = Map::new();
                ex.insert("value".into(), value);
                let mut examples = Map::new();
                examples.insert("response".into(), Value::Object(ex));
                as_object_mut(ct).insert("examples".into(), Value::Object(examples));
            }
        }
    }
    as_object_mut(response).remove("examples");

    // headers.
    process_response_headers(response, options)?;
    Ok(())
}

/// Read-only view of an optional `op`.
fn response_op<'a>(op: &'a Option<&mut Value>) -> Option<&'a Value> {
    op.as_deref()
}

/// Compute the produces list, wrapping a string `op.produces` under patch.
fn compute_produces(
    op: Option<&Value>,
    openapi: &Value,
    options: &mut Options,
) -> Result<Vec<String>, S2OError> {
    if let Some(o) = op {
        if let Some(Value::String(s)) = o.get("produces") {
            if options.patch {
                options.patches += 1;
                return Ok(vec![s.clone()]);
            }
            return Err(S2OError::new(
                "(Patchable) operation.produces must be an array",
            ));
        }
    }
    let from_op = op.and_then(|o| o.get("produces")).and_then(Value::as_array);
    let from_doc = openapi.get("produces").and_then(Value::as_array);
    let list = from_op.or(from_doc);
    let strings: Vec<String> = list
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    Ok(common::unique_only(&strings))
}

/// Process the headers on a response, dropping `Status Code`.
fn process_response_headers(response: &mut Value, options: &mut Options) -> Result<(), S2OError> {
    let header_names: Vec<String> = response
        .get("headers")
        .and_then(Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    for h in header_names {
        if h.to_lowercase() == "status code" {
            if options.patch {
                options.patches += 1;
                if let Some(headers) = response.get_mut("headers") {
                    if let Some(map) = headers.as_object_mut() {
                        map.remove(&h);
                    }
                }
            } else {
                return Err(S2OError::new(
                    "(Patchable) \"Status Code\" is not a valid header",
                ));
            }
        } else if let Some(headers) = response.get_mut("headers") {
            if let Some(header) = headers.get_mut(&h) {
                process_header(header, options)?;
            }
        }
    }
    Ok(())
}

// --- $ref rewriting ------------------------------------------------------

/// One `$ref` site found during the collection pass.
struct RefSite {
    /// Path to the object that holds the `$ref`.
    container_path: String,
    /// Whether the path passes through a `/schema` segment.
    in_schema: bool,
}

/// Collect every `$ref` site in document order.
fn collect_ref_sites(openapi: &Value) -> Vec<RefSite> {
    let mut sites: Vec<RefSite> = Vec::new();
    let mut doc = openapi.clone();
    recurse(&mut doc, "#", &mut |obj, key, state| {
        if is_ref(obj, key) {
            sites.push(RefSite {
                container_path: parent_of(&state.path),
                in_schema: state.path.contains("/schema"),
            });
        }
        // x-ms-odata sites are handled in the same place.
        if key == "x-ms-odata" {
            if let Some(Value::String(s)) = obj.get(key) {
                if s.starts_with("#/") {
                    sites.push(RefSite {
                        container_path: parent_of(&state.path),
                        in_schema: false,
                    });
                }
            }
        }
    });
    sites
}

/// Strip the trailing `/segment` to address the container of a key.
fn parent_of(path: &str) -> String {
    match path.rfind('/') {
        Some(idx) if idx > 0 => path[..idx].to_string(),
        _ => "#".to_string(),
    }
}

/// Rewrite every `$ref` to its OpenAPI 3.0 location.
fn fixup_refs(
    openapi: &mut Value,
    component_names: &ComponentNames,
    options: &mut Options,
) -> Result<(), S2OError> {
    let sites = collect_ref_sites(openapi);
    let mut refmap: Map<String, Value> = Map::new();

    for site in sites {
        let Some(mut container) = jptr::get(openapi, &site.container_path).cloned() else {
            continue;
        };

        // x-ms-odata rewrite.
        if let Some(Value::String(s)) = container.get("x-ms-odata").cloned() {
            if s.starts_with("#/") {
                rewrite_odata(&mut container, &s, component_names, options)?;
                jptr::set(openapi, &site.container_path, container.clone());
            }
        }

        if !is_ref(&container, "$ref") {
            continue;
        }
        let ref_str = get_str(&container, "$ref").unwrap().to_string();

        rewrite_single_ref(
            openapi,
            &mut container,
            &ref_str,
            &site,
            component_names,
            &mut refmap,
            options,
        )?;

        // Sibling handling and write-back.
        finalize_ref_site(openapi, container, &site, options);
    }

    options.refmap = Value::Object(refmap.clone());
    dedupe_refs(openapi, &refmap);
    Ok(())
}

/// Rewrite the `$ref` string of a single container in place.
#[allow(clippy::too_many_arguments)]
fn rewrite_single_ref(
    openapi: &mut Value,
    container: &mut Value,
    ref_str: &str,
    site: &RefSite,
    component_names: &ComponentNames,
    refmap: &mut Map<String, Value>,
    options: &mut Options,
) -> Result<(), S2OError> {
    if ref_str.starts_with("#/components/") {
        // already converted
    } else if ref_str == "#/consumes" {
        let consumes = openapi.get("consumes").cloned().unwrap_or(Value::Null);
        as_object_mut(container).remove("$ref");
        // Replace the whole container with the consumes array.
        *container = consumes;
    } else if ref_str == "#/produces" {
        let produces = openapi.get("produces").cloned().unwrap_or(Value::Null);
        as_object_mut(container).remove("$ref");
        *container = produces;
    } else if let Some(rest) = ref_str.strip_prefix("#/definitions/") {
        let mut keys: Vec<String> = rest.split('/').map(str::to_string).collect();
        let ref0 = jptr::jpunescape(&keys[0]);
        match component_names.schemas.get(&decode_uri(&ref0)) {
            Some(Value::String(new_key)) => keys[0] = new_key.clone(),
            _ => warn_or_error(
                format!("Could not resolve reference {ref_str}"),
                container,
                options,
            )?,
        }
        let new = format!("#/components/schemas/{}", keys.join("/"));
        as_object_mut(container).insert("$ref".into(), Value::String(new));
    } else if let Some(rest) = ref_str.strip_prefix("#/parameters/") {
        let new = format!("#/components/parameters/{}", sanitise_ref_path(rest));
        as_object_mut(container).insert("$ref".into(), Value::String(new));
    } else if let Some(rest) = ref_str.strip_prefix("#/responses/") {
        let new = format!("#/components/responses/{}", sanitise_ref_path(rest));
        as_object_mut(container).insert("$ref".into(), Value::String(new));
    } else if ref_str.starts_with('#') {
        relocate_ref(openapi, container, ref_str, site, refmap, options)?;
    }
    Ok(())
}

/// The heuristic relocator for direct internal `$ref`s.
fn relocate_ref(
    openapi: &mut Value,
    container: &mut Value,
    ref_str: &str,
    _site: &RefSite,
    refmap: &mut Map<String, Value>,
    options: &mut Options,
) -> Result<(), S2OError> {
    let target = jptr::get(openapi, ref_str).cloned();
    let Some(mut target) = target else {
        warn_or_error(
            format!("direct $ref not found {ref_str}"),
            container,
            options,
        )?;
        return Ok(());
    };

    if let Some(existing) = refmap.get(ref_str).and_then(Value::as_str) {
        as_object_mut(container).insert("$ref".into(), Value::String(existing.to_string()));
        return Ok(());
    }

    // Infer the bucket type.
    let mut old_ref = ref_str.to_string();
    for seg in [
        "/properties/headers/",
        "/properties/responses/",
        "/properties/parameters/",
        "/properties/schemas/",
    ] {
        old_ref = old_ref.replace(seg, "");
    }
    let schema_index = old_ref.rfind("/schema").map(|i| i as isize).unwrap_or(-1);
    let after = |needle: &str| -> bool {
        old_ref
            .find(needle)
            .map(|i| i as isize > schema_index)
            .unwrap_or(false)
    };
    let type_name = if after("/headers/") {
        "headers"
    } else if after("/responses/") {
        "responses"
    } else if after("/example") {
        "examples"
    } else if after("/x-") {
        "extensions"
    } else if after("/parameters/") {
        "parameters"
    } else {
        "schemas"
    };

    if type_name == "schemas" {
        fix_up_schema(&mut target, options)?;
    }

    if type_name != "responses" && type_name != "extensions" {
        let mut prefix = type_name[..type_name.len() - 1].to_string();
        if prefix == "parameter" {
            if let Some(name) = get_str(&target, "name") {
                if name == sanitise(name) {
                    prefix = encode_uri_component(name);
                }
            }
        }

        let mut suffix: SuffixCounter = SuffixCounter::Num(1);
        if let Some(Value::String(miro)) = container.get("x-miro") {
            prefix = get_miro_component_name(miro);
            suffix = SuffixCounter::Empty;
        }

        while jptr::exists(
            openapi,
            &format!("#/components/{type_name}/{prefix}{}", suffix.as_str()),
        ) {
            suffix = suffix.next();
        }

        let new_ref = format!("#/components/{type_name}/{prefix}{}", suffix.as_str());
        let mut ref_suffix = "";
        if type_name == "examples" {
            let mut wrapped = Map::new();
            wrapped.insert("value".into(), target);
            target = Value::Object(wrapped);
            ref_suffix = "/value";
        }

        jptr::set(openapi, &new_ref, target);
        let full_ref = format!("{new_ref}{ref_suffix}");
        refmap.insert(ref_str.to_string(), Value::String(full_ref.clone()));
        as_object_mut(container).insert("$ref".into(), Value::String(full_ref));
    }
    Ok(())
}

/// Numeric or empty suffix counter matching the JavaScript `++` coercion.
enum SuffixCounter {
    Empty,
    Num(u64),
}

impl SuffixCounter {
    fn as_str(&self) -> String {
        match self {
            SuffixCounter::Empty => String::new(),
            SuffixCounter::Num(n) => n.to_string(),
        }
    }
    fn next(self) -> Self {
        match self {
            SuffixCounter::Empty => SuffixCounter::Num(2),
            SuffixCounter::Num(n) => SuffixCounter::Num(n + 1),
        }
    }
}

/// Resolve the component name from an `x-miro` provenance value.
fn get_miro_component_name(reference: &str) -> String {
    let name = if reference.contains('#') {
        reference
            .split('#')
            .nth(1)
            .unwrap_or("")
            .split('/')
            .next_back()
            .unwrap_or("")
            .to_string()
    } else {
        reference
            .split('/')
            .next_back()
            .unwrap_or("")
            .split('.')
            .next()
            .unwrap_or("")
            .to_string()
    };
    encode_uri_component(&sanitise(&name))
}

/// Apply sibling handling and write the container back to its path.
fn finalize_ref_site(openapi: &mut Value, mut container: Value, site: &RefSite, options: &Options) {
    // x-miro is always dropped after rewriting.
    if let Some(map) = container.as_object_mut() {
        map.remove("x-miro");
    }

    let has_siblings = container.as_object().map(|m| m.len() > 1).unwrap_or(false);
    if is_ref(&container, "$ref") && has_siblings {
        let tmp_ref = get_str(&container, "$ref").unwrap().to_string();
        use crate::options::RefSiblings;
        match options.ref_siblings {
            RefSiblings::Preserve => {}
            RefSiblings::AllOf if site.in_schema => {
                as_object_mut(&mut container).remove("$ref");
                let mut ref_only = Map::new();
                ref_only.insert("$ref".into(), Value::String(tmp_ref));
                let all_of = vec![Value::Object(ref_only), container.clone()];
                let mut wrapper = Map::new();
                wrapper.insert("allOf".into(), Value::Array(all_of));
                container = Value::Object(wrapper);
            }
            _ => {
                let mut ref_only = Map::new();
                ref_only.insert("$ref".into(), Value::String(tmp_ref));
                container = Value::Object(ref_only);
            }
        }
    }

    jptr::set(openapi, &site.container_path, container);
}

/// Rewrite an `x-ms-odata` pointer to the schemas bucket.
fn rewrite_odata(
    container: &mut Value,
    value: &str,
    component_names: &ComponentNames,
    options: &mut Options,
) -> Result<(), S2OError> {
    let stripped = value
        .replace("#/definitions/", "")
        .replace("#/components/schemas/", "");
    let mut keys: Vec<String> = stripped.split('/').map(str::to_string).collect();
    match component_names.schemas.get(&decode_uri(&keys[0])) {
        Some(Value::String(new_key)) => keys[0] = new_key.clone(),
        _ => warn_or_error(
            format!("Could not resolve reference {value}"),
            container,
            options,
        )?,
    }
    let new = format!("#/components/schemas/{}", keys.join("/"));
    as_object_mut(container).insert("x-ms-odata".into(), Value::String(new));
    Ok(())
}

/// Write a `$ref` object at each refmap source path.
fn dedupe_refs(openapi: &mut Value, refmap: &Map<String, Value>) {
    for (src, target) in refmap {
        if let Some(target) = target.as_str() {
            let mut ref_obj = Map::new();
            ref_obj.insert("$ref".into(), Value::String(target.to_string()));
            jptr::set(openapi, src, Value::Object(ref_obj));
        }
    }
}

// --- paths ---------------------------------------------------------------

/// Process a paths container, converting operations and parameters.
///
/// `openapi` is mutable but holds no reference to `container`, which the caller
/// detaches first. Internal parameter `$ref` deref reads from `openapi`.
fn process_paths(
    container: &mut Value,
    container_name: &str,
    openapi: &mut Value,
    cache: &mut RbCache,
    options: &mut Options,
) -> Result<(), S2OError> {
    let path_keys: Vec<String> = container
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();

    for p in path_keys {
        let Some(path) = container.get_mut(&p) else {
            continue;
        };
        promote_path_extensions(path);

        let method_keys: Vec<String> = path
            .as_object()
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();

        for method in method_keys {
            let is_method = HTTP_METHODS.contains(&method.as_str())
                || method == "x-amazon-apigateway-any-method";
            if !is_method {
                continue;
            }
            process_operation(path, &p, &method, container_name, openapi, cache, options)?;
        }

        // Path-level parameters as components.
        let param_count = path
            .get("parameters")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        for i in 0..param_count {
            let consumes = effective_consumes(None, openapi);
            let Some(param) = path.get_mut("parameters").and_then(|a| a.get_mut(i)) else {
                continue;
            };
            process_parameter(param, None, &p, openapi, &consumes, options)?;
        }
        if !options.debug {
            if let Some(Value::Array(arr)) = path.get_mut("parameters") {
                arr.retain(keep_parameter);
            }
        }
    }
    Ok(())
}

/// Promote path-level `x-` members to their standard names.
fn promote_path_extensions(path: &mut Value) {
    let Some(map) = path.as_object_mut() else {
        return;
    };
    if matches!(map.get("x-trace"), Some(Value::Object(_))) {
        let v = map.remove("x-trace").unwrap();
        map.insert("trace".into(), v);
    }
    if matches!(map.get("x-summary"), Some(Value::String(_))) {
        let v = map.remove("x-summary").unwrap();
        map.insert("summary".into(), v);
    }
    if matches!(map.get("x-description"), Some(Value::String(_))) {
        let v = map.remove("x-description").unwrap();
        map.insert("description".into(), v);
    }
    if matches!(map.get("x-servers"), Some(Value::Array(_))) {
        let v = map.remove("x-servers").unwrap();
        map.insert("servers".into(), v);
    }
}

/// Keep a parameter unless it was marked for deletion.
fn keep_parameter(value: &Value) -> bool {
    !value.is_null() && !truthy(value.get("x-s2o-delete"))
}

/// Process a single operation within a path item.
#[allow(clippy::too_many_arguments)]
fn process_operation(
    path: &mut Value,
    p: &str,
    method: &str,
    container_name: &str,
    openapi: &mut Value,
    cache: &mut RbCache,
    options: &mut Options,
) -> Result<(), S2OError> {
    // Merge applicable path-level parameters into the operation.
    if path.get("parameters").is_some() {
        let path_params = path
            .get("parameters")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for raw_param in path_params {
            let mut param = raw_param;
            if let Some(ref_str) = get_str(&param, "$ref").map(str::to_string) {
                fix_param_ref(&mut param, options)?;
                if let Some(resolved) = jptr::get(openapi, &ref_str).cloned() {
                    param = resolved;
                }
            }
            let name = get_str(&param, "name").map(str::to_string);
            let pin = get_str(&param, "in").map(str::to_string);
            let op_params = path
                .get(method)
                .and_then(|o| o.get("parameters"))
                .and_then(Value::as_array);
            let matched = op_params
                .map(|arr| {
                    arr.iter().any(|e| {
                        get_str(e, "name").map(str::to_string) == name
                            && get_str(e, "in").map(str::to_string) == pin
                    })
                })
                .unwrap_or(false);
            let is_bodyish = pin.as_deref() == Some("formData")
                || pin.as_deref() == Some("body")
                || get_str(&param, "type") == Some("file");
            if !matched && is_bodyish {
                let consumes = {
                    let op = path.get(method);
                    effective_consumes(op, openapi)
                };
                if let Some(op) = path.get_mut(method) {
                    process_parameter(&mut param, Some(op), p, openapi, &consumes, options)?;
                    clean_empty_rbname(op, options);
                }
            }
        }
    }

    // Operation-level parameters.
    let op_param_count = path
        .get(method)
        .and_then(|o| o.get("parameters"))
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    for i in 0..op_param_count {
        let index = format!("{method}:{p}");
        let consumes = {
            let op = path.get(method);
            effective_consumes(op, openapi)
        };
        // Detach the parameter to satisfy the borrow checker, process it, then
        // write it back at the same index.
        let mut param = match path
            .get(method)
            .and_then(|o| o.get("parameters"))
            .and_then(|a| a.get(i))
        {
            Some(p) => p.clone(),
            None => continue,
        };
        let mut op_taken = path.get_mut(method).map(std::mem::take);
        if let Some(op) = op_taken.as_mut() {
            process_parameter(&mut param, Some(op), &index, openapi, &consumes, options)?;
            // The op may have been rebuilt; write the processed param back.
            if let Some(params) = op.get_mut("parameters") {
                if let Some(slot) = params.get_mut(i) {
                    *slot = param;
                }
            }
        }
        if let Some(op) = op_taken {
            as_object_mut(path).insert(method.to_string(), op);
        }
    }
    if let Some(op) = path.get_mut(method) {
        clean_empty_rbname(op, options);
        if !options.debug {
            if let Some(Value::Array(arr)) = op.get_mut("parameters") {
                arr.retain(keep_parameter);
            }
        }
    }

    // Operation security.
    if let Some(op) = path.get_mut(method) {
        if let Some(security) = op.get_mut("security") {
            process_security(security);
        }
    }

    // Responses.
    process_operation_responses(path, method, openapi, options)?;

    // schemes and servers.
    convert_operation_servers(path, method, openapi);

    // Cleanup: drop consumes/produces/schemes, hash the request body.
    finalize_operation(path, p, method, container_name, openapi, cache, options)?;
    Ok(())
}

/// Remove an empty `rbname` marker from an operation.
fn clean_empty_rbname(op: &mut Value, options: &Options) {
    if options.rbname.is_empty() {
        return;
    }
    if op.get(&options.rbname).and_then(Value::as_str) == Some("") {
        as_object_mut(op).remove(&options.rbname);
    }
}

/// Process the responses of one operation.
fn process_operation_responses(
    path: &mut Value,
    method: &str,
    openapi: &Value,
    options: &mut Options,
) -> Result<(), S2OError> {
    let Some(op) = path.get_mut(method) else {
        return Ok(());
    };
    if !op.is_object() {
        return Ok(());
    }
    if op.get("responses").is_none() {
        let mut default = Map::new();
        default.insert(
            "description".into(),
            Value::String("Default response".into()),
        );
        let mut responses = Map::new();
        responses.insert("default".into(), Value::Object(default));
        as_object_mut(op).insert("responses".into(), Value::Object(responses));
    }

    let resp_keys: Vec<String> = op
        .get("responses")
        .and_then(Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    // Detach op so process_response can borrow it while reading openapi.
    let mut op_value = std::mem::take(op);
    for r in resp_keys {
        let mut response = match op_value.get("responses").and_then(|rs| rs.get(&r)) {
            Some(v) => v.clone(),
            None => continue,
        };
        let mut op_for_resp = op_value.clone();
        let result = process_response(&mut response, Some(&mut op_for_resp), openapi, options);
        // produces wrapping may mutate op; carry it back.
        op_value = op_for_resp;
        result?;
        if let Some(responses) = op_value.get_mut("responses") {
            if let Some(slot) = responses.get_mut(&r) {
                *slot = response;
            }
        }
    }
    if let Some(op) = path.get_mut(method) {
        *op = op_value;
    } else {
        as_object_mut(path).insert(method.to_string(), op_value);
    }
    Ok(())
}

/// Convert operation-level schemes to servers.
fn convert_operation_servers(path: &mut Value, method: &str, openapi: &Value) {
    let Some(op) = path.get_mut(method) else {
        return;
    };
    if matches!(op.get("x-servers"), Some(Value::Array(_))) {
        let v = as_object_mut(op).remove("x-servers").unwrap();
        as_object_mut(op).insert("servers".into(), v);
        return;
    }
    let schemes = op
        .get("schemes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if schemes.is_empty() {
        return;
    }
    let doc_schemes = openapi.get("schemes").and_then(Value::as_array);
    let servers = openapi.get("servers").and_then(Value::as_array).cloned();
    for scheme in &schemes {
        let already = doc_schemes.map(|s| s.contains(scheme)).unwrap_or(false);
        if already {
            continue;
        }
        if op.get("servers").is_none() {
            as_object_mut(op).insert("servers".into(), Value::Array(Vec::new()));
        }
        if let Some(servers) = &servers {
            for server in servers {
                let mut new_server = server.clone();
                if let Some(url) = get_str(&new_server, "url") {
                    let rebuilt = set_url_scheme(url, scheme.as_str().unwrap_or(""));
                    as_object_mut(&mut new_server).insert("url".into(), Value::String(rebuilt));
                }
                if let Some(Value::Array(arr)) = op.get_mut("servers") {
                    arr.push(new_server);
                }
            }
        }
    }
}

/// Replace the scheme of a server URL.
fn set_url_scheme(url: &str, scheme: &str) -> String {
    if let Some(idx) = url.find("://") {
        format!("{scheme}://{}", &url[idx + 3..])
    } else if let Some(rest) = url.strip_prefix("//") {
        format!("{scheme}://{rest}")
    } else {
        format!("{scheme}://{url}")
    }
}

/// Final operation cleanup and request body hashing.
#[allow(clippy::too_many_arguments)]
fn finalize_operation(
    path: &mut Value,
    p: &str,
    method: &str,
    container_name: &str,
    openapi: &mut Value,
    cache: &mut RbCache,
    options: &mut Options,
) -> Result<(), S2OError> {
    let Some(op) = path.get_mut(method) else {
        return Ok(());
    };
    if options.debug {
        let consumes = op.get("consumes").cloned().unwrap_or(Value::Array(vec![]));
        let produces = op.get("produces").cloned().unwrap_or(Value::Array(vec![]));
        as_object_mut(op).insert("x-s2o-consumes".into(), consumes);
        as_object_mut(op).insert("x-s2o-produces".into(), produces);
    }
    as_object_mut(op).remove("consumes");
    as_object_mut(op).remove("produces");
    as_object_mut(op).remove("schemes");

    convert_ms_examples(path, method, openapi);

    let Some(op) = path.get_mut(method) else {
        return Ok(());
    };

    // Drop an empty parameters array.
    if op
        .get("parameters")
        .and_then(Value::as_array)
        .map(Vec::is_empty)
        == Some(true)
    {
        as_object_mut(op).remove("parameters");
    }

    // Hash the request body for shared-body extraction.
    if op.get("requestBody").is_some() {
        let effective_operation_id = match get_str(op, "operationId") {
            Some(id) => sanitise_all(id),
            None => to_camel_case(&sanitise_all(&format!("{method}{p}"))),
        };
        let name_source = op
            .get("requestBody")
            .and_then(|rb| get_str(rb, "x-s2o-name"))
            .map(str::to_string)
            .filter(|s| !s.is_empty())
            .unwrap_or(effective_operation_id);
        let rb_name = sanitise(&name_source);
        if let Some(rb) = op.get_mut("requestBody") {
            as_object_mut(rb).remove("x-s2o-name");
        }
        let rb = op.get("requestBody").cloned().unwrap_or_else(empty_object);
        let rb_str = serde_json::to_string(&rb).unwrap_or_default();
        let rb_hash = hash(&rb_str);
        let body = rb.clone();
        let entry = cache.get_or_insert(rb_hash, &rb, || RbEntry {
            name: rb_name,
            body,
            refs: Vec::new(),
        });
        let ptr = format!(
            "#/{container_name}/{}/{method}/requestBody",
            encode_uri_component(&jpescape(p))
        );
        entry.refs.push(ptr);
    }
    Ok(())
}

/// Convert Azure `x-ms-examples` into OpenAPI `examples`.
///
/// Each example maps its parameter values onto matching op or path parameters,
/// its response header values onto response headers, and its response body into
/// `components.examples` with a `$ref` from each response content type. The
/// `x-ms-examples` member is removed.
fn convert_ms_examples(path: &mut Value, method: &str, openapi: &mut Value) {
    let examples = path
        .get(method)
        .and_then(|o| o.get("x-ms-examples"))
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<Vec<_>>()
        });
    let Some(examples) = examples else {
        return;
    };
    // Detach path-level parameters so the op borrow and the path-param writes do
    // not overlap. They are reattached after the examples are applied.
    let mut path_params = path
        .as_object_mut()
        .and_then(|m| m.remove("parameters"))
        .unwrap_or(Value::Null);

    let Some(op) = path.get_mut(method) else {
        return;
    };

    for (name, example) in examples {
        let se = sanitise_all(&name);
        apply_example_parameters(op, &mut path_params, &name, &example, openapi);
        apply_example_responses(op, &name, &se, &example, openapi);
    }

    as_object_mut(op).remove("x-ms-examples");

    if !path_params.is_null() {
        as_object_mut(path).insert("parameters".into(), path_params);
    }
}

/// Attach example parameter values to the matching op or path parameters.
fn apply_example_parameters(
    op: &mut Value,
    path_params: &mut Value,
    example_name: &str,
    example: &Value,
    openapi: &Value,
) {
    let Some(params) = example.get("parameters").and_then(Value::as_object) else {
        return;
    };
    for (pname, value) in params {
        let op_len = op
            .get("parameters")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        for i in 0..op_len {
            if let Some(target) = op.get_mut("parameters").and_then(|a| a.get_mut(i)) {
                set_param_example(target, pname, example_name, value, openapi);
            }
        }
        let path_len = path_params.as_array().map(Vec::len).unwrap_or(0);
        for i in 0..path_len {
            if let Some(target) = path_params.get_mut(i) {
                set_param_example(target, pname, example_name, value, openapi);
            }
        }
    }
}

/// Set `param.examples[name] = {value}` when the param matches and has no
/// inline example. Resolves a `$ref` target inside the document.
fn set_param_example(
    param: &mut Value,
    pname: &str,
    example_name: &str,
    value: &Value,
    openapi: &Value,
) {
    let matches_name = if let Some(ref_str) = param.get("$ref").and_then(Value::as_str) {
        jptr::get(openapi, ref_str)
            .and_then(|t| get_str(t, "name"))
            .map(|n| n == pname)
            .unwrap_or(false)
    } else {
        get_str(param, "name") == Some(pname)
    };
    if !matches_name || param.get("example").is_some() {
        return;
    }
    as_object_mut(param)
        .entry("examples")
        .or_insert_with(empty_object);
    if let Some(examples) = param.get_mut("examples") {
        let mut wrapped = Map::new();
        wrapped.insert("value".into(), value.clone());
        as_object_mut(examples).insert(example_name.to_string(), Value::Object(wrapped));
    }
}

/// Attach example response headers and bodies.
fn apply_example_responses(
    op: &mut Value,
    example_name: &str,
    se: &str,
    example: &Value,
    openapi: &mut Value,
) {
    let Some(responses) = example.get("responses").and_then(Value::as_object) else {
        return;
    };
    for (r, resp) in responses {
        // Headers: header.example = value.
        if let Some(headers) = resp.get("headers").and_then(Value::as_object) {
            for (h, value) in headers {
                let target = op
                    .get_mut("responses")
                    .and_then(|rs| rs.get_mut(r.as_str()))
                    .and_then(|resp| resp.get_mut("headers"))
                    .and_then(|hs| hs.get_mut(h.as_str()));
                if let Some(header) = target {
                    as_object_mut(header).insert("example".into(), value.clone());
                }
            }
        }
        // Body: into components.examples and referenced from each content type.
        if let Some(body) = resp.get("body") {
            let mut wrapped = Map::new();
            wrapped.insert("value".into(), body.clone());
            set_component_example(openapi, se, Value::Object(wrapped));

            let content_types: Vec<String> = op
                .get("responses")
                .and_then(|rs| rs.get(r.as_str()))
                .and_then(|resp| resp.get("content"))
                .and_then(Value::as_object)
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default();
            for ct in content_types {
                let target = op
                    .get_mut("responses")
                    .and_then(|rs| rs.get_mut(r.as_str()))
                    .and_then(|resp| resp.get_mut("content"))
                    .and_then(|c| c.get_mut(&ct));
                if let Some(content_type) = target {
                    as_object_mut(content_type)
                        .entry("examples")
                        .or_insert_with(empty_object);
                    if let Some(examples) = content_type.get_mut("examples") {
                        let mut ref_obj = Map::new();
                        ref_obj.insert(
                            "$ref".into(),
                            Value::String(format!("#/components/examples/{se}")),
                        );
                        as_object_mut(examples)
                            .insert(example_name.to_string(), Value::Object(ref_obj));
                    }
                }
            }
        }
    }
}

/// Insert a value under `components.examples`, creating the bucket.
fn set_component_example(openapi: &mut Value, key: &str, value: Value) {
    as_object_mut(openapi)
        .entry("components")
        .or_insert_with(empty_object);
    if let Some(components) = openapi.get_mut("components") {
        as_object_mut(components)
            .entry("examples")
            .or_insert_with(empty_object);
        if let Some(examples) = components.get_mut("examples") {
            as_object_mut(examples).insert(key.to_string(), value);
        }
    }
}

// --- main conversion core ------------------------------------------------

/// Run the conversion core over an already-skeletoned document.
fn main_convert(openapi: &mut Value, options: &mut Options) -> Result<(), S2OError> {
    let mut cache = RbCache::default();
    let mut component_names = ComponentNames::default();

    if let Some(security) = openapi.get_mut("security") {
        process_security(security);
    }

    process_security_schemes(openapi, options)?;
    process_schemas(openapi, &mut component_names, options)?;

    fixup_refs(openapi, &component_names, options)?;

    process_component_parameters(openapi, options)?;
    process_component_responses(openapi, options)?;
    seed_existing_request_bodies(openapi, &mut cache);

    // Process paths with openapi available for internal deref.
    let mut paths = openapi
        .get_mut("paths")
        .map(std::mem::take)
        .unwrap_or_else(empty_object);
    process_paths(&mut paths, "paths", openapi, &mut cache, options)?;
    as_object_mut(openapi).insert("paths".into(), paths);

    if openapi.get("x-ms-paths").is_some() {
        let mut xms = openapi.get_mut("x-ms-paths").map(std::mem::take).unwrap();
        process_paths(&mut xms, "x-ms-paths", openapi, &mut cache, options)?;
        as_object_mut(openapi).insert("x-ms-paths".into(), xms);
    }

    remove_consumed_parameters(openapi, options);

    if options.debug {
        let consumes = openapi
            .get("consumes")
            .cloned()
            .unwrap_or(Value::Array(vec![]));
        let produces = openapi
            .get("produces")
            .cloned()
            .unwrap_or(Value::Array(vec![]));
        as_object_mut(openapi).insert("x-s2o-consumes".into(), consumes);
        as_object_mut(openapi).insert("x-s2o-produces".into(), produces);
    }
    as_object_mut(openapi).remove("consumes");
    as_object_mut(openapi).remove("produces");
    as_object_mut(openapi).remove("schemes");

    extract_shared_request_bodies(openapi, &cache, options);
    prune_empty_components(openapi);
    Ok(())
}

/// Sanitise and convert each security scheme.
fn process_security_schemes(openapi: &mut Value, options: &mut Options) -> Result<(), S2OError> {
    let names: Vec<String> = openapi
        .get("components")
        .and_then(|c| c.get("securitySchemes"))
        .and_then(Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    for s in names {
        let sname = sanitise(&s);
        if s != sname {
            let schemes = openapi
                .get_mut("components")
                .and_then(|c| c.get_mut("securitySchemes"))
                .and_then(Value::as_object_mut);
            if let Some(map) = schemes {
                if map.contains_key(&sname) {
                    return Err(S2OError::new(format!(
                        "Duplicate sanitised securityScheme name {sname}"
                    )));
                }
                if let Some(v) = map.remove(&s) {
                    map.insert(sname.clone(), v);
                }
            }
        }
        let scheme = openapi
            .get_mut("components")
            .and_then(|c| c.get_mut("securitySchemes"))
            .and_then(|s| s.get_mut(&sname));
        if let Some(scheme) = scheme {
            process_security_scheme(scheme, options)?;
        }
    }
    Ok(())
}

/// Sanitise, deduplicate, and fix every component schema.
fn process_schemas(
    openapi: &mut Value,
    component_names: &mut ComponentNames,
    options: &mut Options,
) -> Result<(), S2OError> {
    let names: Vec<String> = openapi
        .get("components")
        .and_then(|c| c.get("schemas"))
        .and_then(Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    for s in names {
        let sname = sanitise_all(&s);
        let mut suffix = SuffixCounter::Empty;
        let mut final_name = sname.clone();
        if s != sname {
            let map = openapi
                .get("components")
                .and_then(|c| c.get("schemas"))
                .and_then(Value::as_object);
            if let Some(map) = map {
                while map.contains_key(&format!("{sname}{}", suffix.as_str())) {
                    suffix = suffix.next();
                }
            }
            final_name = format!("{sname}{}", suffix.as_str());
            let schemas = openapi
                .get_mut("components")
                .and_then(|c| c.get_mut("schemas"))
                .and_then(Value::as_object_mut);
            if let Some(map) = schemas {
                if let Some(v) = map.remove(&s) {
                    map.insert(final_name.clone(), v);
                }
            }
        }
        component_names
            .schemas
            .insert(s.clone(), Value::String(final_name.clone()));
        let schema = openapi
            .get_mut("components")
            .and_then(|c| c.get_mut("schemas"))
            .and_then(|s| s.get_mut(&final_name));
        if let Some(schema) = schema {
            fix_up_schema(schema, options)?;
        }
    }
    Ok(())
}

/// Sanitise component parameters and convert them.
fn process_component_parameters(
    openapi: &mut Value,
    options: &mut Options,
) -> Result<(), S2OError> {
    let names: Vec<String> = openapi
        .get("components")
        .and_then(|c| c.get("parameters"))
        .and_then(Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    for pname in names {
        let sname = sanitise(&pname);
        if pname != sname {
            let params = openapi
                .get_mut("components")
                .and_then(|c| c.get_mut("parameters"))
                .and_then(Value::as_object_mut);
            if let Some(map) = params {
                if map.contains_key(&sname) {
                    return Err(S2OError::new(format!(
                        "Duplicate sanitised parameter name {sname}"
                    )));
                }
                if let Some(v) = map.remove(&pname) {
                    map.insert(sname.clone(), v);
                }
            }
        }
        let consumes = effective_consumes(None, openapi);
        let mut param = match openapi
            .get("components")
            .and_then(|c| c.get("parameters"))
            .and_then(|p| p.get(&sname))
        {
            Some(v) => v.clone(),
            None => continue,
        };
        process_parameter(&mut param, None, &sname, openapi, &consumes, options)?;
        if let Some(slot) = openapi
            .get_mut("components")
            .and_then(|c| c.get_mut("parameters"))
            .and_then(|p| p.get_mut(&sname))
        {
            *slot = param;
        }
    }
    Ok(())
}

/// Sanitise component responses and convert them.
fn process_component_responses(openapi: &mut Value, options: &mut Options) -> Result<(), S2OError> {
    let names: Vec<String> = openapi
        .get("components")
        .and_then(|c| c.get("responses"))
        .and_then(Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    for rname in names {
        let sname = sanitise(&rname);
        if rname != sname {
            let responses = openapi
                .get_mut("components")
                .and_then(|c| c.get_mut("responses"))
                .and_then(Value::as_object_mut);
            if let Some(map) = responses {
                if map.contains_key(&sname) {
                    return Err(S2OError::new(format!(
                        "Duplicate sanitised response name {sname}"
                    )));
                }
                if let Some(v) = map.remove(&rname) {
                    map.insert(sname.clone(), v);
                }
            }
        }
        let mut response = match openapi
            .get("components")
            .and_then(|c| c.get("responses"))
            .and_then(|r| r.get(&sname))
        {
            Some(v) => v.clone(),
            None => continue,
        };
        let openapi_ro = openapi.clone();
        process_response(&mut response, None, &openapi_ro, options)?;
        process_response_headers(&mut response, options)?;
        if let Some(slot) = openapi
            .get_mut("components")
            .and_then(|c| c.get_mut("responses"))
            .and_then(|r| r.get_mut(&sname))
        {
            *slot = response;
        }
    }
    Ok(())
}

/// Seed the cache with request bodies that already exist as components.
fn seed_existing_request_bodies(openapi: &Value, cache: &mut RbCache) {
    let bodies: Vec<(String, Value)> = openapi
        .get("components")
        .and_then(|c| c.get("requestBodies"))
        .and_then(Value::as_object)
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();
    for (name, rb) in bodies {
        let rb_str = serde_json::to_string(&rb).unwrap_or_default();
        let rb_hash = hash(&rb_str);
        let body = rb.clone();
        cache.get_or_insert(rb_hash, &rb, || RbEntry {
            name,
            body,
            refs: Vec::new(),
        });
    }
}

/// Remove parameters that were consumed into request bodies.
fn remove_consumed_parameters(openapi: &mut Value, options: &Options) {
    if options.debug {
        return;
    }
    let params = openapi
        .get_mut("components")
        .and_then(|c| c.get_mut("parameters"))
        .and_then(Value::as_object_mut);
    if let Some(map) = params {
        let to_remove: Vec<String> = map
            .iter()
            .filter(|(_, v)| truthy(v.get("x-s2o-delete")))
            .map(|(k, _)| k.clone())
            .collect();
        for k in to_remove {
            map.remove(&k);
        }
    }
}

/// Build shared request bodies for any body referenced more than once.
fn extract_shared_request_bodies(openapi: &mut Value, cache: &RbCache, options: &Options) {
    // Reset the bucket.
    if let Some(components) = openapi.get_mut("components") {
        as_object_mut(components).insert("requestBodies".into(), empty_object());
    }
    if options.resolve_internal {
        return;
    }

    let mut generated: Vec<String> = Vec::new();
    let mut counter = 1u64;
    for key in &cache.order {
        let entry = &cache.entries[&key.hash][key.index];
        if entry.refs.len() <= 1 {
            continue;
        }
        let mut name = entry.name.clone();
        let mut suffix = SuffixCounter::Empty;
        if name.is_empty() {
            name = "requestBody".to_string();
            suffix = SuffixCounter::Num(counter);
            counter += 1;
        }
        while generated.contains(&format!("{name}{}", suffix.as_str())) {
            suffix = suffix.next();
        }
        let final_name = format!("{name}{}", suffix.as_str());
        generated.push(final_name.clone());

        if let Some(components) = openapi.get_mut("components") {
            if let Some(bodies) = components.get_mut("requestBodies") {
                as_object_mut(bodies).insert(final_name.clone(), entry.body.clone());
            }
        }
        for ptr in &entry.refs {
            let mut ref_obj = Map::new();
            ref_obj.insert(
                "$ref".into(),
                Value::String(format!("#/components/requestBodies/{final_name}")),
            );
            jptr::set(openapi, ptr, Value::Object(ref_obj));
        }
    }
}

/// Delete empty component buckets, then components itself if empty.
fn prune_empty_components(openapi: &mut Value) {
    let buckets = [
        "responses",
        "parameters",
        "examples",
        "requestBodies",
        "securitySchemes",
        "headers",
        "schemas",
    ];
    if let Some(components) = openapi.get_mut("components") {
        if let Some(map) = components.as_object_mut() {
            for bucket in buckets {
                let empty = map
                    .get(bucket)
                    .and_then(Value::as_object)
                    .map(serde_json::Map::is_empty)
                    .unwrap_or(false);
                if empty {
                    map.remove(bucket);
                }
            }
        }
    }
    let components_empty = openapi
        .get("components")
        .and_then(Value::as_object)
        .map(serde_json::Map::is_empty)
        .unwrap_or(false);
    if components_empty {
        as_object_mut(openapi).remove("components");
    }
}

// --- skeleton helpers ----------------------------------------------------

/// Register server URL template variables and collapse doubled braces.
fn extract_server_parameters(server: &mut Value) {
    let Some(url) = get_str(server, "url").map(str::to_string) else {
        return;
    };
    let url = url.replace("{{", "{").replace("}}", "}");
    as_object_mut(server).insert("url".into(), Value::String(url.clone()));

    // Register each {name} as a variable with default "unknown". The URL text
    // is left unchanged.
    let mut names: Vec<String> = Vec::new();
    let mut rest = url.as_str();
    while let Some(open) = rest.find('{') {
        if let Some(close) = rest[open + 1..].find('}') {
            let name = &rest[open + 1..open + 1 + close];
            names.push(name.to_string());
            rest = &rest[open + 1 + close + 1..];
        } else {
            break;
        }
    }
    if !names.is_empty() {
        as_object_mut(server)
            .entry("variables")
            .or_insert_with(empty_object);
        if let Some(vars) = server.get_mut("variables") {
            for name in names {
                let mut def = Map::new();
                def.insert("default".into(), Value::String("unknown".into()));
                as_object_mut(vars).insert(name, Value::Object(def));
            }
        }
    }
}

/// Validate and repair the info object.
fn fix_info(openapi: &mut Value, options: &mut Options) -> Result<(), S2OError> {
    let info_missing = matches!(openapi.get("info"), None | Some(Value::Null));
    if info_missing {
        if options.patch {
            options.patches += 1;
            let mut info = Map::new();
            info.insert("version".into(), Value::String(String::new()));
            info.insert("title".into(), Value::String(String::new()));
            as_object_mut(openapi).insert("info".into(), Value::Object(info));
        } else {
            return Err(S2OError::new("(Patchable) info object is mandatory"));
        }
    }
    let info_is_object = openapi.get("info").map(Value::is_object).unwrap_or(false);
    if !info_is_object {
        return Err(S2OError::new("info must be an object"));
    }

    let title_missing = matches!(
        openapi.get("info").and_then(|i| i.get("title")),
        None | Some(Value::Null)
    );
    if title_missing {
        if options.patch {
            options.patches += 1;
            set_info(openapi, "title", Value::String(String::new()));
        } else {
            return Err(S2OError::new("(Patchable) info.title cannot be null"));
        }
    }

    let version_missing = matches!(
        openapi.get("info").and_then(|i| i.get("version")),
        None | Some(Value::Null)
    );
    if version_missing {
        if options.patch {
            options.patches += 1;
            set_info(openapi, "version", Value::String(String::new()));
        } else {
            return Err(S2OError::new("(Patchable) info.version cannot be null"));
        }
    }
    let version_is_string = openapi
        .get("info")
        .and_then(|i| i.get("version"))
        .map(Value::is_string)
        .unwrap_or(false);
    if !version_is_string {
        if options.patch {
            options.patches += 1;
            let v = openapi
                .get("info")
                .and_then(|i| i.get("version"))
                .cloned()
                .unwrap_or(Value::Null);
            set_info(openapi, "version", Value::String(value_to_string(&v)));
        } else {
            return Err(S2OError::new("(Patchable) info.version must be a string"));
        }
    }

    if openapi.get("info").and_then(|i| i.get("logo")).is_some() {
        if options.patch {
            options.patches += 1;
            let logo = openapi
                .get("info")
                .and_then(|i| i.get("logo"))
                .cloned()
                .unwrap();
            set_info(openapi, "x-logo", logo);
            if let Some(info) = openapi.get_mut("info") {
                as_object_mut(info).remove("logo");
            }
        } else {
            return Err(S2OError::new(
                "(Patchable) info should not have logo property",
            ));
        }
    }

    fix_terms_of_service(openapi, options)?;
    Ok(())
}

/// Validate the optional info.termsOfService URL.
fn fix_terms_of_service(openapi: &mut Value, options: &mut Options) -> Result<(), S2OError> {
    let tos = openapi.get("info").and_then(|i| i.get("termsOfService"));
    let Some(tos) = tos else {
        return Ok(());
    };
    if tos.is_null() {
        if options.patch {
            options.patches += 1;
            set_info(openapi, "termsOfService", Value::String(String::new()));
        } else {
            return Err(S2OError::new(
                "(Patchable) info.termsOfService cannot be null",
            ));
        }
    }
    let tos_str = openapi
        .get("info")
        .and_then(|i| i.get("termsOfService"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if !looks_like_url(tos_str) {
        if options.patch {
            options.patches += 1;
            if let Some(info) = openapi.get_mut("info") {
                as_object_mut(info).remove("termsOfService");
            }
        } else {
            return Err(S2OError::new(
                "(Patchable) info.termsOfService must be a URL",
            ));
        }
    }
    Ok(())
}

/// Whether a string parses as an absolute URL the way `new URL(...)` would.
///
/// The check requires a scheme followed by `:`, matching the lenient WHATWG
/// behaviour the algorithm relies on.
fn looks_like_url(s: &str) -> bool {
    let Some(idx) = s.find(':') else {
        return false;
    };
    let scheme = &s[..idx];
    !scheme.is_empty()
        && scheme.chars().next().unwrap().is_ascii_alphabetic()
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Set a member of the info object.
fn set_info(openapi: &mut Value, key: &str, value: Value) {
    as_object_mut(openapi)
        .entry("info")
        .or_insert_with(empty_object);
    if let Some(info) = openapi.get_mut("info") {
        as_object_mut(info).insert(key.to_string(), value);
    }
}

/// Render a scalar value as its string form.
fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

/// Ensure a paths object exists.
fn fix_paths(openapi: &mut Value, options: &mut Options) -> Result<(), S2OError> {
    if openapi.get("paths").is_none() {
        if options.patch {
            options.patches += 1;
            as_object_mut(openapi).insert("paths".into(), empty_object());
        } else {
            return Err(S2OError::new("(Patchable) paths object is mandatory"));
        }
    }
    Ok(())
}

// --- public entry points -------------------------------------------------

/// Convert a Swagger 2.0 document into OpenAPI 3.0.
///
/// On success `options.openapi` holds the converted document and is returned by
/// reference through `options`. The input value is not mutated.
pub fn convert_obj(swagger: &Value, options: &mut Options) -> Result<(), S2OError> {
    let swagger = if swagger.is_null() {
        empty_object()
    } else {
        swagger.clone()
    };

    // Record the YAML form of the input when no entry point set it already.
    if options.text.is_empty() {
        options.text = crate::yaml::stringify(&swagger);
    }

    options.patches = 0;

    // Reject YAML anchors unless allowed.
    if options.had_anchors && !options.anchors {
        return Err(S2OError::new("YAML anchor or merge key"));
    }

    // OAS3 pass-through.
    if let Some(v) = swagger.get("openapi").and_then(Value::as_str) {
        if v.starts_with("3.") {
            let mut openapi = swagger.clone();
            fix_info(&mut openapi, options)?;
            fix_paths(&mut openapi, options)?;
            options.openapi = openapi;
            // optional_resolve is a no-op unless resolve is set.
            resolver::optional_resolve(options)?;
            return Ok(());
        }
    }

    // Version gate.
    let swagger_version = swagger.get("swagger");
    if !is_swagger_two(swagger_version) {
        let reported = swagger
            .get("openapi")
            .or(swagger_version)
            .map(value_to_string)
            .unwrap_or_else(|| "undefined".to_string());
        return Err(S2OError::new(format!(
            "Unsupported swagger/OpenAPI version: {reported}"
        )));
    }

    // Skeleton.
    let mut openapi = empty_object();
    let target = match &options.target_version {
        Some(t) if t.starts_with("3.") => t.clone(),
        _ => TARGET_VERSION.to_string(),
    };
    as_object_mut(&mut openapi).insert("openapi".into(), Value::String(target));

    if options.origin {
        let mut origin = Map::new();
        let url = options.source.clone().unwrap_or_else(|| "true".to_string());
        origin.insert("url".into(), Value::String(url));
        origin.insert("format".into(), Value::String("swagger".into()));
        origin.insert(
            "version".into(),
            swagger.get("swagger").cloned().unwrap_or(Value::Null),
        );
        let mut converter = Map::new();
        converter.insert(
            "url".into(),
            Value::String("https://github.com/mermade/oas-kit".into()),
        );
        converter.insert("version".into(), Value::String(OUR_VERSION.into()));
        origin.insert("converter".into(), Value::Object(converter));
        as_object_mut(&mut openapi)
            .insert("x-origin".into(), Value::Array(vec![Value::Object(origin)]));
    }

    // Copy swagger members in, keeping openapi first.
    if let Some(map) = swagger.as_object() {
        for (k, v) in map {
            as_object_mut(&mut openapi).insert(k.clone(), v.clone());
        }
    }
    as_object_mut(&mut openapi).remove("swagger");

    // Strip nulls, sparing x- keys, default, and anything under /example.
    strip_nulls(&mut openapi);

    build_servers(&mut openapi, &swagger);

    if matches!(openapi.get("x-servers"), Some(Value::Array(_))) {
        let v = as_object_mut(&mut openapi).remove("x-servers").unwrap();
        as_object_mut(&mut openapi).insert("servers".into(), v);
    }

    build_parameterized_host(&mut openapi, &swagger);

    fix_info(&mut openapi, options)?;
    fix_paths(&mut openapi, options)?;

    if let Some(Value::String(s)) = openapi.get("consumes") {
        let s = s.clone();
        as_object_mut(&mut openapi).insert("consumes".into(), Value::Array(vec![Value::String(s)]));
    }
    if let Some(Value::String(s)) = openapi.get("produces") {
        let s = s.clone();
        as_object_mut(&mut openapi).insert("produces".into(), Value::Array(vec![Value::String(s)]));
    }

    build_components(&mut openapi);

    options.openapi = openapi;
    resolver::optional_resolve(options)?;
    // Take the document out so the core can borrow it alongside options.
    let mut doc = std::mem::take(&mut options.openapi);
    let result = main_convert(&mut doc, options);
    options.openapi = doc;
    result
}

/// Whether the swagger version value equals `"2.0"` under loose comparison.
fn is_swagger_two(value: Option<&Value>) -> bool {
    match value {
        Some(Value::String(s)) => s == "2.0",
        Some(Value::Number(n)) => n.as_f64() == Some(2.0),
        _ => false,
    }
}

/// Delete null members, sparing extensions, `default`, and example paths.
///
/// On an object the key is removed. On an array the slot is left as `null`
/// rather than spliced out. This matches `delete arr[i]`, which leaves a hole
/// the later indices keep their positions and the hole serializes back to
/// `null`. Compacting the array would shift the indices the traversal already
/// collected and drop the wrong elements.
fn strip_nulls(openapi: &mut Value) {
    recurse(openapi, "#", &mut |obj, key, state| {
        let is_null = obj.get(key) == Some(&Value::Null);
        if is_null && !key.starts_with("x-") && key != "default" && !state.path.contains("/example")
        {
            if let Some(map) = obj.as_object_mut() {
                map.remove(key);
            }
        }
    });
}

/// Build the `servers` array from host, basePath, and schemes.
fn build_servers(openapi: &mut Value, swagger: &Value) {
    if let Some(host) = swagger.get("host").and_then(Value::as_str) {
        let schemes: Vec<String> = match swagger.get("schemes") {
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
            _ => vec![String::new()],
        };
        for s in schemes {
            let base_path = swagger
                .get("basePath")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim_end_matches('/')
                .to_string();
            let url = format!(
                "{}//{host}{base_path}",
                if s.is_empty() {
                    String::new()
                } else {
                    format!("{s}:")
                }
            );
            let mut server = Map::new();
            server.insert("url".into(), Value::String(url));
            let mut server = Value::Object(server);
            extract_server_parameters(&mut server);
            push_server(openapi, server);
        }
    } else if let Some(base_path) = swagger.get("basePath").and_then(Value::as_str) {
        let mut server = Map::new();
        server.insert("url".into(), Value::String(base_path.to_string()));
        let mut server = Value::Object(server);
        extract_server_parameters(&mut server);
        push_server(openapi, server);
    }
    as_object_mut(openapi).remove("host");
    as_object_mut(openapi).remove("basePath");
}

/// Append a server to `openapi.servers`, creating the array if needed.
fn push_server(openapi: &mut Value, server: Value) {
    as_object_mut(openapi)
        .entry("servers")
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Some(Value::Array(arr)) = openapi.get_mut("servers") {
        arr.push(server);
    }
}

/// Build a server from an Azure `x-ms-parameterized-host` block.
///
/// The host template plus the base path becomes `server.url`. Each named
/// parameter moves under `server.variables` keyed by its name. The block is
/// removed from the output. With `useSchemePrefix === false` the server is
/// pushed once. Otherwise one server is pushed per scheme with the scheme
/// prepended to the URL.
fn build_parameterized_host(openapi: &mut Value, swagger: &Value) {
    let Some(host) = swagger.get("x-ms-parameterized-host").cloned() else {
        return;
    };
    let host_template = get_str(&host, "hostTemplate").unwrap_or("");
    let base_path = swagger
        .get("basePath")
        .and_then(Value::as_str)
        .unwrap_or("");
    let url = format!("{host_template}{base_path}");
    let param_names = match_brace_tokens(&url);

    let mut variables = Map::new();
    if let Some(params) = host.get("parameters").and_then(Value::as_object) {
        for (idx, (msp, raw)) in params.iter().enumerate() {
            build_host_variable(openapi, msp, idx, raw, &param_names, &mut variables);
        }
    } else if let Some(params) = host.get("parameters").and_then(Value::as_array) {
        for (idx, raw) in params.iter().enumerate() {
            build_host_variable(
                openapi,
                &idx.to_string(),
                idx,
                raw,
                &param_names,
                &mut variables,
            );
        }
    }

    let mut server = Map::new();
    server.insert("url".into(), Value::String(url.clone()));
    server.insert("variables".into(), Value::Object(variables));
    let server = Value::Object(server);

    let scheme_prefix = host.get("useSchemePrefix").and_then(Value::as_bool);
    if scheme_prefix == Some(false) {
        push_server(openapi, server);
    } else if let Some(schemes) = swagger.get("schemes").and_then(Value::as_array) {
        for scheme in schemes {
            let scheme = scheme.as_str().unwrap_or("");
            let mut copy = server.as_object().cloned().unwrap_or_default();
            copy.insert("url".into(), Value::String(format!("{scheme}://{url}")));
            push_server(openapi, Value::Object(copy));
        }
    }

    as_object_mut(openapi).remove("x-ms-parameterized-host");
}

/// Resolve one parameterized-host parameter and record it as a server variable.
fn build_host_variable(
    openapi: &Value,
    msp: &str,
    idx: usize,
    raw: &Value,
    param_names: &[String],
    variables: &mut Map<String, Value>,
) {
    if msp.starts_with("x-") {
        return;
    }
    let mut param = match raw.get("$ref").and_then(Value::as_str) {
        Some(ref_str) => jptr::get(openapi, ref_str)
            .cloned()
            .unwrap_or_else(empty_object),
        None => raw.clone(),
    };
    let pmap = as_object_mut(&mut param);
    pmap.remove("required");
    pmap.remove("type");
    pmap.remove("in");
    if pmap.get("default").is_none() {
        let default = pmap
            .get("enum")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .cloned()
            .unwrap_or_else(|| Value::String("none".into()));
        pmap.insert("default".into(), default);
    }
    let name = match pmap.get("name").and_then(Value::as_str) {
        Some(n) => n.to_string(),
        None => param_names
            .get(idx)
            .map(|t| t.replace(['{', '}'], ""))
            .unwrap_or_default(),
    };
    pmap.remove("name");
    variables.insert(name, param);
}

/// Collect `{word}` tokens from a URL template in order.
fn match_brace_tokens(url: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let bytes: Vec<char> = url.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == '{' {
            let mut j = i + 1;
            while j < bytes.len() && (bytes[j].is_alphanumeric() || bytes[j] == '_') {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == '}' && j > i + 1 {
                tokens.push(bytes[i..=j].iter().collect());
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    tokens
}

/// Relocate top-level Swagger containers under `components`.
fn build_components(openapi: &mut Value) {
    let mut components = Map::new();
    if let Some(cb) = openapi.get("x-callbacks").cloned() {
        components.insert("callbacks".into(), cb);
        as_object_mut(openapi).remove("x-callbacks");
    }
    components.insert("examples".into(), empty_object());
    components.insert("headers".into(), empty_object());
    if let Some(links) = openapi.get("x-links").cloned() {
        components.insert("links".into(), links);
        as_object_mut(openapi).remove("x-links");
    }
    components.insert(
        "parameters".into(),
        openapi
            .get("parameters")
            .cloned()
            .unwrap_or_else(empty_object),
    );
    components.insert(
        "responses".into(),
        openapi
            .get("responses")
            .cloned()
            .unwrap_or_else(empty_object),
    );
    components.insert("requestBodies".into(), empty_object());
    components.insert(
        "securitySchemes".into(),
        openapi
            .get("securityDefinitions")
            .cloned()
            .unwrap_or_else(empty_object),
    );
    components.insert(
        "schemas".into(),
        openapi
            .get("definitions")
            .cloned()
            .unwrap_or_else(empty_object),
    );

    let m = as_object_mut(openapi);
    m.insert("components".into(), Value::Object(components));
    m.remove("definitions");
    m.remove("responses");
    m.remove("parameters");
    m.remove("securityDefinitions");
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn convert(input: Value) -> Options {
        let mut options = Options::new();
        convert_obj(&input, &mut options).unwrap();
        options
    }

    #[test]
    fn request_body_cache_keeps_hash_collisions_distinct() {
        let options = convert(json!({
            "swagger": "2.0",
            "info": { "title": "Demo", "version": "1.0.0" },
            "paths": {
                "/aa": {
                    "post": {
                        "operationId": "create",
                        "parameters": [
                            {
                                "name": "payload",
                                "in": "body",
                                "schema": {
                                    "description": "Aa",
                                    "type": "object"
                                }
                            }
                        ],
                        "responses": { "200": { "description": "ok" } }
                    }
                },
                "/bb": {
                    "post": {
                        "operationId": "create",
                        "parameters": [
                            {
                                "name": "payload",
                                "in": "body",
                                "schema": {
                                    "description": "BB",
                                    "type": "object"
                                }
                            }
                        ],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        }));

        let aa = &options.openapi["paths"]["/aa"]["post"]["requestBody"]["content"]
            ["application/json"]["schema"]["description"];
        let bb = &options.openapi["paths"]["/bb"]["post"]["requestBody"]["content"]
            ["application/json"]["schema"]["description"];
        assert_eq!(aa, "Aa");
        assert_eq!(bb, "BB");
        assert!(options.openapi["components"].get("requestBodies").is_none());
    }

    #[test]
    fn parameter_ref_decodes_segment_before_sanitise() {
        let options = convert(json!({
            "swagger": "2.0",
            "info": { "title": "Demo", "version": "1.0.0" },
            "parameters": {
                "a b": {
                    "name": "a b",
                    "in": "query",
                    "type": "string"
                }
            },
            "paths": {
                "/p": {
                    "get": {
                        "parameters": [
                            { "$ref": "#/parameters/a%20b" }
                        ],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        }));

        assert_eq!(
            options.openapi["paths"]["/p"]["get"]["parameters"][0]["$ref"],
            "#/components/parameters/a_b"
        );
    }

    #[test]
    fn response_ref_decodes_segment_before_sanitise() {
        let options = convert(json!({
            "swagger": "2.0",
            "info": { "title": "Demo", "version": "1.0.0" },
            "responses": {
                "a b": { "description": "ok" }
            },
            "paths": {
                "/p": {
                    "get": {
                        "responses": {
                            "200": { "$ref": "#/responses/a%20b" }
                        }
                    }
                }
            }
        }));

        assert_eq!(
            options.openapi["paths"]["/p"]["get"]["responses"]["200"]["$ref"],
            "#/components/responses/a_b"
        );
    }

    #[test]
    fn fix_param_ref_decodes_segment_before_sanitise() {
        let mut options = Options::new();
        let mut param = json!({ "$ref": "./defs.json#/parameters/a%20b" });
        fix_param_ref(&mut param, &mut options).unwrap();

        assert_eq!(param["$ref"], "./defs.json#/components/parameters/a_b");
    }

    #[test]
    fn path_body_parameter_creates_operation_request_body() {
        let options = convert(json!({
            "swagger": "2.0",
            "info": { "title": "Demo", "version": "1.0.0" },
            "paths": {
                "/p": {
                    "parameters": [
                        {
                            "name": "payload",
                            "in": "body",
                            "schema": { "type": "object" }
                        }
                    ],
                    "get": {
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        }));

        assert!(options.openapi["paths"]["/p"]["get"]["requestBody"].is_object());
        assert_eq!(
            options.openapi["paths"]["/p"]["parameters"]
                .as_array()
                .map(Vec::len),
            Some(0)
        );
    }

    #[test]
    fn patch_string_operation_produces_sets_response_content() {
        let mut options = Options::new();
        options.patch = true;
        convert_obj(
            &json!({
                "swagger": "2.0",
                "info": { "title": "Demo", "version": "1.0.0" },
                "paths": {
                    "/p": {
                        "get": {
                            "produces": "application/json",
                            "responses": {
                                "200": {
                                    "description": "ok",
                                    "schema": { "type": "object" }
                                }
                            }
                        }
                    }
                }
            }),
            &mut options,
        )
        .unwrap();

        let content = &options.openapi["paths"]["/p"]["get"]["responses"]["200"]["content"];
        assert!(content["application/json"].is_object());
        assert!(content.get("*/*").is_none());
        assert_eq!(options.patches, 1);
    }
}
