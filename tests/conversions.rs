//! Focused conversion tests beyond the golden corpus.
//!
//! Each case locks down a behavior the corpus does not exercise: the Azure
//! `x-ms-*` conversions, the version gate edges, security scheme conversion,
//! schema extension fixups, duplicate-name errors, URL validation,
//! collectionFormat handling, type-array and items fixups, and server variable
//! extraction. The expected values are checked against the conversion algorithm.

use serde_json::{json, Value};
use swagger2openapi::{convert_obj, Options};

/// Convert a value with default options, returning the document or the error.
fn convert(input: Value) -> Result<Value, String> {
    convert_with(input, false)
}

/// Convert with an explicit patch flag.
fn convert_with(input: Value, patch: bool) -> Result<Value, String> {
    let mut options = Options::new();
    options.patch = patch;
    convert_obj(&input, &mut options)
        .map(|()| options.openapi)
        .map_err(|e| e.message)
}

/// Wrap a Swagger 2.0 skeleton around `extra` top-level members.
fn doc(extra: Value) -> Value {
    let mut base = json!({
        "swagger": "2.0",
        "info": { "title": "T", "version": "1" },
        "paths": {}
    });
    if let (Some(b), Some(e)) = (base.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            b.insert(k.clone(), v.clone());
        }
    }
    base
}

// --- #7 x-ms-parameterized-host ------------------------------------------

#[test]
fn parameterized_host_builds_one_server_without_scheme_prefix() {
    let out = convert(doc(json!({
        "schemes": ["https"],
        "x-ms-parameterized-host": {
            "hostTemplate": "{accountName}.example.com",
            "useSchemePrefix": false,
            "parameters": [
                { "name": "accountName", "in": "host", "required": true, "type": "string" }
            ]
        }
    })))
    .unwrap();
    assert_eq!(
        out["servers"],
        json!([{
            "url": "{accountName}.example.com",
            "variables": { "accountName": { "default": "none" } }
        }])
    );
    assert!(out.get("x-ms-parameterized-host").is_none());
}

#[test]
fn parameterized_host_prefixes_each_scheme() {
    // basePath alone first yields a {url: basePath} server. The parameterized
    // host then appends one prefixed server per scheme. The default comes from
    // the first enum value.
    let out = convert(doc(json!({
        "basePath": "/v1",
        "schemes": ["http", "https"],
        "x-ms-parameterized-host": {
            "hostTemplate": "{region}.example.com",
            "parameters": [
                { "name": "region", "in": "host", "required": true, "type": "string",
                  "enum": ["us", "eu"] }
            ]
        }
    })))
    .unwrap();
    assert_eq!(
        out["servers"],
        json!([
            { "url": "/v1" },
            {
                "url": "http://{region}.example.com/v1",
                "variables": { "region": { "enum": ["us", "eu"], "default": "us" } }
            },
            {
                "url": "https://{region}.example.com/v1",
                "variables": { "region": { "enum": ["us", "eu"], "default": "us" } }
            }
        ])
    );
}

// --- #8 x-ms-examples -----------------------------------------------------

#[test]
fn ms_examples_map_onto_parameters_and_responses() {
    let out = convert(doc(json!({
        "paths": { "/p": { "get": {
            "operationId": "getP",
            "parameters": [ { "name": "q", "in": "query", "type": "string" } ],
            "responses": { "200": { "description": "ok", "schema": { "type": "object" } } },
            "x-ms-examples": { "Ex 1": {
                "parameters": { "q": "hello" },
                "responses": { "200": { "body": { "a": 1 } } }
            } }
        } } }
    })))
    .unwrap();
    let op = &out["paths"]["/p"]["get"];
    assert_eq!(
        op["parameters"][0]["examples"]["Ex 1"],
        json!({ "value": "hello" })
    );
    // The body lands under components.examples keyed by the sanitised name.
    assert_eq!(
        out["components"]["examples"]["Ex_1"],
        json!({ "value": { "a": 1 } })
    );
    // Each content type references the shared example by the raw key.
    assert_eq!(
        op["responses"]["200"]["content"]["*/*"]["examples"]["Ex 1"],
        json!({ "$ref": "#/components/examples/Ex_1" })
    );
    assert!(op.get("x-ms-examples").is_none());
}

#[test]
fn ms_examples_set_response_header_example() {
    let out = convert(doc(json!({
        "paths": { "/p": { "get": {
            "operationId": "getP",
            "responses": { "200": { "description": "ok",
                "headers": { "X-Rate": { "type": "string" } } } },
            "x-ms-examples": { "Ex": {
                "responses": { "200": { "headers": { "X-Rate": "42" } } }
            } }
        } } }
    })))
    .unwrap();
    let header = &out["paths"]["/p"]["get"]["responses"]["200"]["headers"]["X-Rate"];
    assert_eq!(header["example"], json!("42"));
}

// --- #16 version gate -----------------------------------------------------

#[test]
fn numeric_swagger_two_is_accepted() {
    // The version gate compares loosely, so a numeric 2.0 and the integer 2
    // both satisfy it the same way the string "2.0" does.
    assert_eq!(
        convert(doc(json!({ "swagger": 2.0 }))).unwrap()["openapi"],
        "3.0.0"
    );
    let mut int_two = doc(json!({}));
    int_two["swagger"] = json!(2);
    assert_eq!(convert(int_two).unwrap()["openapi"], "3.0.0");
}

#[test]
fn near_miss_versions_are_rejected() {
    for bad in [json!(2.5), json!("2"), json!("2.0.0")] {
        let mut input = doc(json!({}));
        input["swagger"] = bad.clone();
        let err = convert(input).unwrap_err();
        assert!(
            err.contains("Unsupported swagger/OpenAPI version"),
            "expected reject for {bad}, got {err}"
        );
    }
}

// --- #17 oauth2 security scheme ------------------------------------------

#[test]
fn oauth2_flow_rename_and_url_trim() {
    let out = convert(doc(json!({
        "securityDefinitions": { "oa": {
            "type": "oauth2", "flow": "accessCode",
            "authorizationUrl": "https://ex/auth?x=1",
            "tokenUrl": "https://ex/token?y=2",
            "scopes": { "read": "r" }
        } }
    })))
    .unwrap();
    assert_eq!(
        out["components"]["securitySchemes"]["oa"],
        json!({ "type": "oauth2", "flows": { "authorizationCode": {
            "authorizationUrl": "https://ex/auth",
            "tokenUrl": "https://ex/token",
            "scopes": { "read": "r" }
        } } })
    );
}

#[test]
fn oauth2_query_only_url_collapses_to_slash() {
    let out = convert(doc(json!({
        "securityDefinitions": { "oa": {
            "type": "oauth2", "flow": "application", "tokenUrl": "?onlyquery", "scopes": {}
        } }
    })))
    .unwrap();
    assert_eq!(
        out["components"]["securitySchemes"]["oa"]["flows"]["clientCredentials"]["tokenUrl"],
        "/"
    );
}

#[test]
fn basic_scheme_becomes_http_basic() {
    let out = convert(doc(json!({
        "securityDefinitions": { "b": { "type": "basic" } }
    })))
    .unwrap();
    assert_eq!(
        out["components"]["securitySchemes"]["b"],
        json!({ "type": "http", "scheme": "basic" })
    );
}

#[test]
fn oauth2_with_name_errors_without_patch() {
    let err = convert(doc(json!({
        "securityDefinitions": { "oa": {
            "type": "oauth2", "flow": "accessCode",
            "authorizationUrl": "https://ex/a", "tokenUrl": "https://ex/t",
            "scopes": {}, "name": "x"
        } }
    })))
    .unwrap_err();
    assert_eq!(
        err,
        "(Patchable) oauth2 securitySchemes should not have name property"
    );
}

// --- #18 schema extension fixups -----------------------------------------

#[test]
fn schema_extensions_promote_to_keywords() {
    let out = convert(doc(json!({
        "definitions": { "Foo": {
            "type": "object",
            "x-anyOf": [ { "type": "string" }, { "type": "number" } ],
            "x-required": ["a", "b"],
            "x-nullable": true,
            "properties": { "a": { "type": "string" } }
        } }
    })))
    .unwrap();
    assert_eq!(
        out["components"]["schemas"]["Foo"],
        json!({
            "type": "object",
            "properties": { "a": { "type": "string" } },
            "required": ["a", "b"],
            "anyOf": [ { "type": "string" }, { "type": "number" } ],
            "nullable": true
        })
    );
}

#[test]
fn discriminator_mapping_rewrites_definition_pointers() {
    let out = convert(doc(json!({
        "definitions": { "Pet": {
            "type": "object",
            "x-discriminator": {
                "propertyName": "kind",
                "mapping": { "cat": "#/definitions/Cat" }
            }
        }, "Cat": { "type": "object" } }
    })))
    .unwrap();
    assert_eq!(
        out["components"]["schemas"]["Pet"]["discriminator"],
        json!({ "propertyName": "kind", "mapping": { "cat": "#/components/schemas/Cat" } })
    );
}

// --- #19 duplicate sanitised names ---------------------------------------

#[test]
fn duplicate_parameter_name_errors() {
    let err = convert(doc(json!({
        "parameters": {
            "a b": { "name": "x", "in": "query", "type": "string" },
            "a_b": { "name": "y", "in": "query", "type": "string" }
        }
    })))
    .unwrap_err();
    assert_eq!(err, "Duplicate sanitised parameter name a_b");
}

#[test]
fn duplicate_response_name_errors() {
    let err = convert(doc(json!({
        "responses": { "a b": { "description": "d1" }, "a_b": { "description": "d2" } }
    })))
    .unwrap_err();
    assert_eq!(err, "Duplicate sanitised response name a_b");
}

// --- #20 origin, odata, logo, termsOfService -----------------------------

#[test]
fn origin_provenance_is_recorded() {
    let mut options = Options::new();
    options.origin = true;
    options.source = Some("http://ex/api.json".to_string());
    convert_obj(&doc(json!({})), &mut options).unwrap();
    assert_eq!(
        options.openapi["x-origin"],
        json!([{
            "url": "http://ex/api.json",
            "format": "swagger",
            "version": "2.0",
            "converter": { "url": "https://github.com/mermade/oas-kit", "version": "7.0.8" }
        }])
    );
}

#[test]
fn ms_odata_pointer_is_rewritten() {
    let out = convert(doc(json!({
        "definitions": {
            "Foo": { "type": "object", "x-ms-odata": "#/definitions/Bar" },
            "Bar": { "type": "object" }
        }
    })))
    .unwrap();
    assert_eq!(
        out["components"]["schemas"]["Foo"]["x-ms-odata"],
        "#/components/schemas/Bar"
    );
}

#[test]
fn logo_moves_under_patch_else_errors() {
    let err = convert(doc(
        json!({ "info": { "title": "T", "version": "1", "logo": { "url": "x" } } }),
    ))
    .unwrap_err();
    assert_eq!(err, "(Patchable) info should not have logo property");

    let out = convert_with(
        doc(json!({ "info": { "title": "T", "version": "1", "logo": { "url": "x" } } })),
        true,
    )
    .unwrap();
    assert_eq!(out["info"]["x-logo"], json!({ "url": "x" }));
    assert!(out["info"].get("logo").is_none());
}

#[test]
fn terms_of_service_url_validation() {
    for ok in [
        "mailto:a@b.com",
        "urn:isbn:123",
        "foo://bar",
        "http://ex.com",
    ] {
        let out = convert(doc(json!({
            "info": { "title": "T", "version": "1", "termsOfService": ok }
        })))
        .unwrap();
        assert_eq!(out["info"]["termsOfService"], ok);
    }
    for bad in ["example.com", "not a url"] {
        let err = convert(doc(json!({
            "info": { "title": "T", "version": "1", "termsOfService": bad }
        })))
        .unwrap_err();
        assert_eq!(err, "(Patchable) info.termsOfService must be a URL");
    }
    // Under patch the bad value is dropped.
    let out = convert_with(
        doc(json!({ "info": { "title": "T", "version": "1", "termsOfService": "example.com" } })),
        true,
    )
    .unwrap();
    assert!(out["info"].get("termsOfService").is_none());
}

// --- #21 collectionFormat -------------------------------------------------

#[test]
fn param_tsv_errors_without_warn_only() {
    let err = convert(doc(json!({
        "paths": { "/p": { "get": {
            "parameters": [ { "name": "q", "in": "query", "type": "array",
                "items": { "type": "string" }, "collectionFormat": "tsv" } ],
            "responses": { "200": { "description": "ok" } }
        } } }
    })))
    .unwrap_err();
    assert_eq!(err, "collectionFormat:tsv is no longer supported");
}

#[test]
fn param_tsv_under_warn_only_records_marker() {
    let mut options = Options::new();
    options.warn_only = true;
    convert_obj(
        &doc(json!({
            "paths": { "/p": { "get": {
                "parameters": [ { "name": "q", "in": "query", "type": "array",
                    "items": { "type": "string" }, "collectionFormat": "tsv" } ],
                "responses": { "200": { "description": "ok" } }
            } } }
        })),
        &mut options,
    )
    .unwrap();
    let param = &options.openapi["paths"]["/p"]["get"]["parameters"][0];
    assert_eq!(param["x-collectionFormat"], "tsv");
}

/// Build a response with one array-typed header carrying `cf`.
///
/// The header has no nested `items`, so only the array collectionFormat branch
/// runs. A header that pairs a collectionFormat with a mismatched nested items
/// format triggers a separate "Nested collectionFormats" error instead.
fn header_doc(cf: &str) -> Value {
    doc(json!({
        "paths": { "/p": { "get": { "responses": { "200": {
            "description": "ok",
            "headers": { "X": { "type": "array", "collectionFormat": cf } }
        } } } } }
    }))
}

#[test]
fn header_collection_formats() {
    // multi -> explode, csv -> style simple.
    for (cf, key, value) in [
        ("multi", "explode", json!(true)),
        ("csv", "style", json!("simple")),
    ] {
        let out = convert(header_doc(cf)).unwrap();
        let header = &out["paths"]["/p"]["get"]["responses"]["200"]["headers"]["X"];
        assert_eq!(header[key], value, "cf={cf}");
        assert!(header.get("collectionFormat").is_none());
    }
    // ssv and pipes error on headers.
    for (cf, msg) in [
        (
            "ssv",
            "collectionFormat:ssv is no longer supported for headers",
        ),
        (
            "pipes",
            "collectionFormat:pipes is no longer supported for headers",
        ),
    ] {
        assert_eq!(convert(header_doc(cf)).unwrap_err(), msg);
    }
    // tsv errors and records the marker under warn_only.
    assert_eq!(
        convert(header_doc("tsv")).unwrap_err(),
        "collectionFormat:tsv is no longer supported"
    );
    let mut options = Options::new();
    options.warn_only = true;
    convert_obj(&header_doc("tsv"), &mut options).unwrap();
    let header = &options.openapi["paths"]["/p"]["get"]["responses"]["200"]["headers"]["X"];
    assert_eq!(header["x-collectionFormat"], "tsv");
}

#[test]
fn param_style_and_explode_mapping() {
    // query/cookie csv -> form/explode false; ssv outside query errors.
    let out = convert(doc(json!({
        "paths": { "/p": { "get": {
            "parameters": [ { "name": "q", "in": "query", "type": "array",
                "items": { "type": "string" }, "collectionFormat": "ssv" } ],
            "responses": { "200": { "description": "ok" } }
        } } }
    })))
    .unwrap();
    let param = &out["paths"]["/p"]["get"]["parameters"][0];
    assert_eq!(param["style"], "spaceDelimited");

    let err = convert(doc(json!({
        "paths": { "/p/{q}": { "get": {
            "parameters": [ { "name": "q", "in": "path", "required": true, "type": "array",
                "items": { "type": "string" }, "collectionFormat": "ssv" } ],
            "responses": { "200": { "description": "ok" } }
        } } }
    })))
    .unwrap_err();
    assert_eq!(
        err,
        "collectionFormat:ssv is no longer supported except for in:query parameters"
    );
}

// --- #22 type array and items collapse -----------------------------------

#[test]
fn type_array_with_null_under_patch() {
    let out = convert_with(
        doc(json!({ "definitions": { "Foo": { "type": ["string", "null"], "maxLength": 5 } } })),
        true,
    )
    .unwrap();
    assert_eq!(
        out["components"]["schemas"]["Foo"],
        json!({ "maxLength": 5, "nullable": true, "type": "string" })
    );
}

#[test]
fn type_array_without_patch_errors() {
    let err = convert(doc(json!({
        "definitions": { "Foo": { "type": ["string", "number"] } }
    })))
    .unwrap_err();
    assert_eq!(err, "(Patchable) schema type must not be an array");
}

#[test]
fn items_array_collapses() {
    // length > 1 -> anyOf.
    let out = convert(doc(json!({
        "definitions": { "Foo": { "type": "array",
            "items": [ { "type": "string" }, { "type": "number" } ] } }
    })))
    .unwrap();
    assert_eq!(
        out["components"]["schemas"]["Foo"]["items"],
        json!({ "anyOf": [ { "type": "string" }, { "type": "number" } ] })
    );

    // empty -> {}.
    let out = convert(doc(json!({
        "definitions": { "Foo": { "type": "array", "items": [] } }
    })))
    .unwrap();
    assert_eq!(out["components"]["schemas"]["Foo"]["items"], json!({}));

    // single -> the element.
    let out = convert(doc(json!({
        "definitions": { "Foo": { "type": "array", "items": [ { "type": "string" } ] } }
    })))
    .unwrap();
    assert_eq!(
        out["components"]["schemas"]["Foo"]["items"],
        json!({ "type": "string" })
    );
}

// --- #23 server variables and null-strip ---------------------------------

#[test]
fn server_variables_collapse_doubled_braces() {
    let out = convert(doc(json!({
        "host": "{{region}}.example.com",
        "basePath": "/{{ver}}"
    })))
    .unwrap();
    assert_eq!(
        out["servers"],
        json!([{
            "url": "//{region}.example.com/{ver}",
            "variables": {
                "region": { "default": "unknown" },
                "ver": { "default": "unknown" }
            }
        }])
    );
}

#[test]
fn null_strip_spares_extensions_default_and_example_paths() {
    let out = convert(doc(json!({
        "x-keep": null,
        "default": null,
        "drop": null
    })))
    .unwrap();
    assert!(out.get("x-keep").map(Value::is_null).unwrap_or(false));
    assert!(out.get("default").map(Value::is_null).unwrap_or(false));
    assert!(out.get("drop").is_none());
}

#[test]
fn null_strip_keeps_nulls_under_example_paths() {
    // A response example value of null survives because the path contains
    // "/examples", which matches the "/example" substring guard.
    let out = convert(doc(json!({
        "paths": { "/p": { "get": {
            "responses": { "200": {
                "description": "ok",
                "schema": { "type": "object" },
                "examples": { "application/json": null }
            } }
        } } }
    })))
    .unwrap();
    let examples = &out["paths"]["/p"]["get"]["responses"]["200"]["content"]["application/json"]
        ["examples"]["response"]["value"];
    assert!(examples.is_null());
}
