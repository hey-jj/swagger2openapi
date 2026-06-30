//! Behavior tests for the entry points and options not covered by the corpus.
//!
//! These exercise the string, file, and stream wrappers, the version gate,
//! target version override, the pass-through path, duplicate name collisions,
//! request body markers, and the warn-only property.

use std::io::Cursor;

use serde_json::{json, Value};
use swagger2openapi::{
    convert_file, convert_obj, convert_str, convert_stream, Options, RefSiblings,
};

/// Minimal valid Swagger 2.0 document as a value.
fn minimal() -> Value {
    json!({
        "swagger": "2.0",
        "info": { "title": "Demo", "version": "1.0.0" },
        "paths": {}
    })
}

#[test]
fn convert_str_accepts_json() {
    let mut options = Options::new();
    convert_str(&minimal().to_string(), &mut options).unwrap();
    assert_eq!(options.openapi["openapi"], "3.0.0");
    assert!(!options.source_yaml);
}

#[test]
fn convert_str_accepts_yaml() {
    let text = "swagger: '2.0'\ninfo:\n  title: Demo\n  version: '1.0.0'\npaths: {}\n";
    let mut options = Options::new();
    convert_str(text, &mut options).unwrap();
    assert_eq!(options.openapi["openapi"], "3.0.0");
    assert!(options.source_yaml);
}

#[test]
fn convert_str_rejects_garbage() {
    let mut options = Options::new();
    let err = convert_str("\t this: : is: not: yaml: [", &mut options).unwrap_err();
    assert!(!err.message.is_empty());
}

#[test]
fn convert_file_missing_is_error() {
    let mut options = Options::new();
    let err = convert_file("/no/such/file.yaml", &mut options).unwrap_err();
    assert!(err.message.contains("/no/such/file.yaml"));
}

#[test]
fn convert_stream_matches_str() {
    let text = minimal().to_string();
    let mut from_stream = Options::new();
    convert_stream(Cursor::new(text.clone()), &mut from_stream).unwrap();
    let mut from_str = Options::new();
    convert_str(&text, &mut from_str).unwrap();
    assert_eq!(from_stream.openapi, from_str.openapi);
}

#[test]
fn target_version_override() {
    let mut options = Options::new();
    options.target_version = Some("3.0.3".to_string());
    convert_obj(&minimal(), &mut options).unwrap();
    assert_eq!(options.openapi["openapi"], "3.0.3");
}

#[test]
fn junk_target_version_falls_back() {
    let mut options = Options::new();
    options.target_version = Some("nonsense".to_string());
    convert_obj(&minimal(), &mut options).unwrap();
    assert_eq!(options.openapi["openapi"], "3.0.0");
}

#[test]
fn unsupported_version_errors() {
    let mut options = Options::new();
    let input = json!({ "swagger": "1.2", "info": {}, "paths": {} });
    let err = convert_obj(&input, &mut options).unwrap_err();
    assert!(err.message.contains("Unsupported swagger/OpenAPI version"));
}

#[test]
fn missing_version_errors() {
    let mut options = Options::new();
    let input = json!({ "info": {}, "paths": {} });
    let err = convert_obj(&input, &mut options).unwrap_err();
    assert!(err.message.contains("Unsupported swagger/OpenAPI version"));
}

#[test]
fn swagger_two_as_number_is_accepted() {
    let mut options = Options::new();
    let input = json!({
        "swagger": 2.0,
        "info": { "title": "Demo", "version": "1.0.0" },
        "paths": {}
    });
    convert_obj(&input, &mut options).unwrap();
    assert_eq!(options.openapi["openapi"], "3.0.0");
}

#[test]
fn oas3_passthrough() {
    let mut options = Options::new();
    let input = json!({
        "openapi": "3.0.0",
        "info": { "title": "Demo", "version": "1.0.0" },
        "paths": {}
    });
    convert_obj(&input, &mut options).unwrap();
    assert_eq!(options.openapi, input);
}

#[test]
fn duplicate_sanitised_schema_names_collide_into_suffix() {
    // Two definitions that sanitise to the same base get distinct suffixes.
    let mut options = Options::new();
    let input = json!({
        "swagger": "2.0",
        "info": { "title": "Demo", "version": "1.0.0" },
        "paths": {},
        "definitions": {
            "Foo Bar": { "type": "object" },
            "Foo/Bar": { "type": "string" }
        }
    });
    convert_obj(&input, &mut options).unwrap();
    let schemas = options.openapi["components"]["schemas"]
        .as_object()
        .unwrap();
    assert!(schemas.contains_key("Foo_Bar"));
    assert!(schemas.contains_key("Foo_Bar2"));
}

#[test]
fn duplicate_sanitised_security_scheme_errors() {
    let mut options = Options::new();
    let input = json!({
        "swagger": "2.0",
        "info": { "title": "Demo", "version": "1.0.0" },
        "paths": {},
        "securityDefinitions": {
            "a b": { "type": "apiKey", "name": "k", "in": "header" },
            "a_b": { "type": "apiKey", "name": "k", "in": "header" }
        }
    });
    let err = convert_obj(&input, &mut options).unwrap_err();
    assert!(err
        .message
        .contains("Duplicate sanitised securityScheme name"));
}

#[test]
fn body_param_becomes_request_body_without_markers() {
    let mut options = Options::new();
    let input = json!({
        "swagger": "2.0",
        "info": { "title": "Demo", "version": "1.0.0" },
        "paths": {
            "/p": {
                "post": {
                    "operationId": "addThing",
                    "parameters": [
                        { "name": "body", "in": "body", "schema": { "type": "object" } }
                    ],
                    "responses": { "200": { "description": "ok" } }
                }
            }
        }
    });
    convert_obj(&input, &mut options).unwrap();
    let op = &options.openapi["paths"]["/p"]["post"];
    assert!(op["requestBody"].is_object());
    // The body parameter is removed and no x-s2o markers survive.
    let dumped = serde_json::to_string(&options.openapi).unwrap();
    assert!(!dumped.contains("x-s2o-delete"));
    assert!(!dumped.contains("x-s2o-name"));
}

#[test]
fn rbname_records_body_name_without_patch() {
    let mut options = Options::new();
    options.rbname = "x-codegen-request-body-name".to_string();
    let input = json!({
        "swagger": "2.0",
        "info": { "title": "Demo", "version": "1.0.0" },
        "paths": {
            "/p": {
                "post": {
                    "operationId": "addThing",
                    "parameters": [
                        { "name": "payload", "in": "body", "schema": { "type": "object" } }
                    ],
                    "responses": { "200": { "description": "ok" } }
                }
            }
        }
    });
    convert_obj(&input, &mut options).unwrap();
    let op = &options.openapi["paths"]["/p"]["post"];
    assert_eq!(op["x-codegen-request-body-name"], "payload");
}

#[test]
fn warn_property_override_records_warning() {
    // A tsv collectionFormat on a response header writes a warning into the
    // header, which is not a $ref, so the warning survives in the output.
    let mut options = Options::new();
    options.warn_only = true;
    options.warn_property = "x-my-warning".to_string();
    let input = json!({
        "swagger": "2.0",
        "info": { "title": "Demo", "version": "1.0.0" },
        "paths": {
            "/p": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "ok",
                            "headers": {
                                "X-Thing": {
                                    "type": "array",
                                    "collectionFormat": "tsv",
                                    "items": { "type": "string" }
                                }
                            }
                        }
                    }
                }
            }
        }
    });
    convert_obj(&input, &mut options).unwrap();
    let header = &options.openapi["paths"]["/p"]["get"]["responses"]["200"]["headers"]["X-Thing"];
    assert_eq!(
        header["x-my-warning"],
        "collectionFormat:tsv is no longer supported"
    );
    assert!(header.get("x-s2o-warning").is_none());
}

#[test]
fn warn_only_prevents_error_on_missing_ref() {
    // Without warn_only this missing parameter $ref would error.
    let mut options = Options::new();
    options.warn_only = true;
    let input = json!({
        "swagger": "2.0",
        "info": { "title": "API", "version": "1.0.0" },
        "paths": {
            "/": {
                "get": {
                    "parameters": [ { "$ref": "#/parameters/notthere" } ],
                    "responses": { "200": { "description": "OK" } }
                }
            }
        }
    });
    convert_obj(&input, &mut options).unwrap();
    assert_eq!(options.openapi["openapi"], "3.0.0");
}

#[test]
fn ref_siblings_remove_is_default() {
    assert_eq!(Options::new().ref_siblings, RefSiblings::Remove);
}

#[test]
fn null_swagger_defaults_then_rejects() {
    let mut options = Options::new();
    let err = convert_obj(&Value::Null, &mut options).unwrap_err();
    assert!(err.message.contains("Unsupported swagger/OpenAPI version"));
}
