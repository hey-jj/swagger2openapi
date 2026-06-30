//! Golden corpus for the converter.
//!
//! Each fixture directory under `tests/fixtures/s2o-test` holds a `swagger.yaml`
//! input and an `openapi.yaml` expected output, plus an optional `options.yaml`.
//! The test parses both, runs the conversion, and compares the produced
//! document against the expected one by structural equality. It lives inside the
//! crate so it can read fixtures through the internal YAML parser without
//! widening the public API.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::convert::convert_obj;
use crate::options::{Options, RefSiblings};
use crate::yaml;

/// Load options from a fixture `options.yaml`, if present.
fn load_options(dir: &Path) -> (Options, bool) {
    let mut options = Options::new();
    options.source = Some(dir.join("swagger.yaml").to_string_lossy().into_owned());
    let mut expect_throw = false;
    if let Ok(text) = fs::read_to_string(dir.join("options.yaml")) {
        let raw: Value = yaml::parse(&text).expect("options.yaml parse");
        if let Some(map) = raw.as_object() {
            if map.get("patch").and_then(Value::as_bool) == Some(true) {
                options.patch = true;
            }
            if map.get("warnOnly").and_then(Value::as_bool) == Some(true) {
                options.warn_only = true;
            }
            if map.get("resolve").and_then(Value::as_bool) == Some(true) {
                options.resolve = true;
            }
            if map.get("resolveInternal").and_then(Value::as_bool) == Some(true) {
                options.resolve_internal = true;
            }
            if map.get("anchors").and_then(Value::as_bool) == Some(true) {
                options.anchors = true;
            }
            if let Some(rb) = map.get("rbname").and_then(Value::as_str) {
                options.rbname = rb.to_string();
            }
            if let Some(rs) = map.get("refSiblings").and_then(Value::as_str) {
                options.ref_siblings = match rs {
                    "preserve" => RefSiblings::Preserve,
                    "allOf" => RefSiblings::AllOf,
                    _ => RefSiblings::Remove,
                };
            }
            if map.get("throws").and_then(Value::as_bool) == Some(true) {
                expect_throw = true;
            }
        }
    }
    (options, expect_throw)
}

/// Run one fixture directory.
fn run_case(dir: &Path) -> Result<(), String> {
    let swagger_text =
        fs::read_to_string(dir.join("swagger.yaml")).map_err(|e| format!("read swagger: {e}"))?;
    let expected_text =
        fs::read_to_string(dir.join("openapi.yaml")).map_err(|e| format!("read openapi: {e}"))?;
    let swagger: Value = yaml::parse(&swagger_text).map_err(|e| format!("parse swagger: {e}"))?;
    let expected: Value = yaml::parse(&expected_text).map_err(|e| format!("parse openapi: {e}"))?;

    let (mut options, expect_throw) = load_options(dir);
    options.had_anchors = yaml::has_alias(&swagger_text);

    match convert_obj(&swagger, &mut options) {
        Ok(()) => {
            if expect_throw {
                return Err("expected an error but conversion succeeded".to_string());
            }
            if options.openapi != expected {
                return Err(format!(
                    "mismatch\n--- expected ---\n{}\n--- actual ---\n{}",
                    serde_json::to_string_pretty(&expected).unwrap(),
                    serde_json::to_string_pretty(&options.openapi).unwrap()
                ));
            }
            Ok(())
        }
        Err(e) => {
            if expect_throw {
                Ok(())
            } else {
                Err(format!("unexpected error: {e}"))
            }
        }
    }
}

/// Directories to skip: shared fragments and private markers.
fn is_skipped(name: &str) -> bool {
    name == "include"
}

#[test]
fn s2o_golden_corpus() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/s2o-test");
    let mut failures: Vec<String> = Vec::new();
    let mut count = 0;

    let mut dirs: Vec<PathBuf> = fs::read_dir(&root)
        .expect("read fixtures root")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();

    for dir in dirs {
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        if is_skipped(&name) {
            continue;
        }
        count += 1;
        if let Err(e) = run_case(&dir) {
            failures.push(format!("[{name}] {e}"));
        }
    }

    assert!(count > 0, "no fixtures discovered");
    if !failures.is_empty() {
        panic!(
            "{} of {} fixtures failed:\n\n{}",
            failures.len(),
            count,
            failures.join("\n\n")
        );
    }
}
