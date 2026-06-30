//! External `$ref` resolution.
//!
//! [`optional_resolve`] is a no-op unless `options.resolve` is set. With resolve
//! on, it walks the document for non-fragment `$ref` strings, reads each target
//! from disk relative to `options.source`, resolves the requested fragment,
//! rewrites the target's own internal `$ref`s, and writes the result back into
//! the document. Repeated targets become `$ref`s to the first copy.
//!
//! Only file targets are handled here. The internal-rewrite logic mirrors the
//! multi-pass resolver so the conversion that follows sees the same shapes.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::clone::clone;
use crate::error::S2OError;
use crate::jptr;
use crate::options::Options;
use crate::recurse::{is_ref, recurse};
use crate::yaml;

/// Resolve external references when `options.resolve` is set.
///
/// Returns `Ok(())` after rewriting `options.openapi` in place. With resolve off
/// this returns immediately.
pub fn optional_resolve(options: &mut Options) -> Result<(), S2OError> {
    if !options.resolve {
        return Ok(());
    }

    let base = options
        .source
        .clone()
        .ok_or_else(|| S2OError::new("resolve requires options.source"))?;

    // Iterate to a fixed point. Each pass resolves the external refs found and
    // may expose new ones inside the inlined data.
    loop {
        let refs = scan_external_refs(&options.openapi);
        if refs.is_empty() {
            break;
        }
        let mut changed = false;
        for reference in refs {
            if resolve_one(options, &reference, &base)? {
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    Ok(())
}

/// Collect non-fragment `$ref` strings paired with the paths that hold them.
///
/// Paths are kept in document order. The first path becomes the attach point.
fn scan_external_refs(openapi: &Value) -> Vec<ExternalRef> {
    let mut order: Vec<String> = Vec::new();
    let mut paths: BTreeMap<String, Vec<String>> = BTreeMap::new();

    let mut doc = openapi.clone();
    recurse(&mut doc, "#", 0, &mut |obj, key, state| {
        if is_ref(obj, key) {
            if let Some(Value::String(s)) = obj.get(key) {
                if !s.starts_with('#') {
                    let entry = paths.entry(s.clone()).or_insert_with(|| {
                        order.push(s.clone());
                        Vec::new()
                    });
                    // The path of the ref string is the key path. The container
                    // holding the ref sits one level up, which is the parent of
                    // this key.
                    entry.push(parent_path(&state.path));
                }
            }
        }
    });

    order
        .into_iter()
        .map(|r| ExternalRef {
            paths: paths.remove(&r).unwrap_or_default(),
            reference: r,
        })
        .collect()
}

/// Drop the last `/segment` of a recurse path to address the container.
fn parent_path(path: &str) -> String {
    match path.rfind('/') {
        Some(idx) if idx > 0 => path[..idx].to_string(),
        _ => path.to_string(),
    }
}

/// One external reference and the document paths that point at it.
struct ExternalRef {
    reference: String,
    paths: Vec<String>,
}

/// Resolve a single external reference, writing data back into the document.
///
/// Returns whether any change was made.
fn resolve_one(options: &mut Options, ext: &ExternalRef, base: &str) -> Result<bool, S2OError> {
    let (file, fragment) = split_fragment(&ext.reference);
    let base_dir = parent_dir(base);
    let target = base_dir.join(&file);

    let text = std::fs::read_to_string(&target)
        .map_err(|e| S2OError::new(format!("could not read {}: {e}", target.display())))?;
    let context = yaml::parse(&text)?;

    let mut data = if fragment.is_empty() {
        context.clone()
    } else {
        jptr::get(&context, &fragment)
            .cloned()
            .unwrap_or(Value::Object(Default::default()))
    };

    let attach_point = ext
        .paths
        .first()
        .cloned()
        .unwrap_or_else(|| "#".to_string());
    resolve_all_internal(&mut data, &context, &attach_point);

    // Rewrite nested external refs so the next pass reads them from the right
    // directory. Each becomes a path relative to the original source.
    let base_dir_canon = base_dir.clone();
    rewrite_nested_external_refs(&mut data, &target, &base_dir_canon);

    // Sort the paths by length so the shortest becomes the canonical copy.
    let mut pointers: Vec<String> = unique(&ext.paths);
    pointers.sort_by_key(|p| p.len());

    let mut resolved_at: Option<String> = None;
    for ptr in &pointers {
        match &resolved_at {
            Some(at) if at != ptr => {
                let mut ref_obj = serde_json::Map::new();
                ref_obj.insert("$ref".to_string(), Value::String(at.clone()));
                jptr::set(&mut options.openapi, ptr, Value::Object(ref_obj));
            }
            Some(_) => {}
            None => {
                resolved_at = Some(ptr.clone());
                jptr::set(&mut options.openapi, ptr, clone(&data));
            }
        }
    }

    Ok(true)
}

/// Resolve the internal `$ref`s of an inlined external fragment.
///
/// A first-seen internal ref is replaced by a clone of its target. A repeat ref
/// becomes a pointer into the already-placed copy, anchored at `attach_point`.
fn resolve_all_internal(obj: &mut Value, context: &Value, attach_point: &str) {
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    loop {
        let mut changed = false;
        recurse(obj, "#", 0, &mut |container, key, state| {
            if !is_ref(container, key) {
                return;
            }
            let ref_str = match container.get(key) {
                Some(Value::String(s)) if s.starts_with('#') => s.clone(),
                _ => return,
            };
            let fixed = container
                .get("$fixed")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if fixed {
                return;
            }
            match seen.get(&ref_str) {
                None => {
                    if let Some(target) = jptr::get(context, &ref_str).cloned() {
                        *container = target;
                        let here = state.path.replace("/%24ref", "");
                        seen.insert(ref_str, here);
                        changed = true;
                    } else {
                        *container = Value::Object(Default::default());
                    }
                }
                Some(here) => {
                    let replacement = format!("{attach_point}/{here}");
                    let new_ref = replacement.replace("/#/", "/");
                    let mut m = serde_json::Map::new();
                    m.insert("$ref".to_string(), Value::String(new_ref));
                    m.insert("x-miro".to_string(), Value::String(ref_str.clone()));
                    m.insert("$fixed".to_string(), Value::Bool(true));
                    *container = Value::Object(m);
                    changed = true;
                }
            }
        });
        if !changed {
            break;
        }
    }

    // Drop the temporary $fixed markers.
    recurse(obj, "#", 0, &mut |container, key, _| {
        if is_ref(container, key) {
            if let Some(map) = container.as_object_mut() {
                map.remove("$fixed");
            }
        }
    });
}

/// Rewrite nested external refs to be relative to the original source.
///
/// A ref like `./subdir2/ok.yaml` inside a file at `dir/test.yaml` becomes
/// `dir/subdir2/ok.yaml` so the next resolution pass reads the correct file.
fn rewrite_nested_external_refs(data: &mut Value, target_file: &Path, base_dir: &Path) {
    let target_dir = target_file
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    recurse(data, "#", 0, &mut |obj, key, _| {
        if !is_ref(obj, key) {
            return;
        }
        let Some(Value::String(s)) = obj.get(key) else {
            return;
        };
        if s.starts_with('#') {
            return;
        }
        let (file, fragment) = split_fragment(s);
        let resolved = target_dir.join(&file);
        let rel = relative_to(&resolved, base_dir);
        let new_ref = format!("{rel}{fragment}");
        if let Some(map) = obj.as_object_mut() {
            map.insert(key.to_string(), Value::String(new_ref));
        }
    });
}

/// Express `path` relative to `base`, falling back to a lexical join.
fn relative_to(path: &Path, base: &Path) -> String {
    // Normalise both lexically, then strip the shared base prefix.
    let path_n = normalise(path);
    let base_n = normalise(base);
    if let Ok(stripped) = path_n.strip_prefix(&base_n) {
        return stripped.to_string_lossy().into_owned();
    }
    path_n.to_string_lossy().into_owned()
}

/// Collapse `.` and `..` segments lexically.
fn normalise(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Split a reference into its file part and fragment (without the leading `#`).
fn split_fragment(reference: &str) -> (String, String) {
    match reference.split_once('#') {
        Some((file, frag)) => (file.to_string(), format!("#{frag}")),
        None => (reference.to_string(), String::new()),
    }
}

/// Directory holding `path`.
fn parent_dir(path: &str) -> PathBuf {
    Path::new(path)
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Deduplicate while preserving order.
fn unique(items: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for i in items {
        if !out.contains(i) {
            out.push(i.clone());
        }
    }
    out
}
