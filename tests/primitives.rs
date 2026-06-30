//! Unit tests for the JSON pointer, clone, recurse, and is_ref primitives.
//!
//! These mirror the canonical primitive test suites. They guard the building
//! blocks that the `$ref` rewriting core depends on.

use serde_json::{json, Value};
use swagger2openapi::clone::clone;
use swagger2openapi::jptr::{get, jpescape, jpunescape, set};
use swagger2openapi::recurse::{is_ref, recurse};

/// The rich fixture object with tricky keys.
fn fixture() -> Value {
    json!({
        "name": "obj",
        "x/y": "x",
        "~": "tilde",
        "#": { "": true },
        "400WithDocument": true,
        "array": ["b"],
        "children": [
            { "$ref": "#/definitions/Child" },
            { "name": "SecondChild", "age": 4 }
        ],
        "definitions": {
            "Child": { "name": "FirstChild", "age": 6 },
            "-": { "value": true }
        }
    })
}

#[test]
fn jptr_custom_and_negative() {
    let obj = fixture();
    assert_eq!(get(&obj, "#/name"), Some(&json!("obj")));
    assert_eq!(get(&obj, "#/name/-"), None); // not an array
    assert_eq!(get(&obj, "#/age"), None);
    assert_eq!(get(&obj, "#/x/y"), None); // x has no member y
    assert_eq!(get(&obj, "#/x~1y"), Some(&json!("x")));
    assert_eq!(get(&obj, "#/~"), Some(&json!("tilde")));
    assert_eq!(get(&obj, "#/~0"), Some(&json!("tilde")));
    assert_eq!(get(&obj, "#/children/1/name"), Some(&json!("SecondChild")));
    assert_eq!(
        get(&obj, "#/children/0/$ref"),
        Some(&json!("#/definitions/Child"))
    );
    assert_eq!(get(&obj, "#/children/2"), None);
    assert_eq!(get(&obj, "#/400WithDocument"), Some(&json!(true)));
    assert_eq!(get(&obj, "#/definitions/-/value"), Some(&json!(true)));
}

#[test]
fn jptr_set_creates_paths() {
    let mut obj = fixture();
    assert_eq!(
        set(&mut obj, "#/not/there/yet", json!("hello")),
        Some(json!("hello"))
    );
    assert_eq!(get(&obj, "#/not/there/yet"), Some(&json!("hello")));
    set(&mut obj, "#/newly/created/0", json!("goodbye"));
    assert!(get(&obj, "#/newly/created").unwrap().is_array());
    set(&mut obj, "#/newly/made/-", json!("sailor"));
    assert!(get(&obj, "#/newly/made").unwrap().is_array());
}

#[test]
fn jptr_array_mutation() {
    let mut obj = fixture();
    assert_eq!(get(&obj, "#/array/0"), Some(&json!("b")));
    set(&mut obj, "#/array/0", json!("c"));
    assert_eq!(get(&obj, "#/array/0"), Some(&json!("c")));
    assert_eq!(get(&obj, "#/array/1"), None);
    set(&mut obj, "#/array/-", json!("d"));
    assert_eq!(get(&obj, "#/array/1"), Some(&json!("d")));
}

#[test]
fn jptr_undefined_obj() {
    // An undefined value is modeled as the absence of a value, which yields a
    // miss for any pointer.
    let obj = Value::Null;
    assert_eq!(get(&obj, "#/anything"), None);
}

#[test]
fn jptr_rfc6901() {
    let doc = json!({
        "foo": ["bar", "baz"],
        "": 0,
        "a/b": 1,
        "c%d": 2,
        "e^f": 3,
        "g|h": 4,
        "i\\j": 5,
        "k\"l": 6,
        " ": 7,
        "m~n": 8
    });
    assert_eq!(get(&doc, ""), Some(&doc));
    assert_eq!(get(&doc, "/foo"), Some(&json!(["bar", "baz"])));
    assert_eq!(get(&doc, "/foo/0"), Some(&json!("bar")));
    assert_eq!(get(&doc, "/"), Some(&json!(0)));
    assert_eq!(get(&doc, "/a~1b"), Some(&json!(1)));
    assert_eq!(get(&doc, "/c%d"), Some(&json!(2)));
    assert_eq!(get(&doc, "/e^f"), Some(&json!(3)));
    assert_eq!(get(&doc, "/g|h"), Some(&json!(4)));
    assert_eq!(get(&doc, "/i\\j"), Some(&json!(5)));
    assert_eq!(get(&doc, "/k\"l"), Some(&json!(6)));
    assert_eq!(get(&doc, "/ "), Some(&json!(7)));
    assert_eq!(get(&doc, "/m~0n"), Some(&json!(8)));
}

#[test]
fn jptr_json_reference_rfc6901() {
    let doc = json!({
        "foo": ["bar", "baz"],
        "": 0,
        "c%d": 2,
        "e^f": 3,
        "g|h": 4,
        " ": 7,
        "m~n": 8
    });
    assert_eq!(get(&doc, "#"), Some(&doc));
    assert_eq!(get(&doc, "#/foo/0"), Some(&json!("bar")));
    assert_eq!(get(&doc, "#/"), Some(&json!(0)));
    assert_eq!(get(&doc, "#/c%25d"), Some(&json!(2)));
    assert_eq!(get(&doc, "#/e%5Ef"), Some(&json!(3)));
    assert_eq!(get(&doc, "#/g%7Ch"), Some(&json!(4)));
    assert_eq!(get(&doc, "#/%20"), Some(&json!(7)));
    assert_eq!(get(&doc, "#/m~0n"), Some(&json!(8)));
}

#[test]
fn jptr_endpointer() {
    let obj = fixture();
    assert_eq!(get(&obj, "/#/"), None); // external reference to uri /
    assert_eq!(get(&obj, "#/%23/"), Some(&json!(true))); // %-encoded # in fragment
}

#[test]
fn jptr_top_level_mutation() {
    let mut o = json!({ "hello": "sailor" });
    let n = json!({ "hello": "dolly" });
    assert_eq!(set(&mut o, "", n.clone()), Some(n.clone()));
    assert_eq!(o, n);
}

#[test]
fn escape_round_trip() {
    assert_eq!(jpescape("a/b~c"), "a~1b~0c");
    assert_eq!(jpunescape("a~1b~0c"), "a/b~c");
}

#[test]
fn clone_is_deep() {
    let input = json!({ "container": { "child": { "value": true } } });
    let output = clone(&input);
    assert_eq!(output, input);
}

#[test]
fn recurse_visits_every_property() {
    let input = json!({ "container": { "child": { "value": true } } });
    let mut count = 0;
    let mut v = input;
    recurse(&mut v, "#", 0, &mut |_, _, _| count += 1);
    assert_eq!(count, 3);
}

#[test]
fn is_ref_basic() {
    let simple = json!({ "$ref": "#/" });
    let extended = json!({ "$ref": "#/", "description": "desc" });
    let wrong_type = json!({ "$ref": true });
    assert!(is_ref(&simple, "$ref"));
    assert!(is_ref(&extended, "$ref"));
    assert!(!is_ref(&simple, "description"));
    assert!(!is_ref(&extended, "description"));
    assert!(!is_ref(&wrong_type, "$ref"));
    assert!(!is_ref(&Value::Null, "$ref"));
}
