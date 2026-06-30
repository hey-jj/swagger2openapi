# swagger2openapi

Convert Swagger 2.0 (OpenAPI v2.0) API definitions to OpenAPI 3.0.x.

The crate takes a Swagger 2.0 document and produces an OpenAPI 3.0.x document.
The transform is pure data restructuring over a `serde_json::Value` tree.
Parameters become request bodies, `securityDefinitions` becomes
`components.securitySchemes`, `definitions` becomes `components.schemas`, and
`host`/`basePath`/`schemes` become `servers`. Non-compliant JSON Schema
constructs are repaired in place. External `$ref` resolution from the local
filesystem runs when requested.

## Install

```toml
[dependencies]
swagger2openapi = "0.1"
```

## Use

Convert an in-memory value:

```rust
use serde_json::json;
use swagger2openapi::{convert_obj, Options};

let swagger = json!({
    "swagger": "2.0",
    "info": { "title": "Demo", "version": "1.0.0" },
    "paths": {}
});

let mut options = Options::new();
convert_obj(&swagger, &mut options).unwrap();
assert_eq!(options.openapi["openapi"], "3.0.0");
```

Convert a JSON or YAML string, a file, or any reader:

```rust
use swagger2openapi::{convert_str, convert_file, convert_stream, Options};

let mut options = Options::new();
convert_str("swagger: '2.0'\ninfo: {title: D, version: '1'}\npaths: {}", &mut options).unwrap();
```

The converted document lands in `options.openapi`. Errors surface as
`S2OError`.

## Options

`Options` carries both inputs and outputs. Common inputs:

- `patch`: repair small patchable errors instead of returning an error.
- `warn_only`: write a warning extension instead of erroring on recoverable
  problems.
- `target_version`: output `openapi` version, used when it starts with `3.`.
- `resolve`: resolve external `$ref`s from the filesystem.
- `ref_siblings`: how to handle a `$ref` that has sibling members
  (`Remove`, `Preserve`, or `AllOf`).
- `rbname`: extension key under which to record body parameter names.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
