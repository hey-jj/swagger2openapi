# swagger2openapi

Convert Swagger 2.0 (OpenAPI v2.0) API definitions to OpenAPI 3.0.x.

The crate takes a Swagger 2.0 document and produces an OpenAPI 3.0.x document.
The transform is pure data restructuring. Parameters become request bodies,
`securityDefinitions` becomes `components.securitySchemes`, `definitions`
becomes `components.schemas`, and `host`/`basePath`/`schemes` become `servers`.
Non-compliant JSON Schema constructs are repaired in place. External and
internal `$ref` resolution and validation are optional.

## Status

Early development. The public API and module layout land first. See the build
tracking issue for progress.

## Installation

```toml
[dependencies]
swagger2openapi = "0.1"
```

## Features

- `yaml` (default): YAML parse and serialize for the string, file, and stream
  entry points.
- `resolve`: external and internal `$ref` resolution plus the URL entry point.
- `wasm`: marker for the hermetic conversion core targeting `wasm32`.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
