# Changelog

## [0.2.0] - 2026-07-07

### Changed
- Request bodies with colliding serialized hashes now keep their own schemas instead of sharing the first matching body. (#24)
- Parameter and response `$ref` names that use percent escapes now point to decoded component keys. (#25)
- Path-level body parameters now become request bodies on operations that inherit them. (#26)
- In patch mode, string operation `produces` values now create response content for that media type instead of falling back to `*/*`. (#27)
- JSON Reference fragments now treat `+` as a literal plus sign. Use `%20` for spaces. (#28)

## [0.2.0] - 2026-07-07

### Changed
- Request bodies with colliding serialized hashes now keep their own schemas instead of sharing the first matching body. (#24)
- Parameter and response `$ref` names that use percent escapes now point to decoded component keys. (#25)
- Path-level body parameters now become request bodies on operations that inherit them. (#26)
- In patch mode, string operation `produces` values now create response content for that media type instead of falling back to `*/*`. (#27)
- JSON Reference fragments now treat `+` as a literal plus sign. Use `%20` for spaces. (#28)
