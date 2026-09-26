# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-09-26

### Added

- `Finding::severity`, `Finding::code` and `Finding::location` accessors, so a
  consumer can branch on structured findings instead of parsing the rendered
  string.
- `finding_codes()`, the complete sorted list of diagnostic codes the library
  can emit.
- `compare_ordinal` and `is_sorted_ordinal`, because MoonBit's `String`
  comparison is shortlex (length first) and cannot order a code list.
- Validation of the optional `length` and `hashes` fields of `timestamp` and
  `snapshot` `meta` entries, with the codes `invalid-meta-length`,
  `invalid-meta-hashes`, `invalid-meta-hash` and
  `unsupported-meta-hash-algorithm`.
- Validation of the `spec_version` field: `missing-spec-version` and
  `malformed-spec-version` are warnings, never errors, so pre-1.0 metadata stays
  usable.
- `sha3-256` and `sha3-512` digest length checks; those algorithms previously
  produced `unsupported-target-hash-algorithm` even when the digest was correct.
- README sections listing every diagnostic code and showing how to use the CLI
  as a pipeline gate.

### Changed

- A bundle finding from a single document now consistently carries that
  document name as a code segment, for example
  `error:timestamp:expired:2030-01-01T00:00:00Z`. Earlier documentation
  described a different order for these strings.
- `moon.mod` records `repository`.

### Fixed

- A bundle whose version reference or document version was missing or malformed
  could be reported as matching, because two absent versions compared equal.
  It is now reported as `missing-version-reference` or
  `missing-document-version`.
- `safe_target_path` matched a single backslash instead of any backslash, so a
  Windows-style path could pass the check.
- Root roles with an empty `keyids` array were accepted silently; they now
  report `missing-keyids`.
- The CLI and example document the exit codes actually produced.

## [0.1.0] - 2026-09-26

### Added

- Initial release: `preflight`, `preflight_at` and `preflight_bundle` plus the
  `Report`, `Finding` and `Severity` types, a `cmd/preflight` CLI, an
  `examples/demo` walkthrough, white-box tests, CI for wasm, wasm-gc, js and
  native, and the MIT license.

[0.1.1]: https://github.com/sun-zhao12/moon-tuf-preflight/commits/main
[0.1.0]: https://github.com/sun-zhao12/moon-tuf-preflight/commits/main
