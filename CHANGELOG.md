# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-09-26

### Added

- A date-time layer (`parse_date_time`, `DateTime`, `DateTimeForm`) that reads
  the specification's exact `YYYY-MM-DDTHH:MM:SSZ` form, accepts fractional
  seconds and numeric UTC offsets while marking them non-canonical, applies the
  Gregorian century rule, and converts instants to seconds since the epoch so
  expiry comparisons are exact rather than lexicographic.
- A semantic-version layer (`parse_semver`, `Semver`,
  `is_compatible_spec_version`) for the `spec_version` field.
- Signature authorization (`signature_keyids`, `signature_values`,
  `check_authorization`, `Authorization`, `count_authorized`,
  `unexpected_signers`, `authorized_keyids`, `role_threshold`): how many
  distinct authorized keys signed, whether that meets the role threshold, and
  which signers belong to neither the previous root nor the document's own role.
- Root rotation chains (`check_root_chain`, `preflight_root_chain`,
  `chain_versions`, `chain_signers`) requiring consecutive versions and
  authorization by the immediate predecessor.
- Delegation checks (`parse_delegations`, `check_delegations`, `path_matches`,
  `is_hex_prefix`, `check_delegation_tree`, `reachable_roles`): unknown
  delegation keys, unreachable thresholds, delegations without paths, duplicate
  role names, malformed path-hash prefixes, suspicious globs and cycles.
- Snapshot coverage (`check_snapshot_coverage`): a snapshot is compared against
  the targets documents the caller supplied, in both directions.
- `empty_findings()`, the shared constructor for a findings buffer.

### Fixed

- A `root` document missing both `keys` and `roles` reported only the first
  problem, because the validator returned early; every missing table and every
  missing top-level role is now reported in one pass.

### Changed

- `unexpected_signers` takes the document's own role key ids as a third
  argument, so a rotation signed by both the old and the new key is not reported
  as carrying an unexpected signer.

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
