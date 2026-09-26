///|
/// A syntactically valid SHA-256 digest. It is a repeated pattern, not a digest
/// of any file in this repository.
let sha256_hex : String = "0123456789abcdef".repeat(4)

///|
/// A syntactically valid SHA-512 digest, again only structurally meaningful.
let sha512_hex : String = "0123456789abcdef".repeat(8)

///|
/// The specification version stamped into every fixture, matching the TUF
/// metadata version this preflight targets.
let spec_version : String = "1.0.31"

///|
/// A structurally valid single-signature envelope around `body`, which must be
/// the JSON text of the `signed` object beginning with `{`.
///
/// The `spec_version` field is injected here so that fixtures stay focused on
/// the field under test instead of repeating shared metadata on every line. The
/// dedicated spec-version test builds its `signed` object by hand.
fn envelope(body : String) -> String {
  let with_spec_version = "{\"spec_version\":\"" +
    spec_version +
    "\"," +
    body[1:].to_owned()
  "{\"signed\":" +
  with_spec_version +
  ",\"signatures\":[{\"keyid\":\"k1\",\"sig\":\"s1\"}]}"
}

///|
/// Escape `value` so that it can be embedded between two JSON double quotes.
fn escape_json(value : String) -> String {
  value
  .replace_all(old="\\", new="\\\\")
  .replace_all(old="\"", new="\\\"")
  .replace_all(old="\n", new="\\n")
}

///|
/// A `targets` document containing one well-formed target named `name`, with
/// `length` bytes and the JSON fragment `hashes` as its `hashes` value.
fn targets_document(
  name : String,
  hashes : String,
  length? : Double = 1024.0,
  version? : Int = 3,
) -> String {
  envelope(
    "{\"_type\":\"targets\",\"version\":" +
    version.to_string() +
    ",\"expires\":\"2030-06-01T12:30:00Z\",\"targets\":{\"" +
    escape_json(name) +
    "\":{\"length\":" +
    length.to_string() +
    ",\"hashes\":" +
    hashes +
    "}}}",
  )
}

///|
/// The set of finding codes in `report`, with the severity prefix stripped.
fn codes(report : Report) -> Array[String] {
  report
  .to_strings()
  .map(line => {
    let parts = line.split(":").to_array().map(part => part.to_owned())
    if parts.length() >= 2 {
      parts[1]
    } else {
      line
    }
  })
}

///|
test "well-formed targets metadata has no findings" {
  let input = targets_document("app.bin", "{\"sha256\":\"" + sha256_hex + "\"}")
  let report = preflight_report(input, "targets")
  assert_eq(report.to_strings(), [])
  assert_true(report.ok())
  assert_eq(report.error_count(), 0)
  assert_eq(report.version(), Some(3))
  assert_eq(report.render(), "ok")
}

///|
test "malformed JSON and wrong envelope shapes are reported" {
  assert_eq(preflight("{", "targets"), ["error:invalid-json"])
  assert_eq(preflight("[]", "targets"), ["error:envelope-not-object"])
  assert_eq(preflight("{\"signatures\":[]}", "targets"), [
    "error:missing-signed-object",
  ])
  assert_eq(preflight("{}", "mirror"), ["error:unsupported-role:mirror"])
}

///|
test "the declared specification version is checked" {
  let signed = fn(spec : String) {
    "{\"_type\":\"targets\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{},\"spec_version\":\"" +
    spec +
    "\"}"
  }
  for accepted in ["1", "1.0", "1.0.31", "10.2.7"] {
    assert_eq(preflight(envelope(signed(accepted)), "targets"), [])
  }
  for
    malformed in [
      "", "v1.0", "1.0.", ".1", "1..0", "1.0.31-beta", "1.0.31+meta",
    ] {
    let report = preflight_report(envelope(signed(malformed)), "targets")
    // The empty version renders without a location suffix, so assert on the
    // structured finding instead of rebuilding the rendered string.
    assert_true(
      report
      .findings()
      .any(finding => {
        finding.code == "malformed-spec-version" &&
        finding.location == malformed
      }),
    )
    assert_eq(report.error_count(), 0)
  }
  // A document without the field stays usable, it is only flagged. This
  // envelope is written by hand because `envelope` always injects the field.
  let missing = "{\"signed\":{\"_type\":\"targets\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{}},\"signatures\":[{\"keyid\":\"k1\",\"sig\":\"s1\"}]}"
  let report = preflight_report(missing, "targets")
  assert_true(report.to_strings().contains("warning:missing-spec-version"))
  assert_eq(report.error_count(), 0)
  assert_true(report.ok())
}

///|
test "role, version and expiry fields are validated" {
  let wrong_role = envelope(
    "{\"_type\":\"snapshot\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{}}",
  )
  assert_true(
    preflight(wrong_role, "targets").contains("error:role-mismatch:targets"),
  )
  let bad_version = envelope(
    "{\"_type\":\"targets\",\"version\":0,\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{}}",
  )
  assert_true(
    preflight(bad_version, "targets").contains("error:invalid-version"),
  )
  let fractional = envelope(
    "{\"_type\":\"targets\",\"version\":1.5,\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{}}",
  )
  assert_true(
    preflight(fractional, "targets").contains("error:invalid-version"),
  )
  let bad_expires = envelope(
    "{\"_type\":\"targets\",\"version\":1,\"expires\":\"2030-02-29T00:00:00Z\",\"targets\":{}}",
  )
  assert_true(
    preflight(bad_expires, "targets").contains("error:invalid-expires"),
  )
  let leap_expires = envelope(
    "{\"_type\":\"targets\",\"version\":1,\"expires\":\"2032-02-29T00:00:00Z\",\"targets\":{}}",
  )
  assert_false(
    preflight(leap_expires, "targets").contains("error:invalid-expires"),
  )
}

///|
test "signature entries are inspected for shape, not validity" {
  let no_signatures = "{\"signed\":{\"_type\":\"targets\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{}}}"
  assert_true(
    preflight(no_signatures, "targets").contains(
      "error:missing-signatures-array",
    ),
  )
  let empty_signatures = "{\"signed\":{\"_type\":\"targets\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{}},\"signatures\":[]}"
  assert_true(
    preflight(empty_signatures, "targets").contains("error:empty-signatures"),
  )
  let broken = "{\"signed\":{\"_type\":\"targets\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{}},\"signatures\":[7,{\"keyid\":\"\",\"sig\":\"\"},{\"keyid\":\"k1\",\"sig\":\"s\"},{\"keyid\":\"k1\",\"sig\":\"s\"}]}"
  let codes = preflight(broken, "targets")
  assert_true(codes.contains("error:invalid-signature-entry"))
  assert_true(codes.contains("error:invalid-signature-keyid"))
  assert_true(codes.contains("error:invalid-signature-value"))
  assert_true(codes.contains("error:duplicate-signature-keyid:k1"))
}

///|
test "root keys, roles and thresholds are checked" {
  let key = "\"k1\":{\"keytype\":\"ed25519\",\"scheme\":\"ed25519\",\"keyval\":{\"public\":\"public-bytes\"}}"
  let role = fn(threshold : Int, keyids : String) {
    "{\"threshold\":" + threshold.to_string() + ",\"keyids\":" + keyids + "}"
  }
  let good = envelope(
    "{\"_type\":\"root\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"keys\":{" +
    key +
    "},\"roles\":{\"root\":" +
    role(1, "[\"k1\"]") +
    ",\"timestamp\":" +
    role(1, "[\"k1\"]") +
    ",\"snapshot\":" +
    role(1, "[\"k1\"]") +
    ",\"targets\":" +
    role(1, "[\"k1\"]") +
    "}}",
  )
  assert_eq(preflight(good, "root"), [])
  let unreachable_root = envelope(
    "{\"_type\":\"root\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"keys\":{\"k1\":{}},\"roles\":{\"root\":" +
    role(2, "[\"k1\",\"ghost\"]") +
    "}}",
  )
  let report = preflight_report(unreachable_root, "root")
  assert_true(codes(report).contains("unreachable-threshold"))
  assert_true(codes(report).contains("unknown-keyid"))
  assert_true(codes(report).contains("missing-role"))
  assert_true(codes(report).contains("invalid-keytype"))
  assert_true(codes(report).contains("invalid-keyval"))
  assert_true(codes(report).contains("missing-role"))
  let missing_roles = envelope(
    "{\"_type\":\"root\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\"}",
  )
  assert_true(preflight(missing_roles, "root").contains("error:missing-keys"))
  let missing_keys = envelope(
    "{\"_type\":\"root\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"roles\":{}}",
  )
  assert_true(preflight(missing_keys, "root").contains("error:missing-keys"))
  let duplicate = envelope(
    "{\"_type\":\"root\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"keys\":{" +
    key +
    "},\"roles\":{\"root\":" +
    role(1, "[\"k1\",\"k1\"]") +
    ",\"timestamp\":" +
    role(1, "[]") +
    "}}",
  )
  let duplicate_codes = preflight(duplicate, "root")
  assert_true(duplicate_codes.contains("error:duplicate-keyid:root:k1"))
  assert_true(duplicate_codes.contains("error:missing-keyids:timestamp"))
}

///|
/// A `snapshot` document whose `targets.json` entry carries `extra` fields, so
/// tests can exercise the optional `length` and `hashes` validation.
fn snapshot_entry(extra : String) -> String {
  envelope(
    "{\"_type\":\"snapshot\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"meta\":{\"targets.json\":{\"version\":3" +
    extra +
    "}}}",
  )
}

///|
test "optional meta length and hashes are validated" {
  // Both fields are optional and stay accepted when they are well formed.
  assert_eq(
    preflight(
      snapshot_entry(
        ",\"length\":1024,\"hashes\":{\"sha256\":\"" + sha256_hex + "\"}",
      ),
      "snapshot",
    ),
    [],
  )
  assert_eq(preflight(snapshot_entry(",\"length\":0"), "snapshot"), [])
  let bad_length = preflight(snapshot_entry(",\"length\":-5"), "snapshot")
  assert_true(bad_length.contains("error:invalid-meta-length:targets.json"))
  let fractional = preflight(snapshot_entry(",\"length\":2.5"), "snapshot")
  assert_true(fractional.contains("error:invalid-meta-length:targets.json"))
  let empty_hashes = preflight(snapshot_entry(",\"hashes\":{}"), "snapshot")
  assert_true(empty_hashes.contains("error:invalid-meta-hashes:targets.json"))
  let not_object = preflight(snapshot_entry(",\"hashes\":[]"), "snapshot")
  assert_true(not_object.contains("error:invalid-meta-hashes:targets.json"))
  let short_digest = preflight(
    snapshot_entry(",\"hashes\":{\"sha256\":\"abc\"}"),
    "snapshot",
  )
  assert_true(
    short_digest.contains("error:invalid-meta-hash:targets.json:sha256"),
  )
  let unknown_algorithm = preflight(
    snapshot_entry(",\"hashes\":{\"md5\":\"abc\"}"),
    "snapshot",
  )
  assert_true(
    unknown_algorithm.contains(
      "warning:unsupported-meta-hash-algorithm:targets.json:md5",
    ),
  )
}

///|
test "timestamp and snapshot meta tables are validated" {
  let timestamp = envelope(
    "{\"_type\":\"timestamp\",\"version\":4,\"expires\":\"2030-01-01T00:00:00Z\",\"meta\":{\"snapshot.json\":{\"version\":3}}}",
  )
  assert_eq(preflight(timestamp, "timestamp"), [])
  let missing_reference = envelope(
    "{\"_type\":\"timestamp\",\"version\":4,\"expires\":\"2030-01-01T00:00:00Z\",\"meta\":{\"other.json\":{\"version\":1}}}",
  )
  assert_true(
    preflight(missing_reference, "timestamp").contains(
      "error:missing-meta:snapshot.json",
    ),
  )
  let empty = envelope(
    "{\"_type\":\"snapshot\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"meta\":{}}",
  )
  let empty_codes = preflight(empty, "snapshot")
  assert_true(empty_codes.contains("error:empty-meta:snapshot"))
  assert_true(empty_codes.contains("error:missing-meta:targets.json"))
  let bad_version = envelope(
    "{\"_type\":\"snapshot\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"meta\":{\"targets.json\":{\"version\":\"1\"}}}",
  )
  assert_true(
    preflight(bad_version, "snapshot").contains(
      "error:invalid-meta-version:targets.json",
    ),
  )
  let not_object = envelope(
    "{\"_type\":\"snapshot\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"meta\":{\"targets.json\":[]}}",
  )
  assert_true(
    preflight(not_object, "snapshot").contains(
      "error:invalid-meta-entry:targets.json",
    ),
  )
  let no_meta = envelope(
    "{\"_type\":\"snapshot\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\"}",
  )
  assert_true(
    preflight(no_meta, "snapshot").contains("error:missing-meta:snapshot"),
  )
}

///|
test "target paths, lengths and digests are validated" {
  assert_eq(
    preflight(
      targets_document("app.bin", "{\"sha256\":\"" + sha256_hex + "\"}"),
      "targets",
    ),
    [],
  )
  assert_eq(
    preflight(
      targets_document("app.bin", "{\"sha512\":\"" + sha512_hex + "\"}"),
      "targets",
    ),
    [],
  )
  // The TUF specification also names the SHA-3 family, so those algorithms must
  // be checked for length instead of being reported as unsupported.
  assert_eq(
    preflight(
      targets_document("app.bin", "{\"sha3-256\":\"" + sha256_hex + "\"}"),
      "targets",
    ),
    [],
  )
  assert_eq(
    preflight(
      targets_document("app.bin", "{\"sha3-512\":\"" + sha512_hex + "\"}"),
      "targets",
    ),
    [],
  )
  let short_sha3 = preflight(
    targets_document("app.bin", "{\"sha3-256\":\"" + sha512_hex + "\"}"),
    "targets",
  )
  assert_true(short_sha3.contains("error:invalid-target-hash:app.bin:sha3-256"))
  for
    path in [
      "../app", "/etc/passwd", "a/../b", "a//b", "a/./b", "", "C:\\\\app",
    ] {
    let found = preflight(
      targets_document(path, "{\"sha256\":\"" + sha256_hex + "\"}"),
      "targets",
    )
    // An empty name produces a finding whose location is the empty string, so
    // the expected text is built from the same values the library reports.
    let expected = if path == "" {
      "error:unsafe-target-path"
    } else {
      "error:unsafe-target-path:" + path
    }
    assert_true(found.contains(expected))
  }
  let short_digest = preflight(
    targets_document("app.bin", "{\"sha256\":\"abc\"}"),
    "targets",
  )
  assert_true(short_digest.contains("error:invalid-target-hash:app.bin:sha256"))
  let non_hex = preflight(
    targets_document("app.bin", "{\"sha256\":\"" + "z".repeat(64) + "\"}"),
    "targets",
  )
  assert_true(non_hex.contains("error:invalid-target-hash:app.bin:sha256"))
  let unknown_algorithm = preflight(
    targets_document("app.bin", "{\"md5\":\"abc\"}"),
    "targets",
  )
  assert_true(
    unknown_algorithm.contains(
      "warning:unsupported-target-hash-algorithm:app.bin:md5",
    ),
  )
  let no_hashes = preflight(targets_document("app.bin", "{}"), "targets")
  assert_true(no_hashes.contains("error:missing-target-hashes:app.bin"))
  let negative = targets_document(
    "app.bin",
    "{\"sha256\":\"" + sha256_hex + "\"}",
    length=-1.0,
  )
  assert_true(
    preflight(negative, "targets").contains(
      "error:invalid-target-length:app.bin",
    ),
  )
  let fractional = targets_document(
    "app.bin",
    "{\"sha256\":\"" + sha256_hex + "\"}",
    length=1.5,
  )
  assert_true(
    preflight(fractional, "targets").contains(
      "error:invalid-target-length:app.bin",
    ),
  )
  let bad_entry = envelope(
    "{\"_type\":\"targets\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{\"app.bin\":4}}",
  )
  assert_true(
    preflight(bad_entry, "targets").contains(
      "error:invalid-target-entry:app.bin",
    ),
  )
  let warning = envelope(
    "{\"_type\":\"targets\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{\"app.bin\":{\"length\":1,\"hashes\":{\"sha256\":\"" +
    sha256_hex +
    "\"},\"custom\":7}}}",
  )
  let warning_report = preflight_report(warning, "targets")
  assert_true(
    warning_report
    .to_strings()
    .contains("warning:non-object-target-custom:app.bin"),
  )
  assert_eq(warning_report.warning_count(), 1)
  assert_eq(warning_report.error_count(), 0)
}

///|
test "expiry is decided by the caller-supplied clock" {
  let input = targets_document("app.bin", "{\"sha256\":\"" + sha256_hex + "\"}")
  assert_false(
    preflight_at(input, "targets", "2029-01-01T00:00:00Z").contains(
      "error:expired:2030-06-01T12:30:00Z",
    ),
  )
  assert_false(
    preflight_at(input, "targets", "2030-06-01T12:29:59Z").contains(
      "error:expired:2030-06-01T12:30:00Z",
    ),
  )
  assert_true(
    preflight_at(input, "targets", "2030-06-01T12:30:00Z").contains(
      "error:expired:2030-06-01T12:30:00Z",
    ),
  )
  assert_true(
    preflight_at(input, "targets", "2031-01-01T00:00:00Z").contains(
      "error:expired:2030-06-01T12:30:00Z",
    ),
  )
  assert_true(
    preflight_at(input, "targets", "yesterday").contains(
      "error:invalid-current-time",
    ),
  )
}

///|
test "bundle checks reference versions in both directions" {
  let timestamp = envelope(
    "{\"_type\":\"timestamp\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"meta\":{\"snapshot.json\":{\"version\":2}}}",
  )
  let snapshot = envelope(
    "{\"_type\":\"snapshot\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"meta\":{\"targets.json\":{\"version\":1}}}",
  )
  let targets = targets_document(
    "app.bin",
    "{\"sha256\":\"" + sha256_hex + "\"}",
  )
  let report = preflight_bundle_report(
    timestamp, snapshot, targets, "2026-09-24T00:00:00Z",
  )
  assert_true(
    report
    .to_strings()
    .contains(
      "error:snapshot-version-mismatch:snapshot.json:referenced=2,actual=1",
    ),
  )
  // `snapshot` references `targets.json` version 1, but the targets document
  // carries version 3, so both mismatches must be reported independently.
  assert_true(
    report
    .to_strings()
    .contains(
      "error:targets-version-mismatch:targets.json:referenced=1,actual=3",
    ),
  )
  let matching = envelope(
    "{\"_type\":\"timestamp\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"meta\":{\"snapshot.json\":{\"version\":1}}}",
  )
  let matching_snapshot = envelope(
    "{\"_type\":\"snapshot\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"meta\":{\"targets.json\":{\"version\":3}}}",
  )
  assert_eq(
    preflight_bundle_report(
      matching, matching_snapshot, targets, "2026-09-24T00:00:00Z",
    ).to_strings(),
    [],
  )
  let no_reference = envelope(
    "{\"_type\":\"timestamp\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"meta\":{}}",
  )
  let missing_codes = preflight_bundle_report(
    no_reference, snapshot, targets, "2026-09-24T00:00:00Z",
  ).to_strings()
  assert_true(
    missing_codes.contains(
      "error:missing-version-reference:timestamp->snapshot.json",
    ),
  )
  let undated_targets = envelope(
    "{\"_type\":\"targets\",\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{}}",
  )
  let no_version = preflight_bundle_report(
    matching, snapshot, undated_targets, "2026-09-24T00:00:00Z",
  ).to_strings()
  assert_true(
    no_version.contains("error:missing-document-version:targets.json"),
  )
  // Per-document findings keep the severity prefix and gain the document name as
  // a code segment, so the document name follows `error:`.
  assert_true(no_version.contains("error:targets:invalid-version"))
  assert_true(missing_codes.any(line => line.has_prefix("error:timestamp:")))
  let expired = preflight_bundle_report(
    matching, snapshot, targets, "2035-01-01T00:00:00Z",
  ).to_strings()
  assert_true(expired.contains("error:timestamp:expired:2030-01-01T00:00:00Z"))
  assert_true(expired.contains("error:snapshot:expired:2030-01-01T00:00:00Z"))
  assert_true(expired.contains("error:targets:expired:2030-06-01T12:30:00Z"))
}

///|
test "report accessors expose severity counts" {
  let input = envelope(
    "{\"_type\":\"targets\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\",\"targets\":{\"app.bin\":{\"length\":1,\"hashes\":{\"sha256\":\"" +
    sha256_hex +
    "\"},\"custom\":7},\"../evil\":{\"length\":1,\"hashes\":{\"sha256\":\"" +
    sha256_hex +
    "\"}}}}",
  )
  let report = preflight_report(input, "targets")
  assert_eq(report.role(), "targets")
  assert_eq(report.version(), Some(1))
  assert_false(report.ok())
  assert_true(report.has_errors())
  assert_eq(report.error_count(), 1)
  assert_eq(report.warning_count(), 1)
  // Consumers branch on the structured findings, so exercise the accessors
  // rather than only the rendered strings.
  let findings = report.findings()
  assert_eq(findings.length(), 2)
  let errors = findings.filter(finding => finding.severity() is Error)
  let warnings = findings.filter(finding => finding.severity() is Warning)
  assert_eq(errors.length(), 1)
  assert_eq(errors[0].code(), "unsafe-target-path")
  assert_eq(errors[0].location(), "../evil")
  assert_eq(warnings.length(), 1)
  assert_eq(warnings[0].code(), "non-object-target-custom")
  assert_eq(warnings[0].location(), "app.bin")
}
