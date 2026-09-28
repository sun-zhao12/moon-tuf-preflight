// White-box tests for delegation structure and snapshot coverage.
//
// The fixtures are built by composing JSON values and stringifying them, because
// hand-written JSON strings in this file were easy to get subtly wrong and then
// the failure looked like a bug in the checker under test.

///|
/// A JSON string value.
fn js(text : String) -> Json {
  @json.to_json(text)
}

///|
/// A JSON integer value.
fn ji(value : Int) -> Json {
  @json.to_json(value)
}

///|
/// A JSON array from already-built values.
fn ja(values : Array[Json]) -> Json {
  @json.to_json(values)
}

///|
/// A JSON object from key/value pairs, in the order supplied.
fn jo(pairs : Array[(String, Json)]) -> Json {
  let map : Map[String, Json] = Map([])
  for pair in pairs {
    let (key, value) = pair
    map[key] = value
  }
  @json.to_json(map)
}

///|
/// A delegated-role entry.
fn delegation_value(
  name : String,
  keyids : Array[String],
  threshold : Int,
  paths : Array[String],
) -> Json {
  let kid_values : Array[Json] = []
  for keyid in keyids {
    kid_values.push(js(keyid))
  }
  let path_values : Array[Json] = []
  for path in paths {
    path_values.push(js(path))
  }
  jo([
    ("name", js(name)),
    ("keyids", ja(kid_values)),
    ("threshold", ji(threshold)),
    ("paths", ja(path_values)),
    ("terminating", @json.to_json(false)),
  ])
}

///|
/// A `keys` table containing one usable key per supplied key id.
fn keys_value(keyids : Array[String]) -> Json {
  let pairs : Array[(String, Json)] = []
  for keyid in keyids {
    pairs.push(
      (
        keyid,
        jo([
          ("keytype", js("ed25519")),
          ("scheme", js("ed25519")),
          ("keyval", jo([("public", js("public-" + keyid))])),
        ]),
      ),
    )
  }
  jo(pairs)
}

///|
/// A `targets` (or delegated) document carrying `roles` as its delegations.
fn delegation_document(
  role : String,
  keyids : Array[String],
  roles : Array[Json],
) -> String {
  let signed = jo([
    ("spec_version", js("1.0.31")),
    ("_type", js(role)),
    ("version", ji(1)),
    ("expires", js("2030-01-01T00:00:00Z")),
    ("targets", jo([])),
    ("keys", keys_value(keyids)),
    ("delegations", jo([("roles", ja(roles))])),
  ])
  let signature = jo([("keyid", js("k1")), ("sig", js("placeholder"))])
  jo([("signed", signed), ("signatures", ja([signature]))]).stringify()
}

///|
test "delegation globs match within a single path segment" {
  // A star never crosses a separator, which is what makes `*` in a delegation
  // different from a recursive wildcard.
  assert_true(path_matches("*.bin", "app.bin"))
  assert_false(path_matches("*.bin", "dir/app.bin"))
  assert_true(path_matches("*/*.bin", "dir/app.bin"))
  assert_false(path_matches("*.bin", "dir/sub/app.bin"))
  assert_true(path_matches("dir/*", "dir/app.bin"))
  assert_false(path_matches("dir/*", "dir/sub/app.bin"))
  assert_true(path_matches("dir/*/*", "dir/sub/app.bin"))
  assert_true(path_matches("*", "anything.bin"))
  assert_false(path_matches("*", "dir/anything.bin"))
  // A trailing star still stops at the separator.
  assert_true(path_matches("dir*", "directory"))
  assert_false(path_matches("dir*", "dir/sub"))
  // A question mark matches exactly one character.
  assert_true(path_matches("app.?in", "app.bin"))
  assert_false(path_matches("app.?in", "app.inn"))
  // `?` matches any single character, including a literal dot, but never a
  // separator.
  assert_true(path_matches("app.?in", "app..in"))
  assert_false(path_matches("app.?in", "app/in"))
  // A character class matches one character from the set or a range.
  assert_true(path_matches("app.[bh]in", "app.bin"))
  assert_true(path_matches("app.[bh]in", "app.hin"))
  assert_false(path_matches("app.[bh]in", "app.xin"))
  assert_true(path_matches("app.[a-c]in", "app.bin"))
  assert_false(path_matches("app.[a-c]in", "app.din"))
  assert_true(path_matches("app.[!x]in", "app.bin"))
  assert_false(path_matches("app.[!b]in", "app.bin"))
  // A pattern without wildcards is an exact match.
  assert_true(path_matches("app.bin", "app.bin"))
  assert_false(path_matches("app.bin", "app.binx"))
  assert_false(path_matches("app.bin", "app.bi"))
  // An empty pattern matches only the empty path.
  assert_true(path_matches("", ""))
  assert_false(path_matches("", "a"))
  assert_false(path_matches("a", ""))
  // An unterminated class is treated as unmatchable rather than panicking.
  assert_false(path_matches("app.[bh", "app.b"))
}

///|
test "any_path_matches scans every pattern" {
  assert_true(any_path_matches(["*.bin", "*.txt"], "notes.txt"))
  assert_true(any_path_matches(["*.bin"], "app.bin"))
  assert_false(any_path_matches(["*.bin"], "app.txt"))
  assert_false(any_path_matches([], "app.bin"))
}

///|
test "hex prefixes are checked as prefixes" {
  let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  assert_true(is_hex_prefix("0123", digest))
  assert_true(is_hex_prefix(digest, digest))
  assert_false(is_hex_prefix("ffff", digest))
  // A prefix longer than the digest, empty, or non-hex cannot be used.
  assert_false(is_hex_prefix(digest + "0", digest))
  assert_false(is_hex_prefix("", digest))
  assert_false(is_hex_prefix("zzzz", digest))
  assert_false(is_hex_prefix("0123", "abc"))
}

///|
test "well-formed delegations parse into typed entries" {
  let document = delegation_document("targets", ["k1", "k2"], [
    delegation_value("role1", ["k1", "k2"], 2, ["apps/*"]),
  ])
  let delegations = match parse_delegations(document) {
    Some(delegations) => delegations
    None => fail("delegations did not parse")
  }
  assert_eq(delegations.length(), 1)
  let entry = delegations[0]
  assert_eq(entry.name(), "role1")
  assert_eq(entry.keyids(), ["k1", "k2"])
  assert_eq(entry.threshold(), 2)
  assert_eq(entry.paths(), ["apps/*"])
  assert_eq(entry.path_hash_prefixes(), [])
  assert_false(entry.terminating())
  assert_true(entry.is_well_formed())
  // No delegations object at all is valid and yields None.
  assert_true(parse_delegations("{\"signed\":{\"_type\":\"targets\"}}") is None)
  assert_true(parse_delegations("{") is None)
  assert_true(parse_delegations("{\"signed\":{\"delegations\":{}}}") is None)
}

///|
test "malformed delegations are reported by index" {
  let signed = jo([
    ("spec_version", js("1.0.31")),
    ("_type", js("targets")),
    ("version", ji(1)),
    ("expires", js("2030-01-01T00:00:00Z")),
    ("targets", jo([])),
    ("delegations", jo([("roles", ja([ji(7), jo([("name", js("no-keys"))])]))])),
  ])
  let document = jo([
    ("signed", signed),
    ("signatures", ja([jo([("keyid", js("k1")), ("sig", js("s"))])])),
  ]).stringify()
  let delegations = match parse_delegations(document) {
    Some(delegations) => delegations
    None => fail("delegations did not parse")
  }
  assert_eq(delegations.length(), 2)
  assert_false(delegations[0].is_well_formed())
  assert_false(delegations[1].is_well_formed())
  let findings = empty_findings()
  check_delegations(document, findings)
  let codes = findings.map(finding => finding.to_string())
  assert_true(codes.contains("error:malformed-delegation:roles[0]"))
  assert_true(codes.contains("error:malformed-delegation:no-keys"))
}

///|
test "delegation key ids must exist in the document keys" {
  let document = delegation_document("targets", ["k1"], [
    delegation_value("role1", ["k1", "ghost"], 2, ["apps/*"]),
  ])
  let findings = empty_findings()
  check_delegations(document, findings)
  let codes = findings.map(finding => finding.to_string())
  assert_true(codes.contains("error:unknown-delegation-keyid:role1:ghost"))
  // One usable key is below a threshold of two.
  assert_true(
    codes.contains(
      "error:unreachable-delegation-threshold:role1:threshold=2,usable=1",
    ),
  )
  // The convenience wrapper returns the same findings as strings.
  assert_eq(preflight_delegations(document), codes)
}

///|
test "a delegation without paths would authorize everything" {
  let document = delegation_document("targets", ["k1"], [
    delegation_value("role1", ["k1"], 1, []),
    delegation_value("role2", ["k1"], 1, ["../escape/*"]),
  ])
  let findings = empty_findings()
  check_delegations(document, findings)
  let codes = findings.map(finding => finding.to_string())
  assert_true(codes.contains("error:delegation-without-paths:role1"))
  assert_true(
    codes.contains("warning:suspicious-delegation-path:role2:../escape/*"),
  )
}

///|
test "duplicate delegations and bad hash prefixes are reported" {
  let with_prefixes = fn(name : String, prefixes : Array[String]) {
    let values : Array[Json] = []
    for prefix in prefixes {
      values.push(js(prefix))
    }
    jo([
      ("name", js(name)),
      ("keyids", ja([js("k1")])),
      ("threshold", ji(1)),
      ("path_hash_prefixes", ja(values)),
    ])
  }
  let document = delegation_document("targets", ["k1"], [
    with_prefixes("role1", ["abc", "zz"]),
    with_prefixes("role1", ["abc"]),
  ])
  let findings = empty_findings()
  check_delegations(document, findings)
  let codes = findings.map(finding => finding.to_string())
  assert_true(codes.contains("error:duplicate-delegation:role1"))
  assert_true(codes.contains("error:malformed-path-hash-prefix:role1:zz"))
}

///|
test "a clean delegation tree reports nothing" {
  let document = delegation_document("targets", ["k1"], [
    delegation_value("role1", ["k1"], 1, ["apps/*"]),
  ])
  let findings = empty_findings()
  check_delegations(document, findings)
  assert_eq(findings.map(finding => finding.to_string()), [])
}

///|
test "reachable roles are computed without looping on cycles" {
  let edges : Map[String, Array[String]] = Map([])
  edges["targets"] = ["role1", "role2"]
  edges["role1"] = ["role3"]
  edges["role3"] = ["role1"]
  let order = reachable_roles("targets", edges)
  assert_eq(order, ["targets", "role1", "role2", "role3"])
  assert_eq(reachable_roles("role3", edges), ["role3", "role1"])
  assert_eq(reachable_roles("absent", edges), ["absent"])
}

///|
test "delegation edges map a role to its children" {
  let document = delegation_document("role1", ["k1"], [
    delegation_value("role2", ["k1"], 1, ["*"]),
  ])
  let edges = delegation_edges(document)
  assert_eq(edges.get("role1"), Some(["role2"]))
  assert_eq(delegation_edges("{").length(), 0)
}

///|
test "a delegation tree reports missing metadata and cycles" {
  // `role1` delegates back to `targets`, which is a cycle, and the caller does
  // not supply a second targets document for that edge.
  let parent = delegation_document("targets", ["k1"], [
    delegation_value("role1", ["k1"], 1, ["*"]),
  ])
  let child = delegation_document("role1", ["k1"], [
    delegation_value("targets", ["k1"], 1, ["*"]),
  ])
  let findings = empty_findings()
  let documents : Map[String, String] = Map([])
  documents["targets"] = parent
  documents["role1"] = child
  check_delegation_tree(documents, findings)
  let codes = findings.map(finding => finding.to_string())
  assert_true(codes.contains("error:delegation-cycle:targets"))
  assert_true(codes.contains("error:delegation-cycle:role1"))
  // The edge into `targets` has no second document, but `targets` is present in
  // the map, so no missing-metadata finding is expected for it.
  assert_false(
    codes.contains("error:missing-delegated-metadata:targets->role1"),
  )
  // A child the caller never supplied is reported.
  let partial : Map[String, String] = Map([])
  partial["targets"] = parent
  let missing_findings = empty_findings()
  check_delegation_tree(partial, missing_findings)
  assert_true(
    missing_findings
    .map(finding => finding.to_string())
    .contains("error:missing-delegated-metadata:targets->role1"),
  )
}

///|
test "snapshot coverage compares listed and supplied metadata" {
  let snapshot = "{\"signed\":{\"spec_version\":\"1.0.31\",\"_type\":\"snapshot\",\"version\":2,\"expires\":\"2030-01-01T00:00:00Z\",\"meta\":{\"targets.json\":{\"version\":3},\"role1.json\":{\"version\":1}}},\"signatures\":[{\"keyid\":\"k1\",\"sig\":\"s\"}]}"
  let supplied : Map[String, Int] = Map([])
  supplied["targets.json"] = 3
  let findings = empty_findings()
  check_snapshot_coverage(snapshot, supplied, findings)
  let codes = findings.map(finding => finding.to_string())
  // `role1.json` is listed but the caller did not supply it.
  assert_true(codes.contains("warning:unprovided-targets-metadata:role1.json"))
  // The supplied targets document agrees, so no mismatch is reported.
  assert_false(codes.contains("error:snapshot-version-mismatch"))
}

///|
test "snapshot coverage reports mismatches and omissions" {
  let snapshot = "{\"signed\":{\"spec_version\":\"1.0.31\",\"_type\":\"snapshot\",\"version\":2,\"expires\":\"2030-01-01T00:00:00Z\",\"meta\":{\"targets.json\":{\"version\":3}}},\"signatures\":[{\"keyid\":\"k1\",\"sig\":\"s\"}]}"
  let supplied : Map[String, Int] = Map([])
  supplied["targets.json"] = 3
  supplied["role1.json"] = 1
  let findings = empty_findings()
  check_snapshot_coverage(snapshot, supplied, findings)
  let codes = findings.map(finding => finding.to_string())
  assert_true(codes.contains("error:unlisted-targets-metadata:role1.json"))
  let mismatched : Map[String, Int] = Map([])
  mismatched["targets.json"] = 4
  let mismatch_findings = empty_findings()
  check_snapshot_coverage(snapshot, mismatched, mismatch_findings)
  assert_true(
    mismatch_findings
    .map(finding => finding.to_string())
    .contains(
      "error:snapshot-version-mismatch:targets.json:referenced=3,actual=4",
    ),
  )
  // A snapshot without a usable meta table is reported rather than ignored.
  let no_meta = "{\"signed\":{\"_type\":\"snapshot\",\"version\":1},\"signatures\":[]}"
  let empty = empty_findings()
  check_snapshot_coverage(no_meta, supplied, empty)
  assert_true(
    empty
    .map(finding => finding.to_string())
    .contains("error:missing-meta:snapshot"),
  )
  let broken = empty_findings()
  check_snapshot_coverage("{", supplied, broken)
  assert_true(
    broken
    .map(finding => finding.to_string())
    .contains("error:missing-signed-object:snapshot"),
  )
  // The convenience wrapper returns the same findings as strings.
  assert_eq(preflight_snapshot_coverage(snapshot, supplied), codes)
}
