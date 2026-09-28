// White-box tests for signature authorization and root rotation.

///|
/// A key entry for a root document, with a distinguishable public value.
fn root_key(keytype : String, scheme : String, public : String) -> String {
  "{\"keytype\":\"" +
  keytype +
  "\",\"scheme\":\"" +
  scheme +
  "\",\"keyval\":{\"public\":\"" +
  public +
  "\"}}"
}

///|
/// A `root` document with the given version, per-role key ids and thresholds,
/// and the key ids that signed it. Each role is `(name, threshold, [keyid])`.
fn root_document(
  version : Int,
  roles : Array[(String, Int, Array[String])],
  signing : Array[String],
) -> String {
  let keys : Map[String, Bool] = Map([])
  let mut keys_json = ""
  let mut roles_json = ""
  for entry in roles {
    let (role, threshold, keyids) = entry
    let mut keyids_json = ""
    for index in 0..<keyids.length() {
      if index > 0 {
        keyids_json = keyids_json + ","
      }
      keyids_json = keyids_json + "\"" + keyids[index] + "\""
      // A key referenced by a role must also exist in `keys`, but only once.
      match keys.get(keyids[index]) {
        Some(_) => ()
        None => {
          keys[keyids[index]] = true
          let key_entry = "\"" +
            keyids[index] +
            "\":" +
            root_key("ed25519", "ed25519", "public-" + keyids[index])
          if keys_json == "" {
            keys_json = key_entry
          } else {
            keys_json = keys_json + "," + key_entry
          }
        }
      }
    }
    let role_entry = "\"" +
      role +
      "\":{\"threshold\":" +
      threshold.to_string() +
      ",\"keyids\":[" +
      keyids_json +
      "]}"
    if roles_json == "" {
      roles_json = role_entry
    } else {
      roles_json = roles_json + "," + role_entry
    }
  }
  let mut signatures = ""
  for index in 0..<signing.length() {
    if index > 0 {
      signatures = signatures + ","
    }
    signatures = signatures +
      "{\"keyid\":\"" +
      signing[index] +
      "\",\"sig\":\"placeholder-" +
      signing[index] +
      "\"}"
  }
  "{\"signed\":{\"spec_version\":\"1.0.31\",\"_type\":\"root\",\"version\":" +
  version.to_string() +
  ",\"expires\":\"2030-01-01T00:00:00Z\",\"keys\":{" +
  keys_json +
  "},\"roles\":{" +
  roles_json +
  "}},\"signatures\":[" +
  signatures +
  "]}"
}

///|
/// The four top-level roles bound to the same key ids, which is all most of
/// these tests need.
fn all_roles(
  threshold : Int,
  keyids : Array[String],
) -> Array[(String, Int, Array[String])] {
  [
    ("root", threshold, keyids),
    ("timestamp", 1, keyids),
    ("snapshot", 1, keyids),
    ("targets", 1, keyids),
  ]
}

///|
/// A root with every top-level role bound to one key id.
fn uniform_root(version : Int, keyid : String, threshold : Int) -> String {
  root_document(version, all_roles(threshold, [keyid]), [keyid])
}

///|
/// A fresh findings buffer, so the tests do not repeat the type annotation.
fn empty_findings() -> Array[Finding] {
  []
}

///|
test "signature key ids and values are read in document order" {
  let document = "{\"signed\":{},\"signatures\":[{\"keyid\":\"a\",\"sig\":\"s1\"},{\"keyid\":\"b\",\"sig\":\"s2\"},{\"keyid\":\"a\",\"sig\":\"s3\"}]}"
  assert_eq(signature_keyids(document), ["a", "b", "a"])
  assert_eq(signature_values(document), ["s1", "s2", "s3"])
  assert_eq(distinct(signature_keyids(document)), ["a", "b"])
  // A signature needs both a key id and a value to count; malformed entries are
  // skipped here because the shape check already reports them.
  let broken = "{\"signed\":{},\"signatures\":[7,{\"keyid\":\"\"},{\"keyid\":\"c\"},{\"sig\":\"x\"},{\"keyid\":\"d\",\"sig\":\"s\"}]}"
  assert_eq(signature_keyids(broken), ["d"])
  assert_eq(signature_values(broken), ["x", "s"])
  assert_eq(signature_keyids("{"), [])
  assert_eq(signature_values("[]"), [])
  assert_eq(signature_keyids("{\"signatures\":\"no\"}"), [])
  assert_eq(distinct([]), [])
  assert_true(contains_keyid(["a", "b"], "b"))
  assert_false(contains_keyid(["a", "b"], "c"))
  assert_false(contains_keyid([], "a"))
}

///|
test "the authorized signature count compares against the threshold" {
  assert_eq(count_authorized(["a", "b"], ["a", "b", "c"]), 2)
  assert_eq(count_authorized(["a", "a", "b"], ["a", "b"]), 2)
  assert_eq(count_authorized(["z"], ["a"]), 0)
  assert_eq(count_authorized([], ["a"]), 0)
  assert_eq(unexpected_signers(["a", "z", "y"], ["a"], []), ["z", "y"])
  assert_eq(unexpected_signers(["a"], ["a", "b"], []), [])
  // A key belonging to the document's own role is not unexpected, which is what
  // makes a rotation signed by both the old and the new key clean.
  assert_eq(unexpected_signers(["old", "new"], ["old"], ["new"]), [])
}

///|
test "authorization is satisfied only when the threshold is met" {
  let root = root_document(1, all_roles(2, ["k1", "k2"]), ["k1", "k2"])
  let satisfied = check_authorization(root, root, "root")
  assert_true(satisfied.is_satisfied())
  assert_eq(satisfied.threshold(), 2)
  assert_eq(satisfied.satisfied_count(), 2)
  assert_eq(satisfied.outcome().to_string(), "satisfied")
  assert_eq(satisfied.authorized_keyids(), ["k1", "k2"])
  // One signature is not enough for a threshold of two.
  let one_signature = root_document(1, all_roles(2, ["k1", "k2"]), ["k1"])
  let unsatisfied = check_authorization(root, one_signature, "root")
  assert_false(unsatisfied.is_satisfied())
  assert_eq(unsatisfied.outcome().to_string(), "unsatisfied")
  assert_eq(unsatisfied.satisfied_count(), 1)
  // Repeated signatures by the same key do not raise the count.
  let repeated = root_document(1, all_roles(2, ["k1", "k2"]), ["k1", "k1"])
  assert_eq(check_authorization(root, repeated, "root").satisfied_count(), 1)
}

///|
test "a signer outside the role is reported but does not satisfy it" {
  let root = uniform_root(1, "k1", 1)
  let outsider = "{\"signed\":{\"_type\":\"root\",\"version\":1},\"signatures\":[{\"keyid\":\"k9\",\"sig\":\"s\"}]}"
  let authorization = check_authorization(root, outsider, "root")
  assert_eq(authorization.satisfied_count(), 0)
  assert_eq(authorization.outcome().to_string(), "unsatisfied")
  assert_eq(
    unexpected_signers(authorization.keyids, authorization.authorized_keyids, []),
    ["k9"],
  )
  let findings = empty_findings()
  authorization_findings(authorization, outsider, findings)
  let codes = findings.map(finding => finding.to_string())
  assert_true(codes.contains("error:insufficient-signatures:root:0/1"))
  assert_true(codes.contains("warning:unexpected-signer:root:k9"))
}

///|
test "an unusable role makes the verdict undecidable" {
  // A root without a `roles` table cannot authorize anything.
  let no_roles = "{\"signed\":{\"_type\":\"root\",\"version\":1,\"expires\":\"2030-01-01T00:00:00Z\"},\"signatures\":[{\"keyid\":\"k1\",\"sig\":\"s\"}]}"
  let authorization = check_authorization(no_roles, no_roles, "root")
  assert_eq(authorization.outcome().to_string(), "undecidable")
  assert_false(authorization.is_satisfied())
  let findings = empty_findings()
  authorization_findings(authorization, no_roles, findings)
  assert_true(
    findings.map(finding => finding.to_string()).contains(
      "error:unverifiable-role:root",
    ),
  )
  // The same for a role the root does not define.
  let root = uniform_root(1, "k1", 1)
  assert_eq(
    check_authorization(root, root, "mirrors").outcome().to_string(),
    "undecidable",
  )
}

///|
test "authorized keys and thresholds are read from a root" {
  let root = root_document(
    1,
    [
      ("root", 2, ["k1", "k2"]),
      ("timestamp", 1, ["k1"]),
      ("snapshot", 1, ["k1"]),
      ("targets", 1, ["k2"]),
    ],
    ["k1", "k2"],
  )
  assert_eq(authorized_keyids(root, "root"), Some(["k1", "k2"]))
  assert_eq(authorized_keyids(root, "targets"), Some(["k2"]))
  assert_eq(authorized_keyids(root, "timestamp"), Some(["k1"]))
  assert_eq(role_threshold(root, "root"), Some(2))
  assert_eq(role_threshold(root, "targets"), Some(1))
  assert_eq(authorized_keyids(root, "mirrors"), None)
  assert_eq(role_threshold(root, "mirrors"), None)
  assert_eq(authorized_keyids("{", "root"), None)
  // Non-string key ids are dropped here; the shape check reports them.
  let mixed = "{\"signed\":{\"_type\":\"root\",\"version\":1,\"roles\":{\"root\":{\"threshold\":1,\"keyids\":[\"k1\",7]}}},\"signatures\":[]}"
  assert_eq(authorized_keyids(mixed, "root"), Some(["k1"]))
}

///|
test "a root rotation is authorized by the previous root" {
  // Version 1 trusts k1 only; version 2 replaces it with k2 and carries both
  // signatures, which is the rotation a client can actually process.
  let first = uniform_root(1, "k1", 1)
  let second = root_document(2, all_roles(1, ["k2"]), ["k1", "k2"])
  let findings = empty_findings()
  check_root_chain([first, second], findings)
  assert_eq(findings.map(finding => finding.to_string()), [])
  // Signed only by its own new key, the rotation is refused by a real client.
  let badly_signed = root_document(2, all_roles(1, ["k2"]), ["k2"])
  let broken = empty_findings()
  check_root_chain([first, badly_signed], broken)
  let codes = broken.map(finding => finding.to_string())
  assert_true(codes.contains("error:insufficient-signatures:root:0/1"))
}

///|
test "a rotation must satisfy the previous root threshold" {
  // The trusted root needs two keys, but the new root carries only one of them.
  let stricter = root_document(1, all_roles(2, ["k1", "k2"]), ["k1", "k2"])
  let one_signature = root_document(2, all_roles(2, ["k1", "k2"]), ["k1"])
  let findings = empty_findings()
  check_root_chain([stricter, one_signature], findings)
  assert_true(
    findings.map(finding => finding.to_string()).contains(
      "error:insufficient-signatures:root:1/2",
    ),
  )
  // Raising the new root's own threshold does not break the rotation: the client
  // authorizes the update with the previous root's role, so the verdict stays
  // satisfied even though the new root would need two keys for itself.
  let raised = root_document(2, all_roles(2, ["k1", "k2"]), ["k1"])
  let raised_findings = empty_findings()
  check_root_chain([uniform_root(1, "k1", 1), raised], raised_findings)
  assert_eq(raised_findings.map(finding => finding.to_string()), [])
}

///|
test "root versions in a chain must be consecutive" {
  let first = uniform_root(1, "k1", 1)
  let third = root_document(3, all_roles(1, ["k1"]), ["k1"])
  let findings = empty_findings()
  check_root_chain([first, third], findings)
  assert_true(
    findings.map(finding => finding.to_string()).contains(
      "error:non-consecutive-root-version:root[1]:expected=2,actual=3",
    ),
  )
  // A repeated version is not an increment either.
  let repeat = empty_findings()
  check_root_chain([first, first], repeat)
  assert_true(
    repeat.map(finding => finding.to_string()).contains(
      "error:non-consecutive-root-version:root[1]:expected=2,actual=1",
    ),
  )
  // A document with no usable version is reported against its own index.
  let undated = "{\"signed\":{\"spec_version\":\"1.0.31\",\"_type\":\"root\",\"expires\":\"2030-01-01T00:00:00Z\",\"keys\":{},\"roles\":{}},\"signatures\":[{\"keyid\":\"k1\",\"sig\":\"s\"}]}"
  let missing = empty_findings()
  check_root_chain([first, undated], missing)
  assert_true(
    missing.map(finding => finding.to_string()).contains(
      "error:missing-root-version:root[1]",
    ),
  )
}

///|
test "a single root chain only checks its own role" {
  let root = uniform_root(1, "k1", 1)
  let findings = empty_findings()
  check_root_chain([root], findings)
  assert_eq(findings.map(finding => finding.to_string()), [])
  // An empty chain is a misuse, not a valid rotation.
  let empty = empty_findings()
  check_root_chain([], empty)
  assert_eq(
    empty.map(finding => finding.to_string()),
    ["error:empty-root-chain"],
  )
}

///|
test "chain findings carry the document index" {
  // The second root is structurally broken: it has neither `keys` nor `roles`,
  // and every top-level role is therefore missing as well.
  let first = uniform_root(1, "k1", 1)
  let broken = "{\"signed\":{\"spec_version\":\"1.0.31\",\"_type\":\"root\",\"version\":2,\"expires\":\"2030-01-01T00:00:00Z\"},\"signatures\":[{\"keyid\":\"k1\",\"sig\":\"s\"}]}"
  let findings = empty_findings()
  check_root_chain([first, broken], findings)
  let codes = findings.map(finding => finding.to_string())
  assert_true(codes.contains("error:root[1]:missing-keys"))
  assert_true(codes.contains("error:root[1]:missing-roles"))
  assert_true(codes.contains("error:root[1]:missing-role:targets"))
  // The rotation itself is still authorized: the second root is signed by the
  // key the first root trusts, which is the check a client performs first.
  assert_false(codes.contains("error:unverifiable-role:root"))
  assert_false(codes.contains("error:insufficient-signatures:root"))
  // The convenience wrapper produces the same findings.
  let rendered = preflight_root_chain([first, broken])
  assert_eq(rendered.length(), codes.length())
  assert_true(rendered.contains("error:root[1]:missing-roles"))
  assert_eq(preflight_root_chain([first]), [])
}
