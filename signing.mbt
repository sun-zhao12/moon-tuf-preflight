// Signature authorization and root-chain rotation checks.
//
// Everything here is *structural*. No cryptographic operation is performed:
// this module never reads a public key, never hashes a canonical encoding and
// never verifies a signature value. What it can answer honestly is:
//
//   * which key ids claim to have signed a document,
//   * whether those key ids are the ones the role authorizes,
//   * whether the number of authorized signatures reaches the threshold,
//   * what bytes a signature would have to cover for a verifier to accept it,
//   * whether a sequence of root documents is a consistent rotation chain.
//
// That last point is where a structural preflight earns its keep: a broken
// rotation chain is invisible to shape checks but guarantees that a real TUF
// client will refuse the update.

///|
/// The key ids listed in an envelope's `signatures` array, in document order.
///
/// An entry counts only when it carries both a non-empty `keyid` and a non-empty
/// `sig`; entries that are not objects or that miss either field are skipped,
/// because [`preflight_report`] already reports those as shape findings and this
/// function is used to decide how many usable signatures a document has.
pub fn signature_keyids(input : String) -> Array[String] {
  let document = @json.parse(input) catch { _ => return [] }
  let envelope = match document {
    Object(envelope) => envelope
    _ => return []
  }
  let signatures = match envelope.get("signatures") {
    Some(Array(signatures)) => signatures
    _ => return []
  }
  let keyids : Array[String] = []
  for signature in signatures {
    match signature {
      Object(entry) => {
        let keyid = match entry.get("keyid") {
          Some(String(keyid)) => keyid
          _ => ""
        }
        let value = match entry.get("sig") {
          Some(String(value)) => value
          _ => ""
        }
        if keyid != "" && value != "" {
          keyids.push(keyid)
        }
      }
      _ => ()
    }
  }
  keyids
}

///|
/// The `sig` values listed in an envelope, in document order, skipping entries
/// that carry no usable value.
///
/// Exposed so a caller can tell "two signatures" from "one signature repeated",
/// and so a test can prove the preflight never treats a signature as valid.
pub fn signature_values(input : String) -> Array[String] {
  let document = @json.parse(input) catch { _ => return [] }
  let envelope = match document {
    Object(envelope) => envelope
    _ => return []
  }
  let signatures = match envelope.get("signatures") {
    Some(Array(signatures)) => signatures
    _ => return []
  }
  let values : Array[String] = []
  for signature in signatures {
    match signature {
      Object(entry) =>
        match entry.get("sig") {
          Some(String(value)) => if value != "" { values.push(value) }
          _ => ()
        }
      _ => ()
    }
  }
  values
}

///|
/// The distinct key ids in `keyids`, in first-seen order.
pub fn distinct(keyids : Array[String]) -> Array[String] {
  let seen : Map[String, Bool] = Map([])
  let result : Array[String] = []
  for keyid in keyids {
    match seen.get(keyid) {
      Some(_) => ()
      None => {
        seen[keyid] = true
        result.push(keyid)
      }
    }
  }
  result
}

///|
/// Whether `keyids` contains `keyid`.
pub fn contains_keyid(keyids : Array[String], keyid : String) -> Bool {
  for candidate in keyids {
    if candidate == keyid {
      return true
    }
  }
  false
}

///|
/// How many distinct key ids in `signature_keyids` are also authorized by the
/// role, which is the number a threshold compares against.
pub fn count_authorized(
  signature_keyids : Array[String],
  authorized_keyids : Array[String],
) -> Int {
  let mut count = 0
  for keyid in distinct(signature_keyids) {
    if contains_keyid(authorized_keyids, keyid) {
      count += 1
    }
  }
  count
}

///|
/// The signature key ids that are neither authorized by the previous root nor
/// part of the document's own role.
///
/// During a root rotation the new root is expected to carry signatures from both
/// the previous root's keys and its own new keys: a client checks the former, and
/// a second client that already holds the new root checks the latter. Reporting
/// the new keys as "unexpected" would therefore be noise, so they are excluded.
pub fn unexpected_signers(
  signature_keyids : Array[String],
  authorized_keyids : Array[String],
  own_keyids : Array[String],
) -> Array[String] {
  let result : Array[String] = []
  for keyid in signature_keyids {
    if !contains_keyid(authorized_keyids, keyid) &&
      !contains_keyid(own_keyids, keyid) {
      result.push(keyid)
    }
  }
  result
}

///|
/// The outcome of a probability-free authorization check: enough authorized
/// signatures, not enough, or a problem that prevented the check entirely.
pub enum AuthorizationOutcome {
  /// At least `threshold` distinct authorized keys signed.
  Satisfied
  /// Fewer than `threshold` distinct authorized keys signed.
  Unsatisfied
  /// The document could not be parsed, or it names a role that does not exist.
  Undecidable
}

///|
/// Whether two verdicts are the same.
pub fn AuthorizationOutcome::equal(
  self : AuthorizationOutcome,
  other : AuthorizationOutcome,
) -> Bool {
  match (self, other) {
    (Satisfied, Satisfied)
    | (Unsatisfied, Unsatisfied)
    | (Undecidable, Undecidable) => true
    _ => false
  }
}

///|
/// A short name for the verdict, used in tests and log lines.
pub fn AuthorizationOutcome::to_string(self : AuthorizationOutcome) -> String {
  match self {
    Satisfied => "satisfied"
    Unsatisfied => "unsatisfied"
    Undecidable => "undecidable"
  }
}

///|
/// A structural authorization verdict for one document against one role.
pub struct Authorization {
  role : String
  keyids : Array[String]
  threshold : Int
  satisfied_count : Int
  authorized_keyids : Array[String]
  outcome : AuthorizationOutcome
}

///|
/// The role that was checked.
pub fn Authorization::role(self : Authorization) -> String {
  self.role
}

///|
/// The declared threshold, or `0` when the role entry was unusable.
pub fn Authorization::threshold(self : Authorization) -> Int {
  self.threshold
}

///|
/// How many distinct authorized keys signed the document.
pub fn Authorization::satisfied_count(self : Authorization) -> Int {
  self.satisfied_count
}

///|
/// The key ids the role authorizes, in root document order.
pub fn Authorization::authorized_keyids(self : Authorization) -> Array[String] {
  self.authorized_keyids
}

///|
/// The verdict.
pub fn Authorization::outcome(self : Authorization) -> AuthorizationOutcome {
  self.outcome
}

///|
/// Whether the document carries enough authorized signatures to be considered
/// by a verifier. Never a statement that any signature is valid.
pub fn Authorization::is_satisfied(self : Authorization) -> Bool {
  self.outcome is Satisfied
}

///|
/// The key ids of `role` from a `root` document, or `None` when the root is not
/// usable or does not define the role.
pub fn authorized_keyids(root : String, role : String) -> Array[String]? {
  let signed = signed_object(root)
  let signed = match signed {
    Some(signed) => signed
    None => return None
  }
  match role_keyids(signed, role) {
    Some(keyids) => Some(keyids)
    None => None
  }
}

///|
/// A root role's `keyids` array, or `None` when the roles table or the entry is
/// missing or not an array of strings.
///
/// Non-string elements are dropped here; shape checks report them separately.
fn role_keyids(signed : Map[String, Json], role : String) -> Array[String]? {
  let roles = match signed.get("roles") {
    Some(Object(roles)) => roles
    _ => return None
  }
  let entry = match roles.get(role) {
    Some(Object(entry)) => entry
    _ => return None
  }
  match entry.get("keyids") {
    Some(Array(keyids)) => {
      let result : Array[String] = []
      for keyid in keyids {
        match keyid {
          String(name) => result.push(name)
          _ => ()
        }
      }
      Some(result)
    }
    _ => None
  }
}

///|
/// A root role's `threshold`, or `None` when it is missing or not a positive
/// integer.
pub fn role_threshold(root : String, role : String) -> Int? {
  let signed = match signed_object(root) {
    Some(signed) => signed
    None => return None
  }
  let roles = match signed.get("roles") {
    Some(Object(roles)) => roles
    _ => return None
  }
  let entry = match roles.get(role) {
    Some(Object(entry)) => entry
    _ => return None
  }
  match entry.get("threshold") {
    Some(Number(value, ..)) if in_int_range(value) => Some(value.to_int())
    _ => None
  }
}

///|
/// Check whether `document` carries enough authorized signatures for `role`, as
/// authorized by `root`.
///
/// `root` is the root metadata whose `roles[role]` entry applies: the document's
/// own root when checking a root at its own version, or the previous root when
/// checking a rotation.
pub fn check_authorization(
  root : String,
  document : String,
  role : String,
) -> Authorization {
  let signature_keyids = signature_keyids(document)
  let keyids = match authorized_keyids(root, role) {
    Some(keyids) => keyids
    None =>
      return Authorization::{
        role,
        keyids: signature_keyids,
        threshold: 0,
        satisfied_count: 0,
        authorized_keyids: [],
        outcome: Undecidable,
      }
  }
  let threshold = match role_threshold(root, role) {
    Some(threshold) => threshold
    None =>
      return Authorization::{
        role,
        keyids: signature_keyids,
        threshold: 0,
        satisfied_count: 0,
        authorized_keyids: keyids,
        outcome: Undecidable,
      }
  }
  let satisfied_count = count_authorized(signature_keyids, keyids)
  Authorization::{
    role,
    keyids: signature_keyids,
    threshold,
    satisfied_count,
    authorized_keyids: keyids,
    outcome: if satisfied_count >= threshold {
      Satisfied
    } else {
      Unsatisfied
    },
  }
}

///|
/// Append the findings for one authorization verdict to `findings`.
///
/// `document` is the metadata being authorized. Its own role key ids are read so
/// that, during a root rotation, the new root's own keys are not reported as
/// unexpected signers: a client that already holds that root checks them.
pub fn authorization_findings(
  authorization : Authorization,
  document : String,
  findings : Array[Finding],
) -> Unit {
  let role = authorization.role
  match authorization.outcome {
    Undecidable =>
      findings.push(Finding::{
        severity: Error,
        code: "unverifiable-role:" + role,
        location: "",
      })
    Satisfied => ()
    Unsatisfied =>
      findings.push(Finding::{
        severity: Error,
        code: "insufficient-signatures:" + role,
        location: "\{authorization.satisfied_count}/\{authorization.threshold}",
      })
  }
  let own_keyids = match authorized_keyids(document, role) {
    Some(keyids) => keyids
    None => []
  }
  for
    keyid in unexpected_signers(
      authorization.keyids,
      authorization.authorized_keyids,
      own_keyids,
    ) {
    findings.push(Finding::{
      severity: Warning,
      code: "unexpected-signer:" + role,
      location: keyid,
    })
  }
}

///|
/// Which key ids signed each document of a root chain, in the order the
/// documents were supplied.
///
/// The chain is the sequence a client walks while rotating trust: the
/// authoritative root first, then each newer root in turn.
pub fn chain_signers(chain : ArrayView[String]) -> Array[Array[String]] {
  let result : Array[Array[String]] = []
  for document in chain {
    result.push(signature_keyids(document))
  }
  result
}

///|
/// The version numbers of a root chain, with `None` for a document whose
/// version field is missing or malformed.
pub fn chain_versions(chain : ArrayView[String]) -> Array[Int?] {
  let result : Array[Int?] = []
  for document in chain {
    result.push(metadata_version(document))
  }
  result
}

///|
/// Append findings for a root rotation chain.
///
/// `chain[0]` is the root the caller already trusts; every later element must
/// be the next version and must be signed by keys authorized by its immediate
/// predecessor's `root` role, because that is the only root a client would hold
/// when it processes the update. Cryptographic verification is out of scope, so
/// a chain that is structurally consistent here can still fail in a real
/// verifier.
pub fn check_root_chain(
  chain : ArrayView[String],
  findings : Array[Finding],
) -> Unit {
  if chain.length() == 0 {
    findings.push(Finding::{
      severity: Error,
      code: "empty-root-chain",
      location: "",
    })
    return
  }
  // Every root must be structurally usable before the rotation itself is judged.
  for index in 0..<chain.length() {
    let report = preflight_report(chain[index], "root")
    for finding in report.findings {
      findings.push(Finding::{
        severity: finding.severity,
        code: "root[" + index.to_string() + "]:" + finding.code,
        location: finding.location,
      })
    }
  }
  if chain.length() == 1 {
    // A single root has no predecessor; it must satisfy its own role.
    authorization_findings(
      check_authorization(chain[0], chain[0], "root"),
      chain[0],
      findings,
    )
    return
  }
  let versions = chain_versions(chain)
  for index in 1..<chain.length() {
    let previous_version = versions[index - 1]
    let current_version = versions[index]
    let location = "root[" + index.to_string() + "]"
    match (previous_version, current_version) {
      (Some(previous), Some(current)) =>
        if current != previous + 1 {
          findings.push(Finding::{
            severity: Error,
            code: "non-consecutive-root-version",
            location: "\{location}:expected=\{previous + 1},actual=\{current}",
          })
        }
      (None, _) =>
        findings.push(Finding::{
          severity: Error,
          code: "missing-root-version",
          location: "root[" + (index - 1).to_string() + "]",
        })
      (_, None) =>
        findings.push(Finding::{
          severity: Error,
          code: "missing-root-version",
          location,
        })
    }
    // The rotation is authorized by the *previous* root's root role.
    authorization_findings(
      check_authorization(chain[index - 1], chain[index], "root"),
      chain[index],
      findings,
    )
  }
}

///|
/// Findings for a root rotation chain, as `severity:code[:location]` strings.
pub fn preflight_root_chain(chain : ArrayView[String]) -> Array[String] {
  let findings : Array[Finding] = []
  check_root_chain(chain, findings)
  Report::{ findings, role: "root-chain", version: None, }.to_strings()
}
