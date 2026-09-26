///|
/// Severity of a single preflight finding.
///
/// `Error` marks a metadata envelope that is structurally invalid for the
/// requested role. `Warning` marks a value that parses but is suspicious, such
/// as a target path that escapes its directory prefix.
pub enum Severity {
  Error
  Warning
}

///|
/// One diagnostic produced by a structural preflight check.
///
/// `code` is a stable, machine-readable identifier such as
/// `invalid-target-hash`; `location` names the offending field owner (a key id,
/// a meta file name or a target path) and is empty when the finding applies to
/// the envelope as a whole.
pub struct Finding {
  severity : Severity
  code : String
  location : String
}

///|
/// The complete preflight result for one metadata document.
///
/// Call [`Report::findings`] for the human-readable diagnostics and
/// [`Report::ok`] or [`Report::has_errors`] for pipeline decisions. A report
/// with no findings is a *structural* statement only: this library never
/// verifies signatures, hashes or the trusted root chain.
pub struct Report {
  findings : Array[Finding]
  role : String
  version : Int?
}

///|
pub fn Severity::to_string(self : Severity) -> String {
  match self {
    Error => "error"
    Warning => "warning"
  }
}

///|
/// The stable `severity:code[:location]` rendering of a finding.
pub fn Finding::to_string(self : Finding) -> String {
  if self.location == "" {
    self.severity.to_string() + ":" + self.code
  } else {
    self.severity.to_string() + ":" + self.code + ":" + self.location
  }
}

///|
/// Whether the document may be handed to a TUF verifier at all.
///
/// `true` means every structural field required by the requested role is
/// present and well formed. It does not mean the update is trusted,
/// unexpired or rollback-safe.
pub fn Report::ok(self : Report) -> Bool {
  self.findings.all(finding => finding.severity is Warning)
}

///|
/// Whether any finding has severity `Error`.
pub fn Report::has_errors(self : Report) -> Bool {
  self.findings.any(finding => finding.severity is Error)
}

///|
/// Number of `Warning` findings.
pub fn Report::warning_count(self : Report) -> Int {
  self.findings.filter(finding => finding.severity is Warning).length()
}

///|
/// Number of `Error` findings.
pub fn Report::error_count(self : Report) -> Int {
  self.findings.filter(finding => finding.severity is Error).length()
}

///|
/// All findings, in detection order.
pub fn Report::findings(self : Report) -> Array[Finding] {
  self.findings.copy()
}

///|
/// The role the report was produced for, as passed to [`preflight_report`].
pub fn Report::role(self : Report) -> String {
  self.role
}

///|
/// The `signed.version` integer, or `None` when it is missing or not an
/// integer in `1 ..= 2147483647`.
pub fn Report::version(self : Report) -> Int? {
  self.version
}

///|
/// The findings rendered as `severity:code[:location]` strings.
pub fn Report::to_strings(self : Report) -> Array[String] {
  self.findings.map(finding => finding.to_string())
}

///|
/// A newline-joined report suitable for printing in a terminal or a CI log.
pub fn Report::render(self : Report) -> String {
  if self.findings.is_empty() {
    return "ok"
  }
  self.to_strings().join("\n")
}

///|
/// Core routine: append findings for `document` interpreted as `role`.
///
/// `role` must be one of `root`, `timestamp`, `snapshot` or `targets`; any
/// other value yields a single `unsupported-role` error and nothing else.
fn collect_findings(
  document : Json,
  role : String,
  findings : Array[Finding],
) -> Int? {
  if role != "root" &&
    role != "timestamp" &&
    role != "snapshot" &&
    role != "targets" {
    findings.push(Finding::{
      severity: Error,
      code: "unsupported-role",
      location: role,
    })
    return None
  }
  let envelope = match document {
    Object(envelope) => envelope
    _ => {
      findings.push(Finding::{
        severity: Error,
        code: "envelope-not-object",
        location: "",
      })
      return None
    }
  }
  let signed = match envelope.get("signed") {
    Some(Object(signed)) => signed
    _ => {
      findings.push(Finding::{
        severity: Error,
        code: "missing-signed-object",
        location: "",
      })
      return None
    }
  }
  check_signatures(envelope, findings)
  match signed.get("_type") {
    Some(String(value)) if value == role => ()
    _ =>
      findings.push(Finding::{
        severity: Error,
        code: "role-mismatch",
        location: role,
      })
  }
  let version = match signed.get("version") {
    Some(Number(value, ..)) if in_int_range(value) => Some(value.to_int())
    _ => {
      findings.push(Finding::{
        severity: Error,
        code: "invalid-version",
        location: "",
      })
      None
    }
  }
  match signed.get("expires") {
    Some(String(value)) if valid_utc_time(value) => ()
    _ =>
      findings.push(Finding::{
        severity: Error,
        code: "invalid-expires",
        location: "",
      })
  }
  // TUF 1.0 metadata declares the specification version it was written for.
  // It is reported as a warning rather than an error because pre-1.0
  // repositories still publish metadata without it, and clients are required to
  // tolerate its absence.
  match signed.get("spec_version") {
    Some(String(value)) if valid_spec_version(value) => ()
    Some(String(value)) =>
      findings.push(Finding::{
        severity: Warning,
        code: "malformed-spec-version",
        location: value,
      })
    _ =>
      findings.push(Finding::{
        severity: Warning,
        code: "missing-spec-version",
        location: "",
      })
  }
  match role {
    "root" => check_root(signed, findings)
    "timestamp" | "snapshot" => check_meta(signed, role, findings)
    "targets" => check_targets(signed, findings)
    _ => ()
  }
  version
}

///|
/// Structurally preflight one TUF metadata envelope.
///
/// `input` is the raw JSON document and `role` the role it claims to be.
/// Malformed JSON yields `error:invalid-json`. See [`Report`] for the meaning
/// of the result, and [`preflight_at`] / [`preflight_bundle`] for expiry and
/// cross-document checks.
pub fn preflight_report(input : String, role : String) -> Report {
  let findings : Array[Finding] = []
  let document = @json.parse(input) catch {
    _ => {
      findings.push(Finding::{
        severity: Error,
        code: "invalid-json",
        location: "",
      })
      return Report::{ findings, role, version: None, }
    }
  }
  let version = collect_findings(document, role, findings)
  Report::{ findings, role, version, }
}

///|
/// [`preflight_report`] collapsed to `severity:code[:location]` strings.
pub fn preflight(input : String, role : String) -> Array[String] {
  preflight_report(input, role).to_strings()
}

///|
/// Preflight a single envelope and additionally compare `expires` with the
/// caller-supplied current UTC time `now`.
///
/// Passing `now` in keeps CI, offline mirrors and Wasm builds reproducible and
/// free of hidden clock reads. The check is deliberately non-strict at the
/// boundary: metadata is reported as expired once `expires <= now`, matching
/// the TUF rule that an update ceases to be valid at `expires`.
pub fn preflight_at_report(
  input : String,
  role : String,
  now : String,
) -> Report {
  let report = preflight_report(input, role)
  let findings = report.findings
  if !valid_utc_time(now) {
    findings.push(Finding::{
      severity: Error,
      code: "invalid-current-time",
      location: "",
    })
    return Report::{ findings, role, version: report.version, }
  }
  match signed_object(input) {
    Some(signed) =>
      match signed.get("expires") {
        Some(String(expires)) if valid_utc_time(expires) =>
          if utc_not_after(expires, now) {
            findings.push(Finding::{
              severity: Error,
              code: "expired",
              location: expires,
            })
          }
        _ => ()
      }
    None => ()
  }
  Report::{ findings, role, version: report.version, }
}

///|
/// [`preflight_at_report`] collapsed to `severity:code[:location]` strings.
pub fn preflight_at(
  input : String,
  role : String,
  now : String,
) -> Array[String] {
  preflight_at_report(input, role, now).to_strings()
}

///|
/// Preflight a `timestamp` / `snapshot` / `targets` triple and check that the
/// versions the documents reference agree with the versions they carry.
///
/// Findings are prefixed with the document they came from, for example
/// `error:timestamp:expired:2030-01-01T00:00:00Z`. A missing or malformed
/// `version` on either side of a reference is reported as
/// `missing-version-reference` or `missing-document-version` instead of being
/// treated as agreement. `now` is the caller-supplied current UTC time.
pub fn preflight_bundle_report(
  timestamp : String,
  snapshot : String,
  targets : String,
  now : String,
) -> Report {
  let findings : Array[Finding] = []
  for
    entry in [
      ("timestamp", timestamp),
      ("snapshot", snapshot),
      ("targets", targets),
    ] {
    let (name, input) = entry
    for finding in preflight_at_report(input, name, now).findings {
      findings.push(Finding::{
        severity: finding.severity,
        code: name + ":" + finding.code,
        location: finding.location,
      })
    }
  }
  check_reference(
    timestamp, "snapshot.json", snapshot, "timestamp", "snapshot-version-mismatch",
    findings,
  )
  check_reference(
    snapshot, "targets.json", targets, "snapshot", "targets-version-mismatch", findings,
  )
  let version = match metadata_version(timestamp) {
    Some(version) => Some(version)
    None => metadata_version(snapshot)
  }
  Report::{ findings, role: "bundle", version, }
}

///|
/// [`preflight_bundle_report`] collapsed to `severity:code[:location]` strings.
pub fn preflight_bundle(
  timestamp : String,
  snapshot : String,
  targets : String,
  now : String,
) -> Array[String] {
  preflight_bundle_report(timestamp, snapshot, targets, now).to_strings()
}

///|
/// Compare `meta[name].version` inside `referrer` with the `version` carried by
/// `target`. Absent or malformed versions on either side are reported instead
/// of being treated as agreement.
fn check_reference(
  referrer : String,
  name : String,
  target : String,
  referrer_role : String,
  mismatch_code : String,
  findings : Array[Finding],
) -> Unit {
  let referenced = referenced_version(referrer, name)
  let actual = metadata_version(target)
  match (referenced, actual) {
    (Some(referenced), Some(actual)) =>
      if referenced != actual {
        findings.push(Finding::{
          severity: Error,
          code: mismatch_code,
          location: "\{name}:referenced=\{referenced},actual=\{actual}",
        })
      }
    (None, _) =>
      findings.push(Finding::{
        severity: Error,
        code: "missing-version-reference",
        location: referrer_role + "->" + name,
      })
    (_, None) =>
      findings.push(Finding::{
        severity: Error,
        code: "missing-document-version",
        location: name,
      })
  }
}

///|
/// Validate the `signatures` array: at least one entry, every entry an object
/// with a non-empty `keyid` and `sig`, and no repeated `keyid`.
///
/// This checks entry *shape* only. No signature is ever verified here.
fn check_signatures(
  envelope : Map[String, Json],
  findings : Array[Finding],
) -> Unit {
  let signatures = match envelope.get("signatures") {
    Some(Array(signatures)) => signatures
    _ => {
      findings.push(Finding::{
        severity: Error,
        code: "missing-signatures-array",
        location: "",
      })
      return
    }
  }
  if signatures.is_empty() {
    findings.push(Finding::{
      severity: Error,
      code: "empty-signatures",
      location: "",
    })
  }
  let seen : Map[String, Bool] = Map([])
  for signature in signatures {
    match signature {
      Object(entry) => {
        let keyid = match entry.get("keyid") {
          Some(String(value)) if value != "" => value
          _ => {
            findings.push(Finding::{
              severity: Error,
              code: "invalid-signature-keyid",
              location: "",
            })
            ""
          }
        }
        match entry.get("sig") {
          Some(String(value)) if value != "" => ()
          _ =>
            findings.push(Finding::{
              severity: Error,
              code: "invalid-signature-value",
              location: keyid,
            })
        }
        if keyid != "" {
          if seen.get(keyid) is Some(_) {
            findings.push(Finding::{
              severity: Error,
              code: "duplicate-signature-keyid",
              location: keyid,
            })
          } else {
            seen[keyid] = true
          }
        }
      }
      _ =>
        findings.push(Finding::{
          severity: Error,
          code: "invalid-signature-entry",
          location: "",
        })
    }
  }
}

///|
/// Validate a `root` document: the `keys` table, the four top-level roles, and
/// for each role the threshold and its key ids.
///
/// A role is unusable when its threshold exceeds the number of *distinct* key
/// ids that exist in `keys`, which is reported as `unreachable-threshold`.
fn check_root(signed : Map[String, Json], findings : Array[Finding]) -> Unit {
  let keys = match signed.get("keys") {
    Some(Object(keys)) => keys
    _ => {
      findings.push(Finding::{
        severity: Error,
        code: "missing-keys",
        location: "",
      })
      return
    }
  }
  let roles = match signed.get("roles") {
    Some(Object(roles)) => roles
    _ => {
      findings.push(Finding::{
        severity: Error,
        code: "missing-roles",
        location: "",
      })
      return
    }
  }
  for entry in keys.iter() {
    let (keyid, key) = entry
    if keyid == "" {
      findings.push(Finding::{
        severity: Error,
        code: "empty-keyid",
        location: "",
      })
    }
    match key {
      Object(config) => {
        match config.get("keytype") {
          Some(String(value)) if value != "" => ()
          _ =>
            findings.push(Finding::{
              severity: Error,
              code: "invalid-keytype",
              location: keyid,
            })
        }
        match config.get("scheme") {
          Some(String(value)) if value != "" => ()
          _ =>
            findings.push(Finding::{
              severity: Error,
              code: "invalid-key-scheme",
              location: keyid,
            })
        }
        match config.get("keyval") {
          Some(Object(keyval)) =>
            match keyval.get("public") {
              Some(String(value)) if value != "" => ()
              _ =>
                findings.push(Finding::{
                  severity: Error,
                  code: "invalid-public-key",
                  location: keyid,
                })
            }
          _ =>
            findings.push(Finding::{
              severity: Error,
              code: "invalid-keyval",
              location: keyid,
            })
        }
      }
      _ =>
        findings.push(Finding::{
          severity: Error,
          code: "invalid-key",
          location: keyid,
        })
    }
  }
  for role in ["root", "timestamp", "snapshot", "targets"] {
    match roles.get(role) {
      Some(Object(config)) => {
        let threshold = match config.get("threshold") {
          Some(Number(value, ..)) if in_int_range(value) => value.to_int()
          _ => {
            findings.push(Finding::{
              severity: Error,
              code: "invalid-threshold",
              location: role,
            })
            0
          }
        }
        check_role_keyids(role, config, keys, threshold, findings)
      }
      _ =>
        findings.push(Finding::{
          severity: Error,
          code: "missing-role",
          location: role,
        })
    }
  }
}

///|
/// Validate one `root` role entry: `keyids` must be a non-empty array of
/// distinct strings that all exist in `keys`, and at least `threshold` of them
/// must do so.
fn check_role_keyids(
  role : String,
  config : Map[String, Json],
  keys : Map[String, Json],
  threshold : Int,
  findings : Array[Finding],
) -> Unit {
  match config.get("keyids") {
    Some(Array(keyids)) => {
      if keyids.is_empty() {
        findings.push(Finding::{
          severity: Error,
          code: "missing-keyids",
          location: role,
        })
      }
      let mut usable = 0
      let seen : Map[String, Bool] = Map([])
      for keyid in keyids {
        match keyid {
          String(name) =>
            if seen.get(name) is Some(_) {
              findings.push(Finding::{
                severity: Error,
                code: "duplicate-keyid",
                location: role + ":" + name,
              })
            } else {
              seen[name] = true
              if keys.get(name) is Some(_) {
                usable += 1
              } else {
                findings.push(Finding::{
                  severity: Error,
                  code: "unknown-keyid",
                  location: role + ":" + name,
                })
              }
            }
          _ =>
            findings.push(Finding::{
              severity: Error,
              code: "invalid-keyid",
              location: role,
            })
        }
      }
      if usable < threshold {
        findings.push(Finding::{
          severity: Error,
          code: "unreachable-threshold",
          location: "\{role}:threshold=\{threshold},usable=\{usable}",
        })
      }
    }
    _ =>
      findings.push(Finding::{
        severity: Error,
        code: "missing-keyids",
        location: role,
      })
  }
}

///|
/// Validate a `timestamp` or `snapshot` document's `meta` table.
///
/// `timestamp` must reference `snapshot.json`, `snapshot` must reference
/// `targets.json`, and every entry needs an integer `version`. The optional
/// `length` and `hashes` fields are checked with the same rules as target
/// entries, because a snapshot that describes a metadata file with a malformed
/// digest would otherwise be accepted silently.
fn check_meta(
  signed : Map[String, Json],
  role : String,
  findings : Array[Finding],
) -> Unit {
  let meta = match signed.get("meta") {
    Some(Object(meta)) => meta
    _ => {
      findings.push(Finding::{
        severity: Error,
        code: "missing-meta",
        location: role,
      })
      return
    }
  }
  if meta.is_empty() {
    findings.push(Finding::{
      severity: Error,
      code: "empty-meta",
      location: role,
    })
  }
  let required = if role == "timestamp" {
    "snapshot.json"
  } else {
    "targets.json"
  }
  if meta.get(required) is None {
    findings.push(Finding::{
      severity: Error,
      code: "missing-meta",
      location: required,
    })
  }
  for entry in meta.iter() {
    let (name, value) = entry
    match value {
      Object(entry) => check_meta_entry(name, entry, findings)
      _ =>
        findings.push(Finding::{
          severity: Error,
          code: "invalid-meta-entry",
          location: name,
        })
    }
  }
}

///|
/// Validate one entry of a `meta` table: a required integer `version`, and the
/// optional `length` and `hashes` fields when they are present.
fn check_meta_entry(
  name : String,
  entry : Map[String, Json],
  findings : Array[Finding],
) -> Unit {
  match entry.get("version") {
    Some(Number(number, ..)) if in_int_range(number) => ()
    _ =>
      findings.push(Finding::{
        severity: Error,
        code: "invalid-meta-version",
        location: name,
      })
  }
  match entry.get("length") {
    None => ()
    Some(Number(length, ..)) if length >= 0.0 &&
      length <= 9007199254740991.0 &&
      length == length.floor() => ()
    _ =>
      findings.push(Finding::{
        severity: Error,
        code: "invalid-meta-length",
        location: name,
      })
  }
  match entry.get("hashes") {
    None => ()
    Some(Object(hashes)) => {
      if hashes.is_empty() {
        findings.push(Finding::{
          severity: Error,
          code: "invalid-meta-hashes",
          location: name,
        })
      }
      for digest in hashes.iter() {
        let (algorithm, value) = digest
        check_digest(
          algorithm,
          value,
          "invalid-meta-hash",
          "unsupported-meta-hash-algorithm",
          name + ":" + algorithm,
          findings,
        )
      }
    }
    Some(_) =>
      findings.push(Finding::{
        severity: Error,
        code: "invalid-meta-hashes",
        location: name,
      })
  }
}

///|
/// Validate a `targets` document: every target path is relative and free of
/// `..`, `.` and backslashes, every target has a non-negative integer `length`
/// and a non-empty `hashes` map whose digests match the declared algorithm.
///
/// Digest checks cover hex characters and length for `sha256`, `sha3-256`,
/// `sha512` and `sha3-512`. No file content is read, so a well-formed digest is
/// never a content check.
fn check_targets(signed : Map[String, Json], findings : Array[Finding]) -> Unit {
  let targets = match signed.get("targets") {
    Some(Object(targets)) => targets
    _ => {
      findings.push(Finding::{
        severity: Error,
        code: "missing-targets",
        location: "",
      })
      return
    }
  }
  for entry in targets.iter() {
    let (name, value) = entry
    if !safe_target_path(name) {
      findings.push(Finding::{
        severity: Error,
        code: "unsafe-target-path",
        location: name,
      })
    }
    match value {
      Object(meta) => {
        match meta.get("length") {
          Some(Number(length, ..)) if length >= 0.0 &&
            length <= 9007199254740991.0 &&
            length == length.floor() => ()
          _ =>
            findings.push(Finding::{
              severity: Error,
              code: "invalid-target-length",
              location: name,
            })
        }
        match meta.get("hashes") {
          Some(Object(hashes)) if !hashes.is_empty() =>
            for digest in hashes.iter() {
              let (algorithm, value) = digest
              check_target_hash(name, algorithm, value, findings)
            }
          _ =>
            findings.push(Finding::{
              severity: Error,
              code: "missing-target-hashes",
              location: name,
            })
        }
        match meta.get("custom") {
          Some(custom) =>
            match custom {
              Object(_) | Null => ()
              _ =>
                findings.push(Finding::{
                  severity: Warning,
                  code: "non-object-target-custom",
                  location: name,
                })
            }
          None => ()
        }
      }
      _ =>
        findings.push(Finding::{
          severity: Error,
          code: "invalid-target-entry",
          location: name,
        })
    }
  }
}

///|
/// Check one `algorithm: digest` pair.
///
/// `location` is `<entry>:<algorithm>`, `invalid_code` is reported when the
/// digest is not a hex string of the length that `algorithm` requires, and
/// `unsupported_code` is reported for algorithms this preflight cannot measure.
/// Both target entries and `snapshot`'s `meta` entries describe file digests, so
/// they share the implementation and differ only in the codes they emit.
fn check_digest(
  algorithm : String,
  value : Json,
  invalid_code : String,
  unsupported_code : String,
  location : String,
  findings : Array[Finding],
) -> Unit {
  let digest = match value {
    String(digest) => digest
    _ => {
      findings.push(Finding::{ severity: Error, code: invalid_code, location, })
      return
    }
  }
  let expected = match algorithm {
    "sha256" | "sha3-256" => 64
    "sha512" | "sha3-512" => 128
    _ => {
      findings.push(Finding::{
        severity: Warning,
        code: unsupported_code,
        location,
      })
      return
    }
  }
  if digest.length() != expected || !valid_hex(digest) {
    findings.push(Finding::{ severity: Error, code: invalid_code, location, })
  }
}

///|
/// Check one `algorithm: digest` pair of a target's `hashes` map.
///
/// Supported digest lengths follow the TUF specification's hash function list.
/// An unknown algorithm is a warning rather than an error because the
/// specification allows repositories to publish additional hash functions; the
/// preflight simply cannot confirm their digest length.
fn check_target_hash(
  name : String,
  algorithm : String,
  value : Json,
  findings : Array[Finding],
) -> Unit {
  check_digest(
    algorithm,
    value,
    "invalid-target-hash",
    "unsupported-target-hash-algorithm",
    name + ":" + algorithm,
    findings,
  )
}

///|
/// Whether `path` is a safe relative TUF target path.
///
/// Rejects empty paths, absolute paths, backslashes, `:` (which would allow a
/// Windows drive or scheme prefix on some consumers), and any empty, `.` or
/// `..` segment.
fn safe_target_path(path : String) -> Bool {
  if path == "" ||
    path.has_prefix("/") ||
    path.contains("\\") ||
    path.contains(":") {
    return false
  }
  for segment in path.split("/") {
    if segment == "" || segment == "." || segment == ".." {
      return false
    }
  }
  true
}

///|
/// Whether every character of `value` is an ASCII hex digit.
fn valid_hex(value : String) -> Bool {
  if value == "" {
    return false
  }
  for char in value.iter() {
    if !((char >= '0' && char <= '9') ||
      (char >= 'a' && char <= 'f') ||
      (char >= 'A' && char <= 'F')) {
      return false
    }
  }
  true
}

///|
/// Whether `value` is an integer that fits a TUF `version` field, that is
/// `1 <= value <= 2147483647`.
fn in_int_range(value : Double) -> Bool {
  value >= 1.0 && value <= 2147483647.0 && value == value.floor()
}
