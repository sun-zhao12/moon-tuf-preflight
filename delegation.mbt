// Delegation structure and snapshot coverage checks.
//
// TUF lets the targets role hand authority to delegated targets roles, forming a
// tree: each delegation names the keys that may sign the delegated metadata, a
// threshold, a set of path patterns or path-hash prefixes, and whether the
// delegation terminates the search. A preflight cannot verify the delegated
// signatures (that is a verifier's job) but it can catch the structural mistakes
// that make a repository unusable:
//
//   * a delegation whose key ids are not in the document's `keys`,
//   * a delegation whose threshold can never be reached,
//   * a delegation that declares neither `paths` nor `path_hash_prefixes`,
//     which would authorize every path by accident,
//   * the same role name delegated twice,
//   * a cycle in the delegation tree,
//   * a snapshot that does not list a targets file the repository needs, or
//     lists one that is not present.
//
// Path globs follow the specification's rule: `*` matches a single path
// segment, `?` matches one character, and `[...]` matches one character from a
// set, all within one segment.

///|
/// One entry of a `delegations.roles` array.
pub struct Delegation {
  /// The delegated role's name.
  name : String
  /// The key ids the delegation authorizes.
  keyids : Array[String]
  /// The number of authorized signatures the delegated metadata needs.
  threshold : Int
  /// The `paths` globs, in document order.
  paths : Array[String]
  /// The `path_hash_prefixes`, in document order.
  path_hash_prefixes : Array[String]
  /// Whether the delegation stops the search.
  terminating : Bool
  /// Whether the entry itself parsed; a malformed entry is reported by index.
  well_formed : Bool
}

///|
/// The delegated role's name.
pub fn Delegation::name(self : Delegation) -> String {
  self.name
}

///|
/// The key ids the delegation authorizes.
pub fn Delegation::keyids(self : Delegation) -> Array[String] {
  self.keyids
}

///|
/// The number of authorized signatures the delegated metadata needs.
pub fn Delegation::threshold(self : Delegation) -> Int {
  self.threshold
}

///|
/// The declared `paths` globs.
pub fn Delegation::paths(self : Delegation) -> Array[String] {
  self.paths
}

///|
/// The declared `path_hash_prefixes`.
pub fn Delegation::path_hash_prefixes(self : Delegation) -> Array[String] {
  self.path_hash_prefixes
}

///|
/// Whether the delegation terminates the search.
pub fn Delegation::terminating(self : Delegation) -> Bool {
  self.terminating
}

///|
/// Whether the entry had all the fields a delegation needs.
pub fn Delegation::is_well_formed(self : Delegation) -> Bool {
  self.well_formed
}

///|
/// Read the `delegations.roles` array of a `targets` document.
///
/// Returns `None` when the document has no `delegations` object, which is valid:
/// delegation is optional. An entry that cannot be read is still returned, with
/// `well_formed` false, so the caller can report it by index.
pub fn parse_delegations(targets : String) -> Array[Delegation]? {
  let signed = match signed_object(targets) {
    Some(signed) => signed
    None => return None
  }
  let delegations = match signed.get("delegations") {
    Some(Object(delegations)) => delegations
    _ => return None
  }
  let roles = match delegations.get("roles") {
    Some(Array(roles)) => roles
    _ => return None
  }
  let result : Array[Delegation] = []
  for entry in roles {
    result.push(parse_delegation(entry))
  }
  Some(result)
}

///|
/// Read one delegation entry, tolerating missing fields.
fn parse_delegation(entry : Json) -> Delegation {
  let fields = match entry {
    Object(fields) => fields
    _ => {
      return Delegation::{
        name: "",
        keyids: [],
        threshold: 0,
        paths: [],
        path_hash_prefixes: [],
        terminating: false,
        well_formed: false,
      }
    }
  }
  let name = match fields.get("name") {
    Some(String(name)) => name
    _ => ""
  }
  let keyids = match fields.get("keyids") {
    Some(Array(keyids)) => string_array(keyids)
    _ => []
  }
  let threshold = match fields.get("threshold") {
    Some(Number(value, ..)) if in_int_range(value) => value.to_int()
    _ => 0
  }
  let paths = match fields.get("paths") {
    Some(Array(paths)) => string_array(paths)
    _ => []
  }
  let path_hash_prefixes = match fields.get("path_hash_prefixes") {
    Some(Array(prefixes)) => string_array(prefixes)
    _ => []
  }
  let terminating = match fields.get("terminating") {
    Some(True) => true
    _ => false
  }
  let well_formed = name != "" && keyids.length() > 0 && threshold > 0
  Delegation::{
    name,
    keyids,
    threshold,
    paths,
    path_hash_prefixes,
    terminating,
    well_formed,
  }
}

///|
/// The strings of a JSON array, dropping non-string elements.
fn string_array(values : Array[Json]) -> Array[String] {
  let result : Array[String] = []
  for value in values {
    match value {
      String(text) => result.push(text)
      _ => ()
    }
  }
  result
}

///|
/// Whether `path` matches the delegation glob `pattern`.
///
/// The specification's globs never cross a path separator, so `*` matches any
/// run of characters inside one segment, `?` matches one character, and a
/// `[abc]` / `[a-z]` class matches one character from the set. A trailing
/// pattern of `*` therefore does not match a nested path, which is the rule a
/// client applies.
pub fn path_matches(pattern : String, path : String) -> Bool {
  let pattern_chars = pattern.iter().to_array()
  let path_chars = path.iter().to_array()
  match_glob(pattern_chars, 0, path_chars, 0)
}

///|
/// Recursive glob matcher over two character arrays.
fn match_glob(
  pattern : Array[Char],
  pattern_index : Int,
  path : Array[Char],
  path_index : Int,
) -> Bool {
  if pattern_index >= pattern.length() {
    return path_index >= path.length()
  }
  let token = pattern[pattern_index]
  if token == '*' {
    // Try every split, but never cross a separator.
    let mut cursor = path_index
    while cursor <= path.length() {
      if match_glob(pattern, pattern_index + 1, path, cursor) {
        return true
      }
      if cursor < path.length() && path[cursor] == '/' {
        return false
      }
      cursor += 1
    }
    return false
  }
  if path_index >= path.length() {
    return false
  }
  if token == '?' {
    return path[path_index] != '/' &&
      match_glob(pattern, pattern_index + 1, path, path_index + 1)
  }
  if token == '[' {
    let (matched, consumed) = match_class(pattern, pattern_index, path[path_index])
    if !matched {
      return false
    }
    return match_glob(pattern, pattern_index + consumed, path, path_index + 1)
  }
  if token == path[path_index] {
    return match_glob(pattern, pattern_index + 1, path, path_index + 1)
  }
  false
}

///|
/// Match one character against the `[...]` class starting at `start`.
///
/// Returns whether it matched and how many pattern characters the class used.
/// An unterminated class consumes the rest of the pattern and matches nothing.
fn match_class(
  pattern : Array[Char],
  start : Int,
  char : Char,
) -> (Bool, Int) {
  let mut index = start + 1
  let negated = index < pattern.length() &&
    (pattern[index] == '!' || pattern[index] == '^')
  if negated {
    index += 1
  }
  let mut matched = false
  let mut closed = false
  while index < pattern.length() {
    if pattern[index] == ']' && index > start + 1 {
      closed = true
      index += 1
      break
    }
    if index + 2 < pattern.length() &&
      pattern[index + 1] == '-' &&
      pattern[index + 2] != ']' {
      if char >= pattern[index] && char <= pattern[index + 2] {
        matched = true
      }
      index += 3
    } else {
      if char == pattern[index] {
        matched = true
      }
      index += 1
    }
  }
  if !closed {
    return (false, pattern.length() - start)
  }
  if negated {
    return (!matched, index - start)
  }
  (matched, index - start)
}

///|
/// Whether any of `patterns` matches `path`.
pub fn any_path_matches(patterns : Array[String], path : String) -> Bool {
  for pattern in patterns {
    if path_matches(pattern, path) {
      return true
    }
  }
  false
}

///|
/// Whether `prefix` is a prefix of `path` under the specification's
/// `path_hash_prefixes` rule.
///
/// The client compares the prefix against the hexadecimal digest of the target
/// path, so a preflight can only check that the prefix looks like a hex string
/// and that the two strings relate as a prefix; it cannot compute the digest
/// without hashing, which is deliberately out of scope.
pub fn is_hex_prefix(prefix : String, digest : String) -> Bool {
  if prefix == "" || prefix.length() > digest.length() {
    return false
  }
  if !valid_hex(prefix) {
    return false
  }
  let prefix_chars = prefix.iter().to_array()
  let digest_chars = digest.iter().to_array()
  for index in 0..<prefix_chars.length() {
    if prefix_chars[index] != digest_chars[index] {
      return false
    }
  }
  true
}

///|
/// Append findings for the delegation tree of one `targets` document.
///
/// `findings` receives one finding per problem, with the delegated role name as
/// the location so a caller can point at the exact entry.
pub fn check_delegations(targets : String, findings : Array[Finding]) -> Unit {
  let delegations = match parse_delegations(targets) {
    Some(delegations) => delegations
    None => return
  }
  let keys = document_keys(targets)
  let seen : Map[String, Bool] = Map([])
  for index in 0..<delegations.length() {
    let delegation = delegations[index]
    let location = if delegation.name == "" {
      "roles[" + index.to_string() + "]"
    } else {
      delegation.name
    }
    if !delegation.well_formed {
      findings.push(Finding::{
        severity: Error,
        code: "malformed-delegation",
        location,
      })
      continue
    }
    match seen.get(delegation.name) {
      Some(_) =>
        findings.push(Finding::{
          severity: Error,
          code: "duplicate-delegation",
          location,
        })
      None => seen[delegation.name] = true
    }
    if delegation.paths.length() == 0 &&
      delegation.path_hash_prefixes.length() == 0 {
      findings.push(Finding::{
        severity: Error,
        code: "delegation-without-paths",
        location,
      })
    }
    let mut usable = 0
    let distinct_keyids = distinct(delegation.keyids)
    for keyid in distinct_keyids {
      match keys.get(keyid) {
        Some(_) => usable += 1
        None =>
          findings.push(Finding::{
            severity: Error,
            code: "unknown-delegation-keyid",
            location: location + ":" + keyid,
          })
      }
    }
    if usable < delegation.threshold {
      findings.push(Finding::{
        severity: Error,
        code: "unreachable-delegation-threshold",
        location: "\{location}:threshold=\{delegation.threshold},usable=\{usable}",
      })
    }
    for prefix in delegation.path_hash_prefixes {
      if prefix == "" || !valid_hex(prefix) {
        findings.push(Finding::{
          severity: Error,
          code: "malformed-path-hash-prefix",
          location: location + ":" + prefix,
        })
      }
    }
    for pattern in delegation.paths {
      if !plausible_target_glob(pattern) {
        findings.push(Finding::{
          severity: Warning,
          code: "suspicious-delegation-path",
          location: location + ":" + pattern,
        })
      }
    }
  }
}

///|
/// The `keys` map of a `signed` document, or an empty map when there is none.
fn document_keys(input : String) -> Map[String, Json] {
  let signed = match signed_object(input) {
    Some(signed) => signed
    None => return Map([])
  }
  match signed.get("keys") {
    Some(Object(keys)) => keys
    _ => Map([])
  }
}

///|
/// Whether a delegation glob is worth trusting.
///
/// A pattern that is empty, absolute, or contains a `..` segment would authorize
/// paths outside the repository's target tree, so it is flagged even though the
/// glob itself is syntactically fine.
fn plausible_target_glob(pattern : String) -> Bool {
  if pattern == "" || pattern.has_prefix("/") || pattern.contains("\\") {
    return false
  }
  for segment in pattern.split("/") {
    if segment == ".." {
      return false
    }
  }
  true
}

///|
/// The role names reachable from `root_role` in a delegation tree.
///
/// `edges` maps a role name to the names it delegates to. The walk is
/// breadth-first and remembers what it has visited, so a cycle in the graph
/// cannot make it loop forever.
pub fn reachable_roles(
  root_role : String,
  edges : Map[String, Array[String]],
) -> Array[String] {
  let visited : Map[String, Bool] = Map([])
  let queue : Array[String] = [root_role]
  let order : Array[String] = []
  let mut index = 0
  while index < queue.length() {
    let role = queue[index]
    index += 1
    match visited.get(role) {
      Some(_) => ()
      None => {
        visited[role] = true
        order.push(role)
        match edges.get(role) {
          Some(children) =>
            for child in children {
              queue.push(child)
            }
          None => ()
        }
      }
    }
  }
  order
}

///|
/// The delegation edges declared by a single `targets` document, mapping the
/// document's own role name to the roles it delegates to.
///
/// Each delegated role is expected to have its own metadata file; this function
/// only records the edge, and [`check_delegation_tree`] walks the whole graph.
pub fn delegation_edges(targets : String) -> Map[String, Array[String]] {
  let signed = match signed_object(targets) {
    Some(signed) => signed
    None => return Map([])
  }
  let role = match signed.get("_type") {
    Some(String(role)) => role
    _ => "targets"
  }
  let children = match parse_delegations(targets) {
    Some(delegations) => {
      let names : Array[String] = []
      for delegation in delegations {
        if delegation.well_formed {
          names.push(delegation.name)
        }
      }
      names
    }
    None => []
  }
  let edges : Map[String, Array[String]] = Map([])
  edges[role] = children
  edges
}

///|
/// Append findings for a whole delegation tree.
///
/// `documents` maps a role name to its metadata text, including the top-level
/// `targets` role. The check reports a delegated role whose metadata is missing,
/// a cycle, and a document that tries to delegate a role it does not own.
pub fn check_delegation_tree(
  documents : Map[String, String],
  findings : Array[Finding],
) -> Unit {
  let edges : Map[String, Array[String]] = Map([])
  for entry in documents.iter() {
    let (role, text) = entry
    let declared = delegation_edges(text)
    match declared.get(role) {
      Some(children) => edges[role] = children
      None => ()
    }
  }
  for entry in documents.iter() {
    let (role, text) = entry
    check_delegations(text, findings)
    let children = match edges.get(role) {
      Some(children) => children
      None => []
    }
    for child in children {
      if documents.get(child) is None {
        findings.push(Finding::{
          severity: Error,
          code: "missing-delegated-metadata",
          location: role + "->" + child,
        })
      }
    }
    // A cycle means the same metadata is reachable from itself, which no client
    // can resolve into a stable search order.
    if child_can_reach(role, role, edges, []) {
      findings.push(Finding::{
        severity: Error,
        code: "delegation-cycle",
        location: role,
      })
    }
  }
}

///|
/// Whether `target` is reachable from any child of `child_role`.
fn child_can_reach(
  child_role : String,
  target : String,
  edges : Map[String, Array[String]],
  visited : Array[String],
) -> Bool {
  let children = match edges.get(child_role) {
    Some(children) => children
    None => return false
  }
  for child in children {
    if child == target {
      return true
    }
    if contains_keyid(visited, child) {
      continue
    }
    if child_can_reach(child, target, edges, visited + [child]) {
      return true
    }
  }
  false
}

///|
/// Append findings that compare a `snapshot` document against the targets
/// documents it claims to describe.
///
/// `snapshot` is `snapshot.json` text and `targets_versions` maps a metadata
/// path such as `targets.json` to the version the corresponding document
/// actually carries. A snapshot that omits a document the caller supplied, or
/// names one the caller did not supply, cannot be resolved by a client.
pub fn check_snapshot_coverage(
  snapshot : String,
  targets_versions : Map[String, Int],
  findings : Array[Finding],
) -> Unit {
  let signed = match signed_object(snapshot) {
    Some(signed) => signed
    None => {
      findings.push(Finding::{
        severity: Error,
        code: "missing-signed-object",
        location: "snapshot",
      })
      return
    }
  }
  let meta = match signed.get("meta") {
    Some(Object(meta)) => meta
    _ => {
      findings.push(Finding::{
        severity: Error,
        code: "missing-meta",
        location: "snapshot",
      })
      return
    }
  }
  for entry in targets_versions.iter() {
    let (path, version) = entry
    match meta.get(path) {
      Some(Object(record)) =>
        match record.get("version") {
          Some(Number(value, ..)) if in_int_range(value) =>
            if value.to_int() != version {
              findings.push(Finding::{
                severity: Error,
                code: "snapshot-version-mismatch",
                location: "\{path}:referenced=\{value.to_int()},actual=\{version}",
              })
            }
          _ =>
            findings.push(Finding::{
              severity: Error,
              code: "missing-document-version",
              location: path,
            })
        }
      Some(_) =>
        findings.push(Finding::{
          severity: Error,
          code: "invalid-meta-entry",
          location: path,
        })
      None =>
        findings.push(Finding::{
          severity: Error,
          code: "unlisted-targets-metadata",
          location: path,
        })
    }
  }
  // A snapshot entry with no corresponding document is just as unusable: the
  // client would try to fetch metadata that does not exist.
  for entry in meta.iter() {
    let (path, _) = entry
    if targets_versions.get(path) is None {
      findings.push(Finding::{
        severity: Warning,
        code: "unprovided-targets-metadata",
        location: path,
      })
    }
  }
}

///|
/// Findings for a delegation tree, as `severity:code[:location]` strings.
pub fn preflight_delegations(targets : String) -> Array[String] {
  let findings = empty_findings()
  check_delegations(targets, findings)
  Report::{ findings, role: "delegations", version: None }.to_strings()
}

///|
/// Findings for a snapshot coverage check, as strings.
pub fn preflight_snapshot_coverage(
  snapshot : String,
  targets_versions : Map[String, Int],
) -> Array[String] {
  let findings = empty_findings()
  check_snapshot_coverage(snapshot, targets_versions, findings)
  Report::{ findings, role: "snapshot", version: None }.to_strings()
}
