///|
/// Walk through the preflight API on one deliberately broken envelope.
///
/// The envelope below has a plausible shape but three separate defects: the
/// metadata expired in 2024, one target path escapes the target directory, and
/// one digest is far too short to be a SHA-256 hash. Run it with:
///
/// ```sh
/// moon run --target wasm-gc examples/demo
/// ```
fn main {
  let expired = targets("2024-01-01T00:00:00Z", "../app.bin", "abcd")
  println("== expired, unsafe path and short digest ==")
  for finding in @tuf.preflight_at(expired, "targets", "2026-09-24T12:00:00Z") {
    println("- " + finding)
  }
  let report = @tuf.preflight_at_report(
    expired, "targets", "2026-09-24T12:00:00Z",
  )
  println(
    "errors=" +
    report.error_count().to_string() +
    " warnings=" +
    report.warning_count().to_string() +
    " ok=" +
    report.ok().to_string(),
  )
  println("")
  let healthy = targets(
    "2030-06-01T12:30:00Z", "app.bin", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  )
  println("== well-formed envelope ==")
  let healthy_report = @tuf.preflight_at_report(
    healthy, "targets", "2026-09-24T12:00:00Z",
  )
  println(healthy_report.render())
  println("")
  println("== timestamp/snapshot/targets version agreement ==")
  let timestamp = envelope(
    "{\"_type\":\"timestamp\",\"version\":7,\"expires\":\"2030-06-01T12:30:00Z\",\"meta\":{\"snapshot.json\":{\"version\":8}}}",
  )
  let snapshot = envelope(
    "{\"_type\":\"snapshot\",\"version\":8,\"expires\":\"2030-06-01T12:30:00Z\",\"meta\":{\"targets.json\":{\"version\":3}}}",
  )
  for
    issue in @tuf.preflight_bundle(
      timestamp, snapshot, healthy, "2026-09-24T12:00:00Z",
    ) {
    println("- " + issue)
  }
  println("(no output above means the three documents agree)")
}

///|
/// A `targets` envelope built from the three parameters the demo varies.
fn targets(expires : String, name : String, digest : String) -> String {
  envelope(
    "{\"_type\":\"targets\",\"version\":3,\"expires\":\"" +
    expires +
    "\",\"targets\":{\"" +
    name +
    "\":{\"length\":1024,\"hashes\":{\"sha256\":\"" +
    digest +
    "\"}}}}",
  )
}

///|
/// Wrap the JSON text of a `signed` object in a signature envelope.
///
/// The signature values are placeholders: this library never verifies them.
fn envelope(body : String) -> String {
  "{\"signed\":" +
  body +
  ",\"signatures\":[{\"keyid\":\"demo-key\",\"sig\":\"demo-only\"}]}"
}
