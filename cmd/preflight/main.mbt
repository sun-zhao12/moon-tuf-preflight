///|
/// Command line front end for the `moon-tuf-preflight` library.
///
/// The tool checks one TUF metadata envelope that arrives as a single argument,
/// prints one finding per line, and sets an exit code so a release pipeline or
/// an offline mirror script can gate on the result:
///
/// * `0` - the envelope is structurally sound for the requested role
/// * `1` - at least one finding was reported
/// * `2` - the command line could not be parsed
///
/// Nothing here verifies a signature, a hash or a trusted root chain: the
/// program is a structural preflight and says so in its help text.
fn main {
  let command = @argparse.Command(
    "moon-tuf-preflight",
    positionals=[
      @argparse.PositionArg(
        "envelope",
        about="the TUF metadata envelope as JSON text",
      ),
    ],
    options=[
      @argparse.OptionArg(
        "role",
        short='r',
        about="root, timestamp, snapshot or targets (default: targets)",
        default_values=["targets"],
      ),
      @argparse.OptionArg(
        "at",
        short='a',
        about="current UTC time, YYYY-MM-DDTHH:MM:SSZ; adds the expiry check",
      ),
    ],
    about="Structural preflight for TUF metadata. It inspects JSON shape, roles, versions, expiry, key references, thresholds, target paths and digest formats. It does not verify signatures or hashes.",
    version="0.1.0",
  )
  let matches = command.parse() catch {
    _ => {
      println("moon-tuf-preflight: could not parse the command line")
      println(command.render_help())
      abort("usage error")
    }
  }
  let envelope = match matches.values.get("envelope") {
    Some(values) => values[0]
    None => {
      println("moon-tuf-preflight: no envelope argument was supplied")
      abort("usage error")
    }
  }
  let role = match matches.values.get("role") {
    Some(values) => values[0]
    None => "targets"
  }
  let clock = match matches.values.get("at") {
    Some(values) => Some(values[0])
    None => None
  }
  let report = match clock {
    Some(now) => @moon-tuf-preflight.preflight_at_report(envelope, role, now)
    None => @moon-tuf-preflight.preflight_report(envelope, role)
  }
  for finding in report.findings() {
    println(finding.to_string())
  }
  if report.ok() {
    println("ok: no structural finding for role " + role)
    return
  }
  println(
    "found " +
    report.error_count().to_string() +
    " error(s) and " +
    report.warning_count().to_string() +
    " warning(s)",
  )
  abort("preflight findings")
}
