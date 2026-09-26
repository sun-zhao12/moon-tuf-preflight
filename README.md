# moon-tuf-preflight

A pure MoonBit diagnostic library and CLI for [TUF](https://theupdateframework.github.io/specification/latest/) metadata envelopes.

It answers one question before anything reaches a real TUF verifier: **is this metadata structurally usable for the role it claims?** It inspects JSON shape, `_type` versus the requested role, `version`, `expires`, signature entry shape, root key references and thresholds, timestamp/snapshot meta versions, target paths, lengths and `sha256`/`sha512` digest formats, and it cross-checks the versions that a timestamp/snapshot/targets bundle references against the ones it carries.

> **Security boundary.** These functions never verify a cryptographic signature, never compare a digest against downloaded bytes, never build a trusted root chain and never prevent rollback. A report with no findings means "this document is well formed", not "this update is safe". Findings must not be used as the authorization to install an update.

## Use as a library

```moonbit
// Structural check of one envelope.
let findings : Array[String] = @moon-tuf-preflight.preflight(targets_json, "targets")

// Same check plus an expiry decision against a caller-supplied UTC clock.
let dated : Array[String] =
  @moon-tuf-preflight.preflight_at(targets_json, "targets", "2026-09-24T00:00:00Z")

// timestamp / snapshot / targets must agree on the versions they reference.
let bundle : Array[String] = @moon-tuf-preflight.preflight_bundle(
  timestamp_json, snapshot_json, targets_json, "2026-09-24T00:00:00Z",
)
```

For severity, counts and a typed result, use the `Report` API:

```moonbit
let report = @moon-tuf-preflight.preflight_at_report(targets_json, "targets", now)
if not(report.ok()) {
  for finding in report.findings() {
    println(finding.severity.to_string() + " " + finding.code + " at " + finding.location)
  }
}
```

### Findings

Findings are stable strings of the form `severity:code[:location]`, where `severity` is `error` or `warning`:

| Example | Meaning |
| --- | --- |
| `error:invalid-json` | the input is not JSON |
| `error:missing-signed-object` | the envelope has no object-valued `signed` |
| `error:role-mismatch:targets` | `signed._type` is not the requested role |
| `error:invalid-version` | `version` is missing, fractional, zero or out of range |
| `error:invalid-expires` | `expires` is not an exact `YYYY-MM-DDTHH:MM:SSZ` UTC time |
| `error:expired:2030-06-01T12:30:00Z` | `expires <= now`, reported by `preflight_at*` |
| `error:empty-signatures` | the `signatures` array is empty |
| `error:duplicate-signature-keyid:k1` | the same `keyid` signs twice |
| `error:unknown-keyid:root:k1` | a role references a key that is not in `keys` |
| `error:unreachable-threshold:root:threshold=2,usable=1` | fewer usable keys than the threshold |
| `error:unsafe-target-path:../app` | absolute, `..`, `.`, empty or backslash/colon path |
| `error:invalid-target-hash:app.bin:sha256` | digest is not hex or not the expected length |
| `warning:unsupported-target-hash-algorithm:app.bin:md5` | digest algorithm is not `sha256`/`sha512` |
| `error:snapshot-version-mismatch:snapshot.json:referenced=2,actual=1` | bundle version disagreement |

Inputs must use second-resolution UTC with a trailing `Z`. Digest checks cover hex characters and digest length only; no file is read. The current time is always a parameter, so CI, Wasm and offline runs reproduce identical output.

## Use as a CLI

```sh
moon run --target wasm-gc cmd/preflight -- --role targets "$(cat targets.json)"
moon run --target wasm-gc cmd/preflight -- --role root --at 2026-09-24T00:00:00Z "$(cat root.json)"
```

The CLI prints one finding per line, exits `0` when nothing is reported, `1` when at least one finding is reported and `2` on a usage error. `--help` lists the options.

## Install and reproduce

Install the [MoonBit toolchain](https://www.moonbitlang.com/download/) and confirm that `moon version --all` works, then run these commands from the project root:

```sh
moon check --deny-warn --target wasm
moon build --deny-warn --target wasm
moon test --deny-warn --target wasm
moon run --target wasm examples/demo
```

Swap `wasm` for `wasm-gc`, `js` (needs Node.js) or `native` (needs a C compiler). CI runs the check, build and test steps for `wasm`, `wasm-gc`, `js` and `native`, runs the example, and verifies that `moon fmt` and `moon info` leave the tree unchanged.

## What it does not do

- No cryptographic signature verification, no digest comparison against real bytes.
- No trusted root chain, no rollback or freeze protection, no update authorization.
- No support for TUF `delegations` or succinct roles yet.
- No network, filesystem or clock access: everything is text in, text out.

## License and sources

The implementation follows the public [TUF specification](https://theupdateframework.github.io/specification/latest/) for field names, role semantics and threshold rules. No third-party source, test vector or data file was copied; all example signatures and digests are placeholders. Licensed under [MIT](LICENSE).
