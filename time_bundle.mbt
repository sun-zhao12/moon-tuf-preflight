///|
/// Whether `value` is an exact TUF timestamp: `YYYY-MM-DDTHH:MM:SSZ`.
///
/// TUF metadata carries second-resolution UTC timestamps. Calendar validity is
/// checked too, including leap years, so `2026-02-31T00:00:00Z` is rejected.
/// Fractional seconds and numeric offsets are intentionally not accepted: the
/// specification requires `Z`.
fn valid_utc_time(value : String) -> Bool {
  let chars = value.iter().to_array()
  if chars.length() != 20 ||
    chars[4] != '-' ||
    chars[7] != '-' ||
    chars[10] != 'T' ||
    chars[13] != ':' ||
    chars[16] != ':' ||
    chars[19] != 'Z' {
    return false
  }
  for index in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18] {
    if chars[index] < '0' || chars[index] > '9' {
      return false
    }
  }
  let month = digit_pair(chars[5], chars[6])
  let day = digit_pair(chars[8], chars[9])
  let year = digit_pair(chars[0], chars[1]) * 100 +
    digit_pair(chars[2], chars[3])
  let hour = digit_pair(chars[11], chars[12])
  let minute = digit_pair(chars[14], chars[15])
  let second = digit_pair(chars[17], chars[18])
  let max_day = match month {
    2 =>
      if year % 400 == 0 || (year % 4 == 0 && year % 100 != 0) {
        29
      } else {
        28
      }
    4 | 6 | 9 | 11 => 30
    _ => 31
  }
  month >= 1 &&
  month <= 12 &&
  day >= 1 &&
  day <= max_day &&
  hour <= 23 &&
  minute <= 59 &&
  second <= 59
}

///|
/// The integer value of two decimal ASCII digits.
fn digit_pair(a : Char, b : Char) -> Int {
  (a.to_int() - 48) * 10 + b.to_int() - 48
}

///|
/// Lexicographic ordering of two `YYYY-MM-DDTHH:MM:SSZ` strings.
///
/// Because the format is fixed-width and big-endian, string comparison is the
/// same as chronological comparison. Both inputs must already have passed
/// [`valid_utc_time`]: they are known to be 20 characters long, so indexing is
/// safe. Returns `true` when `a` is at or before `b`.
fn utc_not_after(a : String, b : String) -> Bool {
  let left = a.iter().to_array()
  let right = b.iter().to_array()
  for index in 0..<20 {
    if left[index] < right[index] {
      return true
    }
    if left[index] > right[index] {
      return false
    }
  }
  true
}

///|
/// The `signed` object of a metadata envelope, or `None` when `input` is not
/// JSON, is not an object, or has no object-valued `signed` field.
fn signed_object(input : String) -> Map[String, Json]? {
  let document = @json.parse(input) catch { _ => return None }
  guard document is Object(envelope) else { return None }
  match envelope.get("signed") {
    Some(Object(value)) => Some(value)
    _ => None
  }
}

///|
/// Narrow a JSON value to a TUF `version` integer.
fn positive_version(value : Json?) -> Int? {
  match value {
    Some(Number(number, ..)) if in_int_range(number) => Some(number.to_int())
    _ => None
  }
}

///|
/// The `signed.version` of a metadata document, or `None` when it is absent or
/// not a valid version integer.
fn metadata_version(input : String) -> Int? {
  match signed_object(input) {
    Some(signed) => positive_version(signed.get("version"))
    None => None
  }
}

///|
/// The version that a `timestamp` or `snapshot` document references for the
/// meta file `name`, or `None` when the reference or its version is missing.
fn referenced_version(input : String, name : String) -> Int? {
  match signed_object(input) {
    Some(signed) =>
      match signed.get("meta") {
        Some(Object(meta)) =>
          match meta.get(name) {
            Some(Object(entry)) => positive_version(entry.get("version"))
            _ => None
          }
        _ => None
      }
    None => None
  }
}
