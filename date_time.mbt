// Date-time and specification-version parsing for TUF metadata.
//
// The TUF specification states that metadata date-times follow ISO 8601 with
// the exact combined form `YYYY-MM-DDTHH:MM:SSZ`, always in UTC. In practice
// repositories and generators also emit a fractional part or a numeric offset,
// and a preflight layer has to say something useful about those documents
// instead of rejecting them as "invalid-expires" with no explanation.
//
// This file therefore separates three questions:
//
//   1. is the string a date-time at all, and is it exactly the relaxed form?
//   2. what instant does it denote, in seconds since the Unix epoch?
//   3. how do two instants compare?
//
// The parsing is deliberately allocation-light and endian-explicit: every
// component is read at a fixed position, so a malformed string can never be
// partially consumed.

///|
/// The relaxed ISO 8601 / RFC 3339 subset this parser accepts.
pub enum DateTimeForm {
  /// `YYYY-MM-DDTHH:MM:SSZ`, the form the TUF specification prescribes.
  Exact
  /// The same, with a fractional second part such as `2030-01-01T00:00:00.5Z`.
  Fractional
  /// The same, with a numeric offset such as `2030-01-01T00:00:00+08:00`.
  Offset
}

///|
/// Whether two forms describe the same shape.
pub fn DateTimeForm::equal(self : DateTimeForm, other : DateTimeForm) -> Bool {
  match (self, other) {
    (Exact, Exact) | (Fractional, Fractional) | (Offset, Offset) => true
    _ => false
  }
}

///|
/// A parsed date-time plus the shape it was written in.
pub struct DateTime {
  /// Seconds since 1970-01-01T00:00:00Z. Negative for earlier instants.
  epoch_seconds : Int64
  /// The shape of the source string, so callers can report drift from the
  /// canonical TUF form without losing the instant.
  form : DateTimeForm
  /// The offset in minutes that was applied, `0` for `Z` and for exact strings.
  offset_minutes : Int
}

///|
/// Whether two parsed instants are identical.
pub fn DateTime::equal(self : DateTime, other : DateTime) -> Bool {
  self.epoch_seconds == other.epoch_seconds &&
  self.form.equal(other.form) &&
  self.offset_minutes == other.offset_minutes
}

///|
/// A semver version as the three numeric components the TUF specification
/// requires for `spec_version`. A missing component defaults to zero, so `"1"`
/// and `"1.0"` both parse and compare as `1.0.0`; a pre-release or build suffix
/// is recorded instead, because the specification calls for a plain semantic
/// version.
pub struct Semver {
  major : Int
  minor : Int
  patch : Int
  /// `""`, or the suffix including its leading `-` or `+`.
  suffix : String
}

///|
/// Whether two semantic versions are identical.
pub fn Semver::equal(self : Semver, other : Semver) -> Bool {
  self.major == other.major &&
  self.minor == other.minor &&
  self.patch == other.patch &&
  self.suffix == other.suffix
}

///|
/// The instant as seconds since the Unix epoch.
pub fn DateTime::epoch_seconds(self : DateTime) -> Int64 {
  self.epoch_seconds
}

///|
/// The shape of the source string.
pub fn DateTime::form(self : DateTime) -> DateTimeForm {
  self.form
}

///|
/// The numeric UTC offset in minutes that was applied during parsing.
pub fn DateTime::offset_minutes(self : DateTime) -> Int {
  self.offset_minutes
}

///|
/// Whether the string was written in the exact form the specification asks for.
pub fn DateTime::is_canonical(self : DateTime) -> Bool {
  self.form is Exact
}

///|
/// A short name for the form, used in diagnostics and tests.
pub fn DateTimeForm::to_string(self : DateTimeForm) -> String {
  match self {
    Exact => "exact"
    Fractional => "fractional-seconds"
    Offset => "numeric-offset"
  }
}

///|
/// The number of days in `month` of `year`, honouring the Gregorian leap rule.
pub fn days_in_month(year : Int, month : Int) -> Int {
  match month {
    1 | 3 | 5 | 7 | 8 | 10 | 12 => 31
    4 | 6 | 9 | 11 => 30
    2 => if is_leap_year(year) { 29 } else { 28 }
    _ => 0
  }
}

///|
/// Whether `year` is a Gregorian leap year.
pub fn is_leap_year(year : Int) -> Bool {
  year % 400 == 0 || (year % 4 == 0 && year % 100 != 0)
}

///|
/// Days from 1970-01-01 to `year-month-day`, by the civil-from-days algorithm of
/// Howard Hinnant. Valid for any proleptic Gregorian date.
///
/// The era is computed with an explicit floor division because MoonBit's `Int`
/// division truncates toward zero, which would place dates before year 1 in the
/// wrong era.
pub fn days_from_civil(year : Int, month : Int, day : Int) -> Int64 {
  let adjusted_year = if month <= 2 { year - 1 } else { year }
  let era = if adjusted_year >= 0 {
    adjusted_year / 400
  } else {
    (adjusted_year - 399) / 400
  }
  let year_of_era = adjusted_year - era * 400
  let adjusted_month = if month > 2 { month - 3 } else { month + 9 }
  let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1
  let day_of_era = year_of_era * 365 +
    year_of_era / 4 -
    year_of_era / 100 +
    day_of_year
  era.to_int64() * 146097 + day_of_era.to_int64() - 719468
}

///|
/// The two-digit integer at `index` of `chars`, or `-1` when either character is
/// not a decimal digit.
fn two_digits(chars : Array[Char], index : Int) -> Int {
  let high = chars[index]
  let low = chars[index + 1]
  if high < '0' || high > '9' || low < '0' || low > '9' {
    return -1
  }
  (high.to_int() - 48) * 10 + (low.to_int() - 48)
}

///|
/// The four-digit integer at `index` of `chars`, or `-1` when any character is
/// not a decimal digit.
fn four_digits(chars : Array[Char], index : Int) -> Int {
  let mut value = 0
  for offset in 0..<4 {
    let char = chars[index + offset]
    if char < '0' || char > '9' {
      return -1
    }
    value = value * 10 + (char.to_int() - 48)
  }
  value
}

///|
/// Whether the calendar components denote a real instant.
fn valid_calendar(
  year : Int,
  month : Int,
  day : Int,
  hour : Int,
  minute : Int,
  second : Int,
) -> Bool {
  if year < 1 || month < 1 || month > 12 || day < 1 {
    return false
  }
  if day > days_in_month(year, month) {
    return false
  }
  // Leap seconds are permitted by ISO 8601 but not by TUF metadata, and a
  // second of 60 would make the epoch arithmetic below ambiguous.
  hour >= 0 && hour <= 23 && minute >= 0 && minute <= 59 && second <= 59
}

///|
/// Parse the fractional part starting at `index` (which must point at the dot),
/// returning the digit count. The fraction is not folded into the instant: TUF
/// metadata has second resolution, so a fraction is reported as a form rather
/// than silently truncated into a comparison.
fn fraction_digits(chars : Array[Char], index : Int) -> Int {
  let mut count = 0
  let mut cursor = index + 1
  while cursor < chars.length() && chars[cursor] >= '0' && chars[cursor] <= '9' {
    count += 1
    cursor += 1
  }
  count
}

///|
/// Parse a TUF metadata date-time.
///
/// Accepts the exact `YYYY-MM-DDTHH:MM:SSZ` form as well as the two deviations
/// that appear in real metadata: a fractional second part, and a numeric UTC
/// offset (`+HH:MM` / `-HH:MM`, with `+00:00` and `-00:00` allowed). Returns
/// `None` when the string is not a date-time of any accepted shape, which lets
/// the caller report one clear "not a date-time" finding instead of three
/// unrelated component errors.
pub fn parse_date_time(value : String) -> DateTime? {
  let chars = value.iter().to_array()
  // The shortest accepted form is 20 characters, `YYYY-MM-DDTHH:MM:SSZ`.
  if chars.length() < 20 {
    return None
  }
  if chars[4] != '-' ||
    chars[7] != '-' ||
    chars[10] != 'T' ||
    chars[13] != ':' ||
    chars[16] != ':' {
    return None
  }
  let year = four_digits(chars, 0)
  let month = two_digits(chars, 5)
  let day = two_digits(chars, 8)
  let hour = two_digits(chars, 11)
  let minute = two_digits(chars, 14)
  let second = two_digits(chars, 17)
  if year < 0 || month < 0 || day < 0 || hour < 0 || minute < 0 || second < 0 {
    return None
  }
  if !valid_calendar(year, month, day, hour, minute, second) {
    return None
  }
  let mut cursor = 19
  let mut form = Exact
  if cursor < chars.length() && chars[cursor] == '.' {
    let digits = fraction_digits(chars, cursor)
    if digits == 0 {
      return None
    }
    form = Fractional
    cursor = cursor + 1 + digits
  }
  let mut offset_minutes = 0
  if cursor < chars.length() && chars[cursor] == 'Z' {
    cursor += 1
  } else if cursor < chars.length() &&
    (chars[cursor] == '+' || chars[cursor] == '-') {
    let sign = if chars[cursor] == '+' { 1 } else { -1 }
    cursor += 1
    if cursor + 5 != chars.length() || chars[cursor + 2] != ':' {
      return None
    }
    let offset_hour = two_digits(chars, cursor)
    let offset_minute = two_digits(chars, cursor + 3)
    if offset_hour < 0 ||
      offset_minute < 0 ||
      offset_hour > 23 ||
      offset_minute > 59 {
      return None
    }
    offset_minutes = sign * (offset_hour * 60 + offset_minute)
    // Even `+00:00` is not the exact form the specification prescribes, so the
    // offset shape is preserved rather than folded back into `Exact`.
    form = Offset
    cursor += 5
  } else {
    return None
  }
  if cursor != chars.length() {
    return None
  }
  let days = days_from_civil(year, month, day)
  let seconds_of_day = hour * 3600 + minute * 60 + second
  let utc_seconds = days * 86400 +
    seconds_of_day.to_int64() -
    (offset_minutes * 60).to_int64()
  Some(DateTime::{ epoch_seconds: utc_seconds, form, offset_minutes, })
}

///|
/// Whether `value` parses as a date-time of any accepted shape.
pub fn is_date_time(value : String) -> Bool {
  match parse_date_time(value) {
    Some(_) => true
    None => false
  }
}

///|
/// Compare two parsed instants.
pub fn compare_date_time(left : DateTime, right : DateTime) -> Int {
  if left.epoch_seconds < right.epoch_seconds {
    -1
  } else if left.epoch_seconds > right.epoch_seconds {
    1
  } else {
    0
  }
}

///|
/// Seconds from `from` to `to`, which is negative when `to` is earlier.
pub fn seconds_between(from : DateTime, to : DateTime) -> Int64 {
  to.epoch_seconds - from.epoch_seconds
}

///|
/// The major version number.
pub fn Semver::major(self : Semver) -> Int {
  self.major
}

///|
/// The minor version number.
pub fn Semver::minor(self : Semver) -> Int {
  self.minor
}

///|
/// The patch version number.
pub fn Semver::patch(self : Semver) -> Int {
  self.patch
}

///|
/// The pre-release or build suffix, including its leading `-` or `+`, or `""`.
pub fn Semver::suffix(self : Semver) -> String {
  self.suffix
}

///|
/// Whether the suffix is empty, which is what `spec_version` should look like.
pub fn Semver::is_plain(self : Semver) -> Bool {
  self.suffix == ""
}

///|
/// The canonical `major.minor.patch` rendering.
pub fn Semver::to_string(self : Semver) -> String {
  self.major.to_string() +
  "." +
  self.minor.to_string() +
  "." +
  self.patch.to_string() +
  self.suffix
}

///|
/// Parse a semantic version.
///
/// Returns `None` when the string is not made of dot-separated decimal numbers
/// with an optional `-`/`+` suffix, or when a numeric component is empty (as in
/// `1..0`) or has a leading zero (as in `01.0.0`), both of which semver forbids.
///
/// The parser is written with local loop state on purpose: MoonBit scopes loop
/// bodies, so mutating an outer `let mut` (or a captured `Ref`) from the body
/// and then leaving the loop can silently discard the assignment. Every value
/// this function needs is therefore derived from the return of a helper.
pub fn parse_semver(value : String) -> Semver? {
  let chars = value.iter().to_array()
  let length = chars.length()
  if length == 0 {
    return None
  }
  let (major, minor, patch, seen) = scan_semver_components(chars, length)
  if seen == 0 {
    return None
  }
  let suffix = if seen >= length {
    ""
  } else {
    let char = chars[seen]
    if char == '-' || char == '+' {
      value[seen:].to_owned()
    } else {
      return None
    }
  }
  Some(Semver::{ major, minor, patch, suffix, })
}

///|
/// Read the leading `major[.minor[.patch]]` part of a semantic version.
///
/// Returns the three components, defaulted to zero, and the index at which the
/// numeric part stopped.
fn scan_semver_components(
  chars : Array[Char],
  length : Int,
) -> (Int, Int, Int, Int) {
  let mut index = 0
  let mut seen = 0
  let mut major = 0
  let mut minor = 0
  let mut patch = 0
  while index < length {
    let char = chars[index]
    if char < '0' || char > '9' {
      // A dot here would mean an empty component; anything else ends the
      // numeric part and is validated by the caller.
      return (major, minor, patch, index)
    }
    let start = index
    let mut component = 0
    while index < length && chars[index] >= '0' && chars[index] <= '9' {
      component = component * 10 + (chars[index].to_int() - 48)
      index += 1
    }
    let digits = index - start
    if digits > 1 && chars[start] == '0' {
      // Leading zeros are rejected by semver.
      return (major, minor, patch, 0)
    }
    if digits > 9 {
      // A component that cannot fit an Int would silently wrap.
      return (major, minor, patch, 0)
    }
    if seen == 0 {
      major = component
    } else if seen == 1 {
      minor = component
    } else if seen == 2 {
      patch = component
    } else {
      return (major, minor, patch, 0)
    }
    seen += 1
    if index >= length {
      return (major, minor, patch, index)
    }
    if chars[index] != '.' {
      return (major, minor, patch, index)
    }
    index += 1
    if index == length {
      // A trailing dot means a missing component.
      return (major, minor, patch, 0)
    }
  }
  (major, minor, patch, index)
}

///|
/// Whether `candidate` is compatible with the `expected` specification version
/// under the matching rule the TUF specification leaves to adopters: the major
/// version must be equal, and the candidate must not be newer than expected.
///
/// This is the rule this project documents for `preflight_authorized`; a caller
/// that wants exact matching can compare `to_string()` instead.
pub fn is_compatible_spec_version(
  candidate : Semver,
  expected : Semver,
) -> Bool {
  if candidate.major != expected.major {
    return false
  }
  if candidate.minor != expected.minor {
    return candidate.minor < expected.minor
  }
  candidate.patch <= expected.patch
}
