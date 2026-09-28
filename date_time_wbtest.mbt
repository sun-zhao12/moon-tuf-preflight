// White-box tests for the date-time and semver layer.

///|
/// Parse `value` and fail with a readable message when it is not accepted.
fn must_parse(value : String) -> DateTime raise {
  match parse_date_time(value) {
    Some(parsed) => parsed
    None => {
      println("expected a date-time, got none for [" + value + "]")
      fail("date-time was rejected")
    }
  }
}

///|
/// Parse `value` as a semantic version, failing loudly when it is rejected.
fn must_semver(value : String) -> Semver raise {
  match parse_semver(value) {
    Some(parsed) => parsed
    None => {
      println("expected a semver, got none for [" + value + "]")
      fail("semver was rejected")
    }
  }
}

///|
test "the canonical TUF date-time form parses" {
  let epoch = must_parse("1970-01-01T00:00:00Z")
  assert_eq(epoch.epoch_seconds(), 0L)
  assert_true(epoch.is_canonical())
  assert_eq(epoch.form().to_string(), "exact")
  assert_eq(epoch.offset_minutes(), 0)
  let example = must_parse("1985-10-21T01:21:00Z")
  assert_true(example.is_canonical())
  // Cross-checked against .NET DateTimeOffset arithmetic.
  assert_eq(example.epoch_seconds(), 498705660L)
}

///|
test "calendar arithmetic matches the Gregorian rules" {
  assert_eq(days_from_civil(1970, 1, 1), 0L)
  assert_eq(days_from_civil(1970, 1, 2), 1L)
  assert_eq(days_from_civil(1969, 12, 31), -1L)
  assert_eq(days_from_civil(2000, 3, 1), 11017L)
  assert_eq(days_from_civil(2024, 2, 29), 19782L)
  assert_true(is_leap_year(2000))
  assert_true(is_leap_year(2024))
  assert_true(is_leap_year(2032))
  assert_false(is_leap_year(1900))
  assert_false(is_leap_year(2023))
  assert_eq(days_in_month(2024, 2), 29)
  assert_eq(days_in_month(2023, 2), 28)
  assert_eq(days_in_month(2024, 4), 30)
  assert_eq(days_in_month(2024, 12), 31)
  assert_eq(days_in_month(2024, 13), 0)
}

///|
test "fractional seconds and numeric offsets are parsed" {
  let fractional = must_parse("2030-01-01T00:00:00.500Z")
  assert_eq(fractional.form().to_string(), "fractional-seconds")
  assert_eq(
    fractional.epoch_seconds(),
    must_parse("2030-01-01T00:00:00Z").epoch_seconds(),
  )
  assert_false(fractional.is_canonical())
  let plus_eight = must_parse("2030-01-01T08:00:00+08:00")
  assert_eq(plus_eight.form().to_string(), "numeric-offset")
  assert_eq(plus_eight.offset_minutes(), 480)
  assert_eq(
    plus_eight.epoch_seconds(),
    must_parse("2030-01-01T00:00:00Z").epoch_seconds(),
  )
  let minus_five = must_parse("2029-12-31T19:00:00-05:00")
  assert_eq(minus_five.offset_minutes(), -300)
  assert_eq(
    minus_five.epoch_seconds(),
    must_parse("2030-01-01T00:00:00Z").epoch_seconds(),
  )
  // `+00:00` is the same instant but not the canonical spelling.
  let zero_offset = must_parse("2030-01-01T00:00:00+00:00")
  assert_eq(zero_offset.form().to_string(), "numeric-offset")
  assert_eq(zero_offset.epoch_seconds(), 1893456000L)
  assert_eq(zero_offset.form().to_string(), "numeric-offset")
}

///|
test "malformed date-times are rejected instead of misread" {
  for
    bad in [
      "", "2030-01-01", "2030-01-01T00:00:00", "2030-01-01 00:00:00Z", "2030-01-01T00:00:00z",
      "2030-13-01T00:00:00Z", "2030-00-10T00:00:00Z", "2030-02-29T00:00:00Z", "2023-02-29T00:00:00Z",
      "2030-04-31T00:00:00Z", "2030-01-00T00:00:00Z", "2030-01-01T24:00:00Z", "2030-01-01T00:60:00Z",
      "2030-01-01T00:00:60Z", "2030-01-01T00:00:00.Z", "2030-01-01T00:00:00+08",
      "2030-01-01T00:00:00+8:00", "2030-01-01T00:00:00+08:0", "2030-01-01T00:00:00+24:00",
      "2030-01-01T00:00:00+00:60", "2030-01-01T00:00:00Z ", " 2030-01-01T00:00:00Z",
      "2030-01-01T00:00:00ZZ", "203x-01-01T00:00:00Z", "2030-01-01T00:00:00+08:00extra",
    ] {
    assert_true(parse_date_time(bad) is None)
    assert_false(is_date_time(bad))
  }
  // A leap day in a leap year is accepted, and the century rule is applied.
  assert_true(is_date_time("2032-02-29T23:59:59Z"))
  assert_false(is_date_time("2100-02-29T23:59:59Z"))
  assert_true(is_date_time("2000-02-29T23:59:59Z"))
}

///|
test "semantic versions parse with and without suffix" {
  let full = must_semver("1.0.31")
  assert_eq(full.major(), 1)
  assert_eq(full.minor(), 0)
  assert_eq(full.patch(), 31)
  assert_true(full.is_plain())
  assert_eq(full.to_string(), "1.0.31")
  // A shorter spelling fills the missing components with zero.
  assert_eq(must_semver("1").to_string(), "1.0.0")
  assert_eq(must_semver("2.3").to_string(), "2.3.0")
  let suffixed = must_semver("1.0.31-beta.1")
  assert_eq(suffixed.suffix(), "-beta.1")
  assert_false(suffixed.is_plain())
  assert_eq(suffixed.to_string(), "1.0.31-beta.1")
  assert_eq(must_semver("1.0.0+build.7").suffix(), "+build.7")
}

///|
test "invalid semantic versions are rejected" {
  for
    bad in [
      "", "v1.0", "1.0.", ".1", "1..0", "1.0.0.0", "01.0.0", "1.00.0", "-1", "1.0.x",
      "1,0", "1.0.31 beta", "0000000001",
    ] {
    assert_true(parse_semver(bad) is None)
  }
}

///|
test "specification version compatibility follows the documented rule" {
  let expected = must_semver("1.0.31")
  assert_true(is_compatible_spec_version(must_semver("1.0.31"), expected))
  assert_true(is_compatible_spec_version(must_semver("1.0.0"), expected))
  assert_true(is_compatible_spec_version(must_semver("1.0"), expected))
  // Anything in 1.x is accepted when it is not newer than expected.
  assert_false(is_compatible_spec_version(must_semver("1.1.0"), expected))
  assert_false(is_compatible_spec_version(must_semver("2.0.0"), expected))
  assert_false(is_compatible_spec_version(must_semver("0.9.0"), expected))
  let loose = must_semver("1.1.0")
  assert_true(is_compatible_spec_version(must_semver("1.0.31"), loose))
}

///|
test "instant comparison and differences are exact" {
  let before = must_parse("2030-01-01T00:00:00Z")
  let after = must_parse("2030-01-01T00:00:01Z")
  assert_eq(compare_date_time(before, after), -1)
  assert_eq(compare_date_time(after, before), 1)
  assert_eq(compare_date_time(before, before), 0)
  assert_eq(seconds_between(before, after), 1L)
  assert_eq(seconds_between(after, before), -1L)
  assert_eq(seconds_between(before, before), 0L)
  // A year apart is 365 days in a non-leap span and 366 across a leap day.
  assert_eq(
    seconds_between(
      must_parse("2031-01-01T00:00:00Z"),
      must_parse("2032-01-01T00:00:00Z"),
    ),
    31536000L,
  )
  assert_eq(
    seconds_between(
      must_parse("2032-01-01T00:00:00Z"),
      must_parse("2033-01-01T00:00:00Z"),
    ),
    31622400L,
  )
  // The same instant written two ways compares equal.
  assert_eq(
    compare_date_time(
      must_parse("2030-01-01T08:00:00+08:00"),
      must_parse("2030-01-01T00:00:00Z"),
    ),
    0,
  )
  assert_eq(
    compare_date_time(
      must_parse("2030-01-01T00:00:00.999Z"),
      must_parse("2030-01-01T00:00:00Z"),
    ),
    0,
  )
}
