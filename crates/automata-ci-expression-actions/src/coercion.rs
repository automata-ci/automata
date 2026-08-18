use std::cmp::Ordering;

use crate::GithubValue;

pub(crate) fn to_number(value: &GithubValue) -> f64 {
    match value.without_sensitivity() {
        GithubValue::Null => 0.0,
        GithubValue::Boolean(value) => u8::from(*value).into(),
        GithubValue::Number(bits) => f64::from_bits(*bits),
        GithubValue::String(value) => parse_number(value),
        GithubValue::Array(_) | GithubValue::Object(_) => f64::NAN,
        GithubValue::Sensitive(_) => unreachable!("sensitivity wrappers are removed recursively"),
    }
}

pub(crate) fn to_string(value: &GithubValue) -> String {
    match value.without_sensitivity() {
        GithubValue::Null => String::new(),
        GithubValue::Boolean(true) => "true".to_owned(),
        GithubValue::Boolean(false) => "false".to_owned(),
        GithubValue::Number(bits) => format_number(f64::from_bits(*bits)),
        GithubValue::String(value) => value.to_string(),
        GithubValue::Array(_) => "Array".to_owned(),
        GithubValue::Object(_) => "Object".to_owned(),
        GithubValue::Sensitive(_) => unreachable!("sensitivity wrappers are removed recursively"),
    }
}

pub(crate) fn abstract_equal(left: &GithubValue, right: &GithubValue) -> bool {
    let left = left.without_sensitivity();
    let right = right.without_sensitivity();
    match (left, right) {
        (GithubValue::Null, GithubValue::Null) => true,
        (GithubValue::Boolean(left), GithubValue::Boolean(right)) => left == right,
        (GithubValue::Number(left), GithubValue::Number(right)) => {
            let left = f64::from_bits(*left);
            let right = f64::from_bits(*right);
            left.partial_cmp(&right) == Some(Ordering::Equal)
        }
        (GithubValue::String(left), GithubValue::String(right)) => ordinal_ignore_case(left, right),
        (GithubValue::Array(left), GithubValue::Array(right)) => {
            std::sync::Arc::ptr_eq(left, right)
        }
        (GithubValue::Object(left), GithubValue::Object(right)) => left.same_identity(right),
        (GithubValue::Boolean(_) | GithubValue::Null, _)
        | (_, GithubValue::Boolean(_) | GithubValue::Null)
        | (GithubValue::Number(_), GithubValue::String(_))
        | (GithubValue::String(_), GithubValue::Number(_)) => {
            let left = to_number(left);
            let right = to_number(right);
            left.partial_cmp(&right) == Some(Ordering::Equal)
        }
        _ => false,
    }
}

pub(crate) fn abstract_compare(left: &GithubValue, right: &GithubValue) -> Option<Ordering> {
    let left = left.without_sensitivity();
    let right = right.without_sensitivity();
    match (left, right) {
        (GithubValue::String(left), GithubValue::String(right)) => {
            Some(ordinal_compare(left, right))
        }
        (GithubValue::Boolean(left), GithubValue::Boolean(right)) => Some(left.cmp(right)),
        (GithubValue::Number(left), GithubValue::Number(right)) => {
            f64::from_bits(*left).partial_cmp(&f64::from_bits(*right))
        }
        (GithubValue::Boolean(_) | GithubValue::Null, _)
        | (_, GithubValue::Boolean(_) | GithubValue::Null)
        | (GithubValue::Number(_), GithubValue::String(_))
        | (GithubValue::String(_), GithubValue::Number(_)) => {
            to_number(left).partial_cmp(&to_number(right))
        }
        _ => None,
    }
}

pub(crate) fn ordinal_ignore_case(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right) || ordinal_key(left) == ordinal_key(right)
}

pub(crate) fn ordinal_key(value: &str) -> String {
    value.chars().map(ordinal_fold_character).collect()
}

fn ordinal_compare(left: &str, right: &str) -> Ordering {
    ordinal_key(left)
        .encode_utf16()
        .cmp(ordinal_key(right).encode_utf16())
}

fn ordinal_fold_character(character: char) -> char {
    // .NET's ordinal-ignore-case comparison applies one-to-one invariant
    // casing and never expands a scalar into multiple characters. The two
    // compatibility characters below deliberately remain distinct in the
    // pinned runtime's ordinal table even though Unicode full-uppercase maps
    // them to ASCII letters.
    if matches!(character, '\u{0131}' | '\u{017f}') {
        return character;
    }
    let mut uppercase = character.to_uppercase();
    let first = uppercase.next().unwrap_or(character);
    if uppercase.next().is_none() {
        first
    } else {
        character
    }
}

fn parse_number(value: &str) -> f64 {
    let value = value.trim();
    if value.is_empty() {
        return 0.0;
    }
    if value == "Infinity" {
        return f64::INFINITY;
    }
    if value == "-Infinity" {
        return f64::NEG_INFINITY;
    }
    if let Some(hex) = value.strip_prefix("0x") {
        return parse_hex_i32(hex);
    }
    if let Some(octal) = value.strip_prefix("0o") {
        return parse_radix_i32(octal, 8);
    }
    if !valid_decimal(value) {
        return f64::NAN;
    }
    value.parse::<f64>().unwrap_or(f64::NAN)
}

fn parse_radix_i32(value: &str, radix: u32) -> f64 {
    if value.is_empty() || !value.chars().all(|character| character.is_digit(radix)) {
        return f64::NAN;
    }
    u32::from_str_radix(value, radix).map_or(f64::NAN, |value| {
        f64::from(i32::from_be_bytes(value.to_be_bytes()))
    })
}

fn parse_hex_i32(value: &str) -> f64 {
    if value.is_empty() || !value.chars().all(|character| character.is_ascii_hexdigit()) {
        return f64::NAN;
    }
    u32::from_str_radix(value, 16).map_or(f64::NAN, |value| {
        f64::from(i32::from_be_bytes(value.to_be_bytes()))
    })
}

fn valid_decimal(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut cursor = usize::from(matches!(bytes.first(), Some(b'+' | b'-')));
    let mut digits = 0_usize;
    while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
        cursor += 1;
        digits += 1;
    }
    if bytes.get(cursor) == Some(&b'.') {
        cursor += 1;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
            digits += 1;
        }
    }
    if digits == 0 {
        return false;
    }
    if matches!(bytes.get(cursor), Some(b'e' | b'E')) {
        cursor += 1;
        if matches!(bytes.get(cursor), Some(b'+' | b'-')) {
            cursor += 1;
        }
        let exponent_start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if cursor == exponent_start {
            return false;
        }
    }
    cursor == bytes.len()
}

fn format_number(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_owned();
    }
    if value == f64::INFINITY {
        return "Infinity".to_owned();
    }
    if value == f64::NEG_INFINITY {
        return "-Infinity".to_owned();
    }
    if value == 0.0 {
        return "0".to_owned();
    }

    let scientific = format!("{value:.14e}");
    let (scientific_mantissa, scientific_exponent) =
        scientific.split_once('e').unwrap_or((&scientific, "0"));
    let exponent = scientific_exponent.parse::<i32>().unwrap_or_default();
    if (-4..15).contains(&exponent) {
        let decimals = usize::try_from((14 - exponent).max(0)).unwrap_or(0);
        trim_decimal(format!("{value:.decimals$}"))
    } else {
        format!(
            "{}E{exponent:+03}",
            trim_decimal(scientific_mantissa.to_owned())
        )
    }
}

fn trim_decimal(mut value: String) -> String {
    if value.contains('.') {
        while value.ends_with('0') {
            value.pop();
        }
        if value.ends_with('.') {
            value.pop();
        }
    }
    value
}
