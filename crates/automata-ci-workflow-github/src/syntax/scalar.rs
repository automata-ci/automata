use super::{ScalarResolution, ScalarStyle};

pub(super) fn resolve_scalar(decoded: &str, style: ScalarStyle) -> ScalarResolution {
    if style != ScalarStyle::Plain {
        return ScalarResolution::String;
    }

    match decoded {
        "" | "~" | "null" | "Null" | "NULL" => ScalarResolution::Null,
        "true" | "True" | "TRUE" | "false" | "False" | "FALSE" => ScalarResolution::Boolean,
        value if is_integer(value) => ScalarResolution::Integer,
        value if is_float(value) => ScalarResolution::Float,
        _ => ScalarResolution::String,
    }
}

fn is_integer(value: &str) -> bool {
    let unsigned = strip_sign(value);
    if let Some(octal) = unsigned.strip_prefix("0o") {
        return digits_with_separators(octal, |character| matches!(character, '0'..='7'));
    }
    if let Some(hexadecimal) = unsigned.strip_prefix("0x") {
        return digits_with_separators(hexadecimal, |character| character.is_ascii_hexdigit());
    }
    digits_with_separators(unsigned, |character| character.is_ascii_digit())
}

fn is_float(value: &str) -> bool {
    if matches!(
        value,
        ".inf"
            | ".Inf"
            | ".INF"
            | "+.inf"
            | "+.Inf"
            | "+.INF"
            | "-.inf"
            | "-.Inf"
            | "-.INF"
            | ".nan"
            | ".NaN"
            | ".NAN"
    ) {
        return true;
    }

    if !value.contains(['.', 'e', 'E']) {
        return false;
    }
    let normalized: String = value
        .chars()
        .filter(|character| *character != '_')
        .collect();
    normalized.parse::<f64>().is_ok()
}

fn strip_sign(value: &str) -> &str {
    value.strip_prefix(['+', '-']).unwrap_or(value)
}

fn digits_with_separators(value: &str, is_digit: impl Fn(char) -> bool) -> bool {
    let mut found_digit = false;
    for character in value.chars() {
        if character == '_' {
            continue;
        }
        if !is_digit(character) {
            return false;
        }
        found_digit = true;
    }
    found_digit
}
