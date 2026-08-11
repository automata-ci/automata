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
    if let Some(octal) = value.strip_prefix("0o") {
        return digits(octal, |character| matches!(character, '0'..='7'));
    }
    if let Some(hexadecimal) = value.strip_prefix("0x") {
        return digits(hexadecimal, |character| character.is_ascii_hexdigit());
    }
    digits(strip_sign(value), |character| character.is_ascii_digit())
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
    value.parse::<f64>().is_ok()
}

fn strip_sign(value: &str) -> &str {
    value.strip_prefix(['+', '-']).unwrap_or(value)
}

fn digits(value: &str, is_digit: impl Fn(char) -> bool) -> bool {
    !value.is_empty() && value.chars().all(is_digit)
}
