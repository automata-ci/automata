use std::{cell::Cell, io::Write as _};

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};

use crate::{
    GithubExpressionEvaluationError, GithubExpressionEvaluationErrorKind, GithubExpressionLimits,
    GithubObject, GithubValue, coercion,
};

pub(crate) fn contains(
    arguments: &[GithubValue],
) -> Result<GithubValue, GithubExpressionEvaluationError> {
    exact_arity(arguments, 2)?;
    let found = match &arguments[0] {
        GithubValue::Array(values) => values
            .iter()
            .any(|value| coercion::abstract_equal(&arguments[1], value)),
        value if value.is_primitive() && arguments[1].is_primitive() => {
            let left = coercion::to_string(value).to_lowercase();
            let right = coercion::to_string(&arguments[1]).to_lowercase();
            left.contains(&right)
        }
        _ => false,
    };
    Ok(GithubValue::Boolean(found))
}

pub(crate) fn starts_with(
    arguments: &[GithubValue],
) -> Result<GithubValue, GithubExpressionEvaluationError> {
    string_predicate(arguments, |left, right| left.starts_with(right))
}

pub(crate) fn ends_with(
    arguments: &[GithubValue],
) -> Result<GithubValue, GithubExpressionEvaluationError> {
    string_predicate(arguments, |left, right| left.ends_with(right))
}

fn string_predicate(
    arguments: &[GithubValue],
    predicate: impl FnOnce(&str, &str) -> bool,
) -> Result<GithubValue, GithubExpressionEvaluationError> {
    exact_arity(arguments, 2)?;
    let value = if arguments[0].is_primitive() && arguments[1].is_primitive() {
        let left = coercion::to_string(&arguments[0]).to_lowercase();
        let right = coercion::to_string(&arguments[1]).to_lowercase();
        predicate(&left, &right)
    } else {
        false
    };
    Ok(GithubValue::Boolean(value))
}

pub(crate) fn join(
    arguments: &[GithubValue],
    maximum_bytes: usize,
) -> Result<GithubValue, GithubExpressionEvaluationError> {
    arity_range(arguments, 1, 2)?;
    let result = match &arguments[0] {
        GithubValue::Array(values) => {
            let separator = arguments
                .get(1)
                .filter(|value| value.is_primitive())
                .map_or_else(|| ",".to_owned(), coercion::to_string);
            let mut result = String::new();
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    append_bounded(&mut result, &separator, maximum_bytes)?;
                }
                let value = coercion::to_string(value);
                append_bounded(&mut result, &value, maximum_bytes)?;
            }
            result
        }
        value if value.is_primitive() => {
            let result = coercion::to_string(value);
            if result.len() > maximum_bytes {
                return Err(resource_limit());
            }
            result
        }
        _ => String::new(),
    };
    Ok(GithubValue::string(result))
}

pub(crate) fn format_template(
    template: &str,
    argument_count: usize,
    maximum_bytes: usize,
    mut argument: impl FnMut(usize) -> Result<String, GithubExpressionEvaluationError>,
) -> Result<GithubValue, GithubExpressionEvaluationError> {
    let mut output = String::with_capacity(template.len().min(maximum_bytes));
    let mut arguments = vec![None; argument_count];
    let mut cursor = 0;
    let bytes = template.as_bytes();
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'{' if bytes.get(cursor + 1) == Some(&b'{') => {
                append_bounded(&mut output, "{", maximum_bytes)?;
                cursor += 2;
            }
            b'}' if bytes.get(cursor + 1) == Some(&b'}') => {
                append_bounded(&mut output, "}", maximum_bytes)?;
                cursor += 2;
            }
            b'{' => {
                let end = template[cursor + 1..]
                    .find('}')
                    .map(|offset| cursor + 1 + offset)
                    .ok_or_else(invalid_operation)?;
                let placeholder = &template[cursor + 1..end];
                if placeholder.contains(':') || placeholder.is_empty() {
                    return Err(invalid_operation());
                }
                let index = placeholder.parse::<u8>().map_err(|_| invalid_operation())?;
                let index = usize::from(index);
                if index >= argument_count {
                    return Err(invalid_operation());
                }
                if arguments[index].is_none() {
                    arguments[index] = Some(argument(index)?);
                }
                let Some(value) = arguments[index].as_deref() else {
                    return Err(invalid_operation());
                };
                append_bounded(&mut output, value, maximum_bytes)?;
                cursor = end + 1;
            }
            b'}' => return Err(invalid_operation()),
            _ => {
                let character = template[cursor..]
                    .chars()
                    .next()
                    .ok_or_else(invalid_operation)?;
                let character_bytes = character.len_utf8();
                append_bounded(
                    &mut output,
                    &template[cursor..cursor + character_bytes],
                    maximum_bytes,
                )?;
                cursor += character_bytes;
            }
        }
    }
    Ok(GithubValue::string(output))
}

fn append_bounded(
    output: &mut String,
    value: &str,
    maximum_bytes: usize,
) -> Result<(), GithubExpressionEvaluationError> {
    let result_bytes = output
        .len()
        .checked_add(value.len())
        .ok_or_else(resource_limit)?;
    if result_bytes > maximum_bytes {
        return Err(resource_limit());
    }
    output.push_str(value);
    Ok(())
}

pub(crate) fn from_json(
    arguments: &[GithubValue],
    limits: GithubExpressionLimits,
) -> Result<GithubValue, GithubExpressionEvaluationError> {
    exact_arity(arguments, 1)?;
    let source = coercion::to_string(&arguments[0]);
    let mut deserializer = serde_json::Deserializer::from_str(&source);
    let budget = JsonBudget::new(limits.collection_items(), limits.value_depth());
    let value = JsonValueSeed {
        depth: 0,
        budget: &budget,
    }
    .deserialize(&mut deserializer)
    .map_err(|_| {
        if budget.exhausted.get() {
            resource_limit()
        } else {
            invalid_operation()
        }
    })?;
    deserializer.end().map_err(|_| invalid_operation())?;
    Ok(value)
}

pub(crate) fn to_json(
    arguments: &[GithubValue],
    limits: GithubExpressionLimits,
) -> Result<GithubValue, GithubExpressionEvaluationError> {
    exact_arity(arguments, 1)?;
    let mut output = BoundedJsonWriter::new(limits.result_bytes());
    write_json(&arguments[0], 0, limits.value_depth(), &mut output)?;
    String::from_utf8(output.into_bytes())
        .map(GithubValue::string)
        .map_err(|_| invalid_operation())
}

fn write_json(
    value: &GithubValue,
    depth: usize,
    maximum_depth: usize,
    output: &mut BoundedJsonWriter,
) -> Result<(), GithubExpressionEvaluationError> {
    if depth >= maximum_depth {
        return Err(resource_limit());
    }
    match value {
        GithubValue::Null => output.append("null")?,
        GithubValue::Boolean(value) => output.append(if *value { "true" } else { "false" })?,
        GithubValue::Number(bits) => {
            output.append(&coercion::to_string(&GithubValue::Number(*bits)))?;
        }
        GithubValue::String(value) => {
            serde_json::to_writer(output, value.as_ref()).map_err(|_| resource_limit())?;
        }
        GithubValue::Array(values) => {
            if values.is_empty() {
                output.append("[]")?;
            } else {
                output.append("[")?;
                for (index, item) in values.iter().enumerate() {
                    if index > 0 {
                        output.append(",")?;
                    }
                    output.append("\n")?;
                    write_indent(output, depth + 1)?;
                    write_json(item, depth + 1, maximum_depth, output)?;
                }
                output.append("\n")?;
                write_indent(output, depth)?;
                output.append("]")?;
            }
        }
        GithubValue::Object(object) => {
            if object.entries().is_empty() {
                output.append("{}")?;
            } else {
                output.append("{")?;
                for (index, (key, item)) in object.entries().iter().enumerate() {
                    if index > 0 {
                        output.append(",")?;
                    }
                    output.append("\n")?;
                    write_indent(output, depth + 1)?;
                    serde_json::to_writer(&mut *output, key).map_err(|_| resource_limit())?;
                    output.append(": ")?;
                    write_json(item, depth + 1, maximum_depth, output)?;
                }
                output.append("\n")?;
                write_indent(output, depth)?;
                output.append("}")?;
            }
        }
    }
    Ok(())
}

fn write_indent(
    output: &mut BoundedJsonWriter,
    depth: usize,
) -> Result<(), GithubExpressionEvaluationError> {
    let spaces = depth.checked_mul(2).ok_or_else(resource_limit)?;
    for _ in 0..spaces {
        output.append(" ")?;
    }
    Ok(())
}

struct BoundedJsonWriter {
    bytes: Vec<u8>,
    maximum_bytes: usize,
}

impl BoundedJsonWriter {
    const fn new(maximum_bytes: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum_bytes,
        }
    }

    fn append(&mut self, value: &str) -> Result<(), GithubExpressionEvaluationError> {
        self.write_all(value.as_bytes())
            .map_err(|_| resource_limit())
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl std::io::Write for BoundedJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let next = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|next| *next <= self.maximum_bytes)
            .ok_or_else(|| std::io::Error::other("JSON result limit exceeded"))?;
        self.bytes.reserve(next - self.bytes.len());
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct JsonBudget {
    items: Cell<usize>,
    maximum_items: usize,
    maximum_depth: usize,
    exhausted: Cell<bool>,
}

impl JsonBudget {
    const fn new(maximum_items: usize, maximum_depth: usize) -> Self {
        Self {
            items: Cell::new(0),
            maximum_items,
            maximum_depth,
            exhausted: Cell::new(false),
        }
    }

    fn observe(&self, depth: usize) -> bool {
        let Some(items) = self.items.get().checked_add(1) else {
            self.exhausted.set(true);
            return false;
        };
        if items > self.maximum_items || depth >= self.maximum_depth {
            self.exhausted.set(true);
            return false;
        }
        self.items.set(items);
        true
    }
}

#[derive(Clone, Copy)]
struct JsonValueSeed<'budget> {
    depth: usize,
    budget: &'budget JsonBudget,
}

impl<'de> DeserializeSeed<'de> for JsonValueSeed<'_> {
    type Value = GithubValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if !self.budget.observe(self.depth) {
            return Err(serde::de::Error::custom("JSON value depth limit exceeded"));
        }
        deserializer.deserialize_any(JsonValueVisitor {
            depth: self.depth,
            budget: self.budget,
        })
    }
}

struct JsonValueVisitor<'budget> {
    depth: usize,
    budget: &'budget JsonBudget,
}

impl<'de> Visitor<'de> for JsonValueVisitor<'_> {
    type Value = GithubValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a bounded JSON value")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(GithubValue::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(GithubValue::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(GithubValue::Boolean(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        value
            .to_string()
            .parse::<f64>()
            .map(GithubValue::number)
            .map_err(|_| E::custom("JSON number cannot be represented"))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        value
            .to_string()
            .parse::<f64>()
            .map(GithubValue::number)
            .map_err(|_| E::custom("JSON number cannot be represented"))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E> {
        Ok(GithubValue::number(value))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(GithubValue::string(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(
            sequence
                .size_hint()
                .unwrap_or(0)
                .min(self.budget.maximum_items),
        );
        let seed = JsonValueSeed {
            depth: self.depth + 1,
            budget: self.budget,
        };
        while let Some(value) = sequence.next_element_seed(seed)? {
            values.push(value);
        }
        GithubValue::array(values)
            .map_err(|_| serde::de::Error::custom("JSON collection limit exceeded"))
    }

    fn visit_map<A>(self, mut mapping: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Vec::with_capacity(
            mapping
                .size_hint()
                .unwrap_or(0)
                .min(self.budget.maximum_items),
        );
        let seed = JsonValueSeed {
            depth: self.depth + 1,
            budget: self.budget,
        };
        while let Some(key) = mapping.next_key::<String>()? {
            values.push((key, mapping.next_value_seed(seed)?));
        }
        GithubObject::new(values)
            .map(GithubValue::object)
            .map_err(|_| serde::de::Error::custom("invalid JSON object"))
    }
}

fn exact_arity(
    arguments: &[GithubValue],
    expected: usize,
) -> Result<(), GithubExpressionEvaluationError> {
    arity_range(arguments, expected, expected)
}

fn arity_range(
    arguments: &[GithubValue],
    minimum: usize,
    maximum: usize,
) -> Result<(), GithubExpressionEvaluationError> {
    if (minimum..=maximum).contains(&arguments.len()) {
        Ok(())
    } else {
        Err(invalid_operation())
    }
}

pub(crate) const fn invalid_operation() -> GithubExpressionEvaluationError {
    GithubExpressionEvaluationError::new(GithubExpressionEvaluationErrorKind::InvalidOperation)
}

pub(crate) const fn resource_limit() -> GithubExpressionEvaluationError {
    GithubExpressionEvaluationError::new(GithubExpressionEvaluationErrorKind::ResourceLimit)
}
