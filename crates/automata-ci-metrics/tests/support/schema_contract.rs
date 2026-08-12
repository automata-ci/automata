use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Deserialize)]
struct Manifest {
    schema_version: u64,
    profiles: BTreeMap<String, Profile>,
}

#[derive(Debug, Deserialize)]
struct Profile {
    #[serde(default)]
    series_budget: Option<usize>,
    families: Vec<FamilyContract>,
}

#[derive(Debug, Deserialize)]
struct FamilyContract {
    name: String,
    help: String,
    #[serde(rename = "type")]
    metric_type: String,
    #[serde(default)]
    unit: Option<String>,
    labels: Vec<LabelContract>,
    label_sets: LabelSets,
    #[serde(default)]
    buckets: Vec<String>,
    maximum_series: usize,
}

#[derive(Debug, Deserialize)]
struct LabelContract {
    name: String,
    #[serde(default)]
    values: Vec<String>,
    #[serde(default)]
    validator: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LabelSets {
    mode: String,
    #[serde(default)]
    tuples: Vec<Vec<String>>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ActualFamily {
    help: String,
    metric_type: String,
    unit: Option<String>,
    label_names: BTreeSet<String>,
    label_sets: BTreeSet<Vec<(String, String)>>,
    buckets: BTreeSet<String>,
    bucket_sets: BTreeMap<Vec<(String, String)>, BTreeSet<String>>,
    sums: BTreeMap<Vec<(String, String)>, usize>,
    counts: BTreeMap<Vec<(String, String)>, usize>,
    maximum_series: usize,
}

pub fn assert_exposition_contract(manifest_json: &str, exposition: &str, profile_names: &[&str]) {
    let manifest: Manifest =
        serde_json::from_str(manifest_json).expect("cardinality manifest must be valid JSON");
    validate_manifest(&manifest);
    let actual = parse_exposition(exposition);

    let mut expected = BTreeMap::new();
    for profile_name in profile_names {
        let profile = manifest
            .profiles
            .get(*profile_name)
            .unwrap_or_else(|| panic!("missing metrics profile: {profile_name}"));
        for family in &profile.families {
            assert!(
                expected.insert(family.name.as_str(), family).is_none(),
                "family is repeated across selected profiles: {}",
                family.name
            );
        }
    }

    let expected_names = expected.keys().copied().collect::<BTreeSet<_>>();
    let actual_names = actual.keys().map(String::as_str).collect::<BTreeSet<_>>();
    assert_eq!(
        actual_names,
        expected_names,
        "OpenMetrics family set differs from the canonical manifest\nactual schema:\n{}",
        inferred_contract_json(&actual)
    );

    for (name, contract) in expected {
        let family = actual
            .get(name)
            .unwrap_or_else(|| panic!("missing metric family: {name}"));
        assert_family(name, contract, family);
    }

    let expected_series = profile_names
        .iter()
        .flat_map(|name| &manifest.profiles[*name].families)
        .map(|family| family.maximum_series)
        .sum::<usize>();
    let actual_series = actual
        .values()
        .map(|family| family.maximum_series)
        .sum::<usize>();
    assert_eq!(
        actual_series, expected_series,
        "process series total changed"
    );

    if let Some(product_profile) = profile_names.iter().find_map(|name| {
        manifest.profiles[*name]
            .series_budget
            .map(|budget| (*name, budget))
    }) {
        assert!(
            actual_series <= product_profile.1,
            "{} process exposes {actual_series} series over its {} budget",
            product_profile.0,
            product_profile.1
        );
    }
}

pub fn inferred_profile_json(exposition: &str, family_prefixes: &[&str]) -> String {
    let all = parse_exposition(exposition);
    let selected = all
        .into_iter()
        .filter(|(name, _)| {
            family_prefixes
                .iter()
                .any(|prefix| name.starts_with(prefix))
        })
        .collect::<BTreeMap<_, _>>();
    inferred_contract_json(&selected)
}

#[allow(clippy::too_many_lines)] // One canonical validation walk keeps all schema invariants together.
fn validate_manifest(manifest: &Manifest) {
    assert_eq!(
        manifest.schema_version, 2,
        "unsupported metrics schema version"
    );
    assert_eq!(
        manifest
            .profiles
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["common", "control_plane", "runner"]
    );
    assert!(manifest.profiles["common"].series_budget.is_none());
    assert!(manifest.profiles["control_plane"].series_budget.is_some());
    assert!(manifest.profiles["runner"].series_budget.is_some());

    let mut family_names = BTreeSet::new();
    for profile in manifest.profiles.values() {
        assert!(!profile.families.is_empty(), "metrics profile is empty");
        if let Some(budget) = profile.series_budget {
            assert!(budget > 0, "series budget must be positive");
        }
        for family in &profile.families {
            assert!(
                !family.help.is_empty(),
                "metric HELP is empty: {}",
                family.name
            );
            assert!(
                valid_metric_name(&family.name),
                "invalid metric name: {}",
                family.name
            );
            assert!(
                family_names.insert(family.name.as_str()),
                "duplicate metric family: {}",
                family.name
            );
            assert!(
                matches!(
                    family.metric_type.as_str(),
                    "counter" | "gauge" | "histogram" | "info"
                ),
                "invalid metric type for {}",
                family.name
            );
            if let Some(unit) = &family.unit {
                assert!(
                    matches!(unit.as_str(), "seconds" | "bytes"),
                    "invalid unit for {}",
                    family.name
                );
            }
            let mut label_names = BTreeSet::new();
            for label in &family.labels {
                assert!(
                    valid_label_name(&label.name),
                    "invalid label name in {}",
                    family.name
                );
                assert!(
                    label_names.insert(label.name.as_str()),
                    "duplicate label in {}",
                    family.name
                );
                assert!(
                    matches!(
                        label.name.as_str(),
                        "backend"
                            | "cause"
                            | "conclusion"
                            | "dependency"
                            | "desired_state"
                            | "direction"
                            | "disposition"
                            | "domain"
                            | "event"
                            | "exchange"
                            | "kind"
                            | "lifecycle"
                            | "method"
                            | "mode"
                            | "observed_state"
                            | "operation"
                            | "outcome"
                            | "reason"
                            | "resource"
                            | "revision"
                            | "role"
                            | "route"
                            | "service"
                            | "stage"
                            | "state"
                            | "status"
                            | "status_class"
                            | "version"
                    ),
                    "unreviewed or identity-bearing label in {}: {}",
                    family.name,
                    label.name
                );
                assert!(
                    label.validator.is_some() ^ !label.values.is_empty(),
                    "each label in {} needs either values or one validator",
                    family.name
                );
                let unique_values = label.values.iter().collect::<BTreeSet<_>>();
                assert_eq!(
                    unique_values.len(),
                    label.values.len(),
                    "duplicate label value in {}",
                    family.name
                );
                assert!(
                    label.values.iter().all(|value| !value.is_empty()),
                    "empty label value in {}",
                    family.name
                );
                if let Some(validator) = &label.validator {
                    assert!(
                        matches!(
                            validator.as_str(),
                            "build_version" | "build_revision" | "process_role"
                        ),
                        "unknown label validator in {}",
                        family.name
                    );
                }
            }

            let label_set_count = match family.label_sets.mode.as_str() {
                "cartesian" => {
                    assert!(
                        family.label_sets.tuples.is_empty(),
                        "cartesian family {} has explicit tuples",
                        family.name
                    );
                    assert!(
                        family.labels.iter().all(|label| label.validator.is_none()),
                        "cartesian family {} has a dynamic label",
                        family.name
                    );
                    family
                        .labels
                        .iter()
                        .map(|label| label.values.len())
                        .product()
                }
                "explicit" => {
                    assert!(
                        !family.label_sets.tuples.is_empty(),
                        "explicit family {} has no tuples",
                        family.name
                    );
                    let tuples = family.label_sets.tuples.iter().collect::<BTreeSet<_>>();
                    assert_eq!(
                        tuples.len(),
                        family.label_sets.tuples.len(),
                        "duplicate tuple in {}",
                        family.name
                    );
                    for tuple in &family.label_sets.tuples {
                        assert_eq!(
                            tuple.len(),
                            family.labels.len(),
                            "tuple width differs in {}",
                            family.name
                        );
                        for (value, label) in tuple.iter().zip(&family.labels) {
                            assert!(
                                label.values.contains(value),
                                "tuple value is outside {}.{} domain",
                                family.name,
                                label.name
                            );
                        }
                    }
                    family.label_sets.tuples.len()
                }
                "dynamic_singleton" => {
                    assert!(
                        family.label_sets.tuples.is_empty(),
                        "dynamic singleton {} has tuples",
                        family.name
                    );
                    assert!(
                        family.labels.iter().all(|label| label.validator.is_some()),
                        "dynamic singleton {} has a fixed label domain",
                        family.name
                    );
                    1
                }
                other => panic!("invalid label-set mode {other} in {}", family.name),
            };

            let series_per_label_set = if family.metric_type == "histogram" {
                assert!(
                    !family.buckets.is_empty(),
                    "histogram {} has no finite buckets",
                    family.name
                );
                let mut previous = f64::NEG_INFINITY;
                for bucket in &family.buckets {
                    let value = bucket
                        .parse::<f64>()
                        .unwrap_or_else(|_| panic!("invalid bucket in {}", family.name));
                    assert!(
                        value.is_finite() && value > previous,
                        "unordered bucket in {}",
                        family.name
                    );
                    previous = value;
                }
                family.buckets.len() + 3
            } else {
                assert!(
                    family.buckets.is_empty(),
                    "non-histogram {} declares buckets",
                    family.name
                );
                1
            };
            assert_eq!(
                family.maximum_series,
                label_set_count * series_per_label_set,
                "maximum series arithmetic differs for {}",
                family.name
            );
        }
    }

    let common = manifest.profiles["common"]
        .families
        .iter()
        .map(|family| family.maximum_series)
        .sum::<usize>();
    for product in ["control_plane", "runner"] {
        let profile = &manifest.profiles[product];
        let product_series = profile
            .families
            .iter()
            .map(|family| family.maximum_series)
            .sum::<usize>();
        assert!(common + product_series <= profile.series_budget.expect("product budget"));
    }
}

fn assert_family(name: &str, contract: &FamilyContract, actual: &ActualFamily) {
    assert_eq!(actual.help, contract.help, "HELP changed for {name}");
    assert_eq!(
        actual.metric_type, contract.metric_type,
        "TYPE changed for {name}"
    );
    assert_eq!(actual.unit, contract.unit, "UNIT changed for {name}");
    let expected_names = contract
        .labels
        .iter()
        .map(|label| label.name.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual.label_names, expected_names,
        "label keys changed for {name}"
    );

    let actual_tuples = actual
        .label_sets
        .iter()
        .map(|labels| tuple_in_contract_order(name, labels, &contract.labels))
        .collect::<BTreeSet<_>>();
    match contract.label_sets.mode.as_str() {
        "cartesian" => {
            let expected = cartesian_tuples(&contract.labels);
            assert_eq!(
                actual_tuples, expected,
                "label domain/tuples changed for {name}"
            );
        }
        "explicit" => {
            let expected = contract
                .label_sets
                .tuples
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            assert_eq!(
                actual_tuples, expected,
                "reachable label tuples changed for {name}"
            );
        }
        "dynamic_singleton" => {
            assert_eq!(
                actual_tuples.len(),
                1,
                "dynamic singleton cardinality changed for {name}"
            );
            for (value, label) in actual_tuples
                .iter()
                .next()
                .expect("one tuple")
                .iter()
                .zip(&contract.labels)
            {
                assert_label_value(name, label, value);
            }
        }
        _ => unreachable!("manifest was validated"),
    }

    if contract.metric_type == "histogram" {
        let expected_buckets = contract.buckets.iter().cloned().collect::<BTreeSet<_>>();
        assert_eq!(
            actual.buckets, expected_buckets,
            "finite buckets changed for {name}"
        );
        let mut expected_with_infinity = expected_buckets;
        expected_with_infinity.insert("+Inf".to_owned());
        for label_set in &actual.label_sets {
            assert_eq!(
                actual.bucket_sets.get(label_set),
                Some(&expected_with_infinity),
                "histogram bucket expansion changed for {name} {label_set:?}"
            );
            assert_eq!(
                actual.sums.get(label_set),
                Some(&1),
                "histogram sum changed for {name}"
            );
            assert_eq!(
                actual.counts.get(label_set),
                Some(&1),
                "histogram count changed for {name}"
            );
        }
    }
    assert_eq!(
        actual.maximum_series, contract.maximum_series,
        "series maximum changed for {name}"
    );
}

fn assert_label_value(family: &str, label: &LabelContract, value: &str) {
    if !label.values.is_empty() {
        assert!(
            label.values.iter().any(|allowed| allowed == value),
            "value outside {family}.{} domain",
            label.name
        );
        return;
    }
    let valid = match label.validator.as_deref() {
        Some("build_version") => {
            !value.is_empty()
                && value.len() <= 64
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'_')
                })
        }
        Some("build_revision") => {
            value == "unknown"
                || (matches!(value.len(), 40 | 64)
                    && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        }
        Some("process_role") => matches!(value, "control_plane" | "runner"),
        _ => false,
    };
    assert!(valid, "value failed {family}.{} validator", label.name);
}

fn cartesian_tuples(labels: &[LabelContract]) -> BTreeSet<Vec<String>> {
    let mut tuples = vec![Vec::new()];
    for label in labels {
        let mut expanded = Vec::new();
        for tuple in tuples {
            for value in &label.values {
                let mut next = tuple.clone();
                next.push(value.clone());
                expanded.push(next);
            }
        }
        tuples = expanded;
    }
    tuples.into_iter().collect()
}

fn tuple_in_contract_order(
    family: &str,
    actual: &[(String, String)],
    labels: &[LabelContract],
) -> Vec<String> {
    let values = actual.iter().cloned().collect::<BTreeMap<_, _>>();
    labels
        .iter()
        .map(|label| {
            values
                .get(&label.name)
                .unwrap_or_else(|| panic!("missing {family}.{}", label.name))
                .clone()
        })
        .collect()
}

#[allow(clippy::too_many_lines)] // Parsing every OpenMetrics sample shape is clearer as one stateful pass.
fn parse_exposition(exposition: &str) -> BTreeMap<String, ActualFamily> {
    let mut helps = BTreeMap::<String, String>::new();
    let mut descriptors = BTreeMap::<String, (String, Option<String>)>::new();
    let mut units = BTreeMap::<String, String>::new();
    for line in exposition.lines() {
        if let Some(metadata) = line.strip_prefix("# HELP ") {
            let (descriptor, help) = metadata
                .split_once(' ')
                .unwrap_or_else(|| panic!("malformed HELP: {line}"));
            assert!(!descriptor.is_empty(), "malformed HELP: {line}");
            let help = parse_help_text(help);
            assert!(!help.is_empty(), "empty HELP: {descriptor}");
            assert!(
                helps.insert(descriptor.to_owned(), help).is_none(),
                "duplicate HELP: {descriptor}"
            );
        } else if let Some(metadata) = line.strip_prefix("# TYPE ") {
            let (descriptor, metric_type) = metadata
                .split_once(' ')
                .unwrap_or_else(|| panic!("malformed TYPE: {line}"));
            assert!(
                descriptors
                    .insert(descriptor.to_owned(), (metric_type.to_owned(), None))
                    .is_none(),
                "duplicate TYPE: {descriptor}"
            );
        } else if let Some(metadata) = line.strip_prefix("# UNIT ") {
            let (descriptor, unit) = metadata
                .split_once(' ')
                .unwrap_or_else(|| panic!("malformed UNIT: {line}"));
            assert!(
                units
                    .insert(descriptor.to_owned(), unit.to_owned())
                    .is_none(),
                "duplicate UNIT: {descriptor}"
            );
        }
    }
    assert!(!descriptors.is_empty(), "exposition has no TYPE metadata");
    for descriptor in helps.keys() {
        assert!(
            descriptors.contains_key(descriptor),
            "HELP without TYPE: {descriptor}"
        );
    }
    for (descriptor, unit) in units {
        descriptors
            .get_mut(&descriptor)
            .unwrap_or_else(|| panic!("UNIT without TYPE: {descriptor}"))
            .1 = Some(unit);
    }

    let mut sample_to_descriptor = BTreeMap::<String, (String, SamplePart)>::new();
    let mut actual = BTreeMap::new();
    for (descriptor, (metric_type, unit)) in descriptors {
        let help = helps
            .remove(&descriptor)
            .unwrap_or_else(|| panic!("TYPE without HELP: {descriptor}"));
        let family_name = canonical_family_name(&descriptor, &metric_type);
        let mut family = ActualFamily {
            help,
            metric_type: metric_type.clone(),
            unit,
            ..ActualFamily::default()
        };
        match metric_type.as_str() {
            "histogram" => {
                sample_to_descriptor.insert(
                    format!("{descriptor}_bucket"),
                    (family_name.clone(), SamplePart::Bucket),
                );
                sample_to_descriptor.insert(
                    format!("{descriptor}_sum"),
                    (family_name.clone(), SamplePart::Sum),
                );
                sample_to_descriptor.insert(
                    format!("{descriptor}_count"),
                    (family_name.clone(), SamplePart::Count),
                );
            }
            _ => {
                sample_to_descriptor.insert(
                    family_name.clone(),
                    (family_name.clone(), SamplePart::Value),
                );
            }
        }
        assert!(
            actual
                .insert(family_name, std::mem::take(&mut family))
                .is_none(),
            "duplicate canonical family"
        );
    }

    for line in exposition
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let sample = line.split_once(' ').map_or(line, |(sample, _value)| sample);
        let (sample_name, labels) = parse_sample(sample);
        let (family_name, part) = sample_to_descriptor
            .get(sample_name)
            .unwrap_or_else(|| panic!("sample without TYPE family: {sample_name}"));
        let family = actual.get_mut(family_name).expect("known family");
        family.maximum_series += 1;
        let mut base_labels = labels;
        match part {
            SamplePart::Bucket => {
                let bucket = remove_label(&mut base_labels, "le")
                    .unwrap_or_else(|| panic!("histogram bucket lacks le: {sample}"));
                if bucket != "+Inf" {
                    family.buckets.insert(bucket.clone());
                }
                family
                    .bucket_sets
                    .entry(base_labels.clone())
                    .or_default()
                    .insert(bucket);
            }
            SamplePart::Sum => *family.sums.entry(base_labels.clone()).or_default() += 1,
            SamplePart::Count => *family.counts.entry(base_labels.clone()).or_default() += 1,
            SamplePart::Value => {}
        }
        for (name, _) in &base_labels {
            family.label_names.insert(name.clone());
        }
        family.label_sets.insert(base_labels);
    }
    assert!(
        actual.values().all(|family| family.maximum_series > 0),
        "TYPE family has no samples"
    );
    actual
}

fn parse_help_text(encoded: &str) -> String {
    let mut chars = encoded.chars();
    let mut help = String::with_capacity(encoded.len());
    while let Some(character) = chars.next() {
        if character != '\\' {
            help.push(character);
            continue;
        }
        let escaped = chars
            .next()
            .unwrap_or_else(|| panic!("truncated HELP escape: {encoded}"));
        help.push(match escaped {
            'n' => '\n',
            '\\' => '\\',
            _ => panic!("invalid HELP escape in {encoded}"),
        });
    }
    help
}

#[derive(Clone, Copy, Debug)]
enum SamplePart {
    Value,
    Bucket,
    Sum,
    Count,
}

fn canonical_family_name(descriptor: &str, metric_type: &str) -> String {
    match metric_type {
        "counter" => format!("{descriptor}_total"),
        "info" => format!("{descriptor}_info"),
        _ => descriptor.to_owned(),
    }
}

fn parse_sample(sample: &str) -> (&str, Vec<(String, String)>) {
    let Some(open) = sample.find('{') else {
        return (sample, Vec::new());
    };
    assert!(sample.ends_with('}'), "malformed label set: {sample}");
    let name = &sample[..open];
    let labels = parse_labels(&sample[open + 1..sample.len() - 1]);
    (name, labels)
}

fn parse_labels(encoded: &str) -> Vec<(String, String)> {
    if encoded.is_empty() {
        return Vec::new();
    }
    let bytes = encoded.as_bytes();
    let mut cursor = 0;
    let mut labels = Vec::new();
    while cursor < bytes.len() {
        let name_start = cursor;
        while cursor < bytes.len() && bytes[cursor] != b'=' {
            cursor += 1;
        }
        assert!(
            cursor > name_start && cursor + 1 < bytes.len() && bytes[cursor + 1] == b'"',
            "malformed labels: {encoded}"
        );
        let name = encoded[name_start..cursor].to_owned();
        cursor += 2;
        let mut value = String::new();
        let mut escaped = false;
        while cursor < bytes.len() {
            let byte = bytes[cursor];
            cursor += 1;
            if escaped {
                value.push(match byte {
                    b'n' => '\n',
                    b'\\' => '\\',
                    b'"' => '"',
                    _ => panic!("invalid label escape in {encoded}"),
                });
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                break;
            } else {
                value.push(char::from(byte));
            }
        }
        assert!(!escaped, "truncated label escape in {encoded}");
        labels.push((name, value));
        if cursor == bytes.len() {
            break;
        }
        assert_eq!(
            bytes[cursor], b',',
            "malformed label separator in {encoded}"
        );
        cursor += 1;
    }
    labels.sort();
    let unique = labels.iter().map(|(name, _)| name).collect::<BTreeSet<_>>();
    assert_eq!(
        unique.len(),
        labels.len(),
        "duplicate sample label in {encoded}"
    );
    labels
}

fn remove_label(labels: &mut Vec<(String, String)>, wanted: &str) -> Option<String> {
    let index = labels.iter().position(|(name, _)| name == wanted)?;
    Some(labels.remove(index).1)
}

fn inferred_contract_json(actual: &BTreeMap<String, ActualFamily>) -> String {
    let families = actual
        .iter()
        .map(|(name, family)| inferred_family(name, family))
        .collect::<Vec<_>>();
    serde_json::to_string_pretty(&families).expect("inferred schema is serializable")
}

fn inferred_family(name: &str, family: &ActualFamily) -> Value {
    let label_names = family.label_names.iter().cloned().collect::<Vec<_>>();
    let tuples = family
        .label_sets
        .iter()
        .map(|labels| {
            let values = labels.iter().cloned().collect::<BTreeMap<_, _>>();
            label_names
                .iter()
                .map(|label| values[label].clone())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let mut labels = Vec::new();
    for (index, label_name) in label_names.iter().enumerate() {
        let values = tuples
            .iter()
            .map(|tuple| tuple[index].clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        labels.push(json!({"name": label_name, "values": values}));
    }
    let cartesian_count = labels
        .iter()
        .map(|label| label["values"].as_array().expect("values").len())
        .product::<usize>();
    let label_sets = if cartesian_count == tuples.len() {
        json!({"mode": "cartesian"})
    } else {
        json!({"mode": "explicit", "tuples": tuples})
    };
    let mut value = json!({
        "name": name,
        "help": family.help,
        "type": family.metric_type,
        "labels": labels,
        "label_sets": label_sets,
        "maximum_series": family.maximum_series,
    });
    if let Some(unit) = &family.unit {
        value["unit"] = json!(unit);
    }
    if family.metric_type == "histogram" {
        let mut buckets = family.buckets.iter().cloned().collect::<Vec<_>>();
        buckets.sort_by(|left, right| {
            left.parse::<f64>()
                .expect("parsed exposition bucket")
                .total_cmp(&right.parse::<f64>().expect("parsed exposition bucket"))
        });
        value["buckets"] = json!(buckets);
    }
    value
}

fn valid_metric_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'_' | b':'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':'))
}

fn valid_label_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[cfg(test)]
mod contract_tests {
    use std::{any::Any, panic};

    use serde_json::Value;

    use super::{assert_exposition_contract, inferred_profile_json, json};

    fn panic_message(payload: &(dyn Any + Send)) -> String {
        if let Some(message) = payload.downcast_ref::<String>() {
            return message.clone();
        }
        if let Some(message) = payload.downcast_ref::<&str>() {
            return (*message).to_owned();
        }
        "non-string panic".to_owned()
    }

    fn assert_inference_panics(exposition: &str, expected: &str) {
        let panic = panic::catch_unwind(|| inferred_profile_json(exposition, &[""]))
            .expect_err("malformed exposition must fail closed");
        let message = panic_message(panic.as_ref());
        assert!(
            message.contains(expected),
            "panic `{message}` did not contain `{expected}`"
        );
    }

    fn manifest(common_help: &str) -> String {
        serde_json::to_string(&json!({
            "schema_version": 2,
            "profiles": {
                "common": {
                    "families": [{
                        "name": "fixture_requests_total",
                        "help": common_help,
                        "type": "counter",
                        "labels": [],
                        "label_sets": {"mode": "cartesian"},
                        "maximum_series": 1
                    }]
                },
                "control_plane": {
                    "series_budget": 2,
                    "families": [{
                        "name": "fixture_control_ready",
                        "help": "Whether the fixture control plane is ready.",
                        "type": "gauge",
                        "labels": [],
                        "label_sets": {"mode": "cartesian"},
                        "maximum_series": 1
                    }]
                },
                "runner": {
                    "series_budget": 2,
                    "families": [{
                        "name": "fixture_runner_ready",
                        "help": "Whether the fixture runner is ready.",
                        "type": "gauge",
                        "labels": [],
                        "label_sets": {"mode": "cartesian"},
                        "maximum_series": 1
                    }]
                }
            }
        }))
        .expect("fixture manifest is serializable")
    }

    #[test]
    fn inferred_schema_canonicalizes_counter_and_info_help() {
        let inferred = inferred_profile_json(
            "# HELP fixture_requests Number of requests.\n\
             # TYPE fixture_requests counter\n\
             fixture_requests_total 0\n\
             # HELP fixture_build Build\\nmetadata with é.\n\
             # TYPE fixture_build info\n\
             fixture_build_info{version=\"1\"} 1\n\
             # EOF\n",
            &["fixture_"],
        );
        let families: Vec<Value> = serde_json::from_str(&inferred).expect("inferred JSON");
        assert_eq!(families[0]["name"], "fixture_build_info");
        assert_eq!(families[0]["help"], "Build\nmetadata with é.");
        assert_eq!(families[1]["name"], "fixture_requests_total");
        assert_eq!(families[1]["help"], "Number of requests.");
    }

    #[test]
    fn exposition_requires_exactly_one_help_and_type_per_descriptor() {
        assert_inference_panics(
            "# HELP fixture Duplicate.\n# HELP fixture Duplicate.\n# TYPE fixture gauge\nfixture 1\n# EOF\n",
            "duplicate HELP: fixture",
        );
        assert_inference_panics(
            "# HELP fixture Present.\n# TYPE fixture gauge\n# TYPE fixture gauge\nfixture 1\n# EOF\n",
            "duplicate TYPE: fixture",
        );
        assert_inference_panics(
            "# HELP fixture Present.\n# TYPE fixture gauge\nfixture 1\n# HELP orphan Orphan.\n# EOF\n",
            "HELP without TYPE: orphan",
        );
        assert_inference_panics(
            "# TYPE fixture gauge\nfixture 1\n# EOF\n",
            "TYPE without HELP: fixture",
        );
    }

    #[test]
    fn committed_help_text_is_an_exact_contract() {
        let exposition = "# HELP fixture_requests Number of requests.\n# TYPE fixture_requests counter\nfixture_requests_total 0\n# EOF\n";
        assert_exposition_contract(&manifest("Number of requests."), exposition, &["common"]);

        let mismatch = panic::catch_unwind(|| {
            assert_exposition_contract(&manifest("Different help."), exposition, &["common"]);
        })
        .expect_err("changed HELP must fail the schema contract");
        assert!(
            panic_message(mismatch.as_ref()).contains("HELP changed for fixture_requests_total")
        );
    }
}
