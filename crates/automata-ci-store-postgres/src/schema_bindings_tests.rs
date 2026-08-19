use std::{collections::BTreeSet, fs, path::Path};

#[test]
fn admission_epoch_and_workflow_plan_use_independent_sql_parameters() {
    let postgres = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut inspected_queries = 0_usize;

    for path in source_files(&postgres) {
        let extension = path.extension().and_then(|value| value.to_str());
        if !matches!(extension, Some("rs" | "sql")) {
            continue;
        }
        let source = fs::read_to_string(&path).expect("read PostgreSQL adapter source");
        let queries = if extension == Some("sql") {
            vec![source.as_str()]
        } else {
            rust_raw_strings(&source)
        };
        for query in queries {
            let Some(result) = validate_independent_schema_parameters(query) else {
                continue;
            };
            inspected_queries += 1;
            result.unwrap_or_else(|error| panic!("{} {error}", path.display()));
        }
    }

    assert!(
        inspected_queries >= 17,
        "expected the PostgreSQL Store adapter's independently versioned run-schema queries"
    );

    for (file, minimum_binds) in [
        ("github_job_runtime_authority.rs", 1),
        ("workload_oidc.rs", 1),
        ("logical_activation.rs", 4),
        ("logical_activation_preparation.rs", 1),
        ("logical_graph.rs", 1),
        ("logical_instance_result.rs", 1),
        ("logical_job_result.rs", 1),
        ("logical_materialization.rs", 3),
        ("logical_run_finalization.rs", 2),
        ("logical_work_selection.rs", 5),
        ("managed_secret_authority.rs", 2),
        ("reusable_workflow_runtime.rs", 1),
    ] {
        let source = fs::read_to_string(postgres.join(file)).expect("read bound Store adapter");
        assert!(
            source.matches(".bind(schemas.admission_epoch_i32)").count() >= minimum_binds,
            "{file} must bind the independently sourced admission epoch"
        );
    }

    assert!(
        validate_independent_schema_parameters(
            "WHERE run.admission_epoch = 1 AND run.plan_schema = 1"
        )
        .expect("both columns are compared")
        .is_err(),
        "hardcoded schema comparisons must fail closed"
    );
    assert!(
        validate_independent_schema_parameters(
            "WHERE run.admission_epoch = $1 AND run.plan_schema = $1"
        )
        .expect("both columns are compared")
        .is_err(),
        "shared schema parameters must fail closed"
    );
    assert!(
        validate_independent_schema_parameters(
            "WHERE run.admission_epoch = $1 AND run.plan_schema = $2"
        )
        .expect("both columns are compared")
        .is_ok(),
        "independent schema parameters must be accepted"
    );
}

fn validate_independent_schema_parameters(query: &str) -> Option<Result<(), String>> {
    if !compares_column(query, "admission_epoch") || !compares_column(query, "plan_schema") {
        return None;
    }
    let hardcoded_admission = integer_comparisons(query, "admission_epoch");
    let hardcoded_plan = integer_comparisons(query, "plan_schema");
    if !hardcoded_admission.is_empty() || !hardcoded_plan.is_empty() {
        return Some(Err(format!(
            "hardcodes admission epoch {hardcoded_admission:?} or workflow-plan schema {hardcoded_plan:?}"
        )));
    }
    let admission = parameter_numbers(query, "admission_epoch");
    let plan = parameter_numbers(query, "plan_schema");
    if admission.is_empty() || plan.is_empty() {
        return Some(Err(
            "must bind both admission epoch and workflow-plan schema".to_owned(),
        ));
    }
    let shared = admission.intersection(&plan).copied().collect::<Vec<_>>();
    if !shared.is_empty() {
        return Some(Err(format!(
            "couples admission epoch and workflow-plan schema through SQL parameter(s) {shared:?}"
        )));
    }
    Some(Ok(()))
}

fn compares_column(query: &str, column: &str) -> bool {
    column_comparison_suffixes(query, column).any(|_| true)
}

fn integer_comparisons(query: &str, column: &str) -> Vec<u64> {
    column_comparison_suffixes(query, column)
        .filter_map(|suffix| {
            let digits = suffix
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>();
            if digits.is_empty() {
                None
            } else {
                digits.parse().ok()
            }
        })
        .collect()
}

fn column_comparison_suffixes<'a>(
    query: &'a str,
    column: &'a str,
) -> impl Iterator<Item = &'a str> {
    query.match_indices(column).filter_map(move |(index, _)| {
        let before = query[..index].chars().next_back();
        let mut suffix = &query[index + column.len()..];
        if before.is_some_and(identifier_character)
            || suffix.chars().next().is_some_and(identifier_character)
        {
            return None;
        }
        suffix = suffix.trim_start();
        suffix.strip_prefix('=').map(str::trim_start)
    })
}

fn source_files(directory: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for entry in fs::read_dir(directory).expect("read PostgreSQL adapter directory") {
        let path = entry.expect("read PostgreSQL adapter entry").path();
        if path.is_dir() {
            files.extend(source_files(&path));
        } else if path.is_file() {
            files.push(path);
        }
    }
    files.sort();
    files
}

fn parameter_numbers(query: &str, column: &str) -> BTreeSet<u16> {
    let mut parameters = BTreeSet::new();
    for suffix in column_comparison_suffixes(query, column) {
        let Some(after_parameter) = suffix.strip_prefix('$') else {
            continue;
        };
        let digits = after_parameter
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>();
        if let Ok(parameter) = digits.parse() {
            parameters.insert(parameter);
        }
    }
    parameters
}

fn identifier_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_'
}

fn rust_raw_strings(source: &str) -> Vec<&str> {
    let bytes = source.as_bytes();
    let mut strings = Vec::new();
    let mut cursor = 0_usize;
    while cursor < bytes.len() {
        if bytes[cursor] != b'r' {
            cursor += 1;
            continue;
        }
        let mut quote = cursor + 1;
        while quote < bytes.len() && bytes[quote] == b'#' {
            quote += 1;
        }
        if quote >= bytes.len() || bytes[quote] != b'"' {
            cursor += 1;
            continue;
        }
        let hashes = quote - cursor - 1;
        let content_start = quote + 1;
        let closing = format!("\"{}", "#".repeat(hashes));
        let Some(relative_end) = source[content_start..].find(&closing) else {
            break;
        };
        let content_end = content_start + relative_end;
        strings.push(&source[content_start..content_end]);
        cursor = content_end + closing.len();
    }
    strings
}
