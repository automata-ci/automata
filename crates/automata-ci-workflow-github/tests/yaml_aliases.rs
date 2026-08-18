use crate::support;

use automata_ci_core::{WorkflowEventProvenance, WorkflowPlan};
use automata_ci_workflow_github::{
    DiagnosticKind, GithubWorkflowFrontend, ParseWorkflowRequest, RunnerSelection,
    SourceProvenance, WorkflowFrontend, WorkflowParseLimits, YamlNode, YamlNodeKind,
};
use serde_json::Value;

#[test]
fn scalar_sequence_mapping_and_whole_job_aliases_decode_before_compilation() {
    let report = support::parse_accepted(include_str!("fixtures/aliases-equivalent.yml"));
    let plan = report.plan().expect("source plan");

    assert!(contains_alias(plan.document().root()));
    assert!(contains_anchor(plan.document().root()));
    assert!(!contains_alias(plan.expanded_document().root()));
    assert!(!contains_anchor(plan.expanded_document().root()));

    let workflow = plan.workflow();
    assert_eq!(workflow.jobs().len(), 3);
    for job in workflow.jobs() {
        assert_eq!(
            job.job().name().expect("aliased scalar").value(),
            "Alias equivalence"
        );
        assert!(matches!(
            job.job().runner().expect("aliased sequence"),
            RunnerSelection::Labels { labels, .. } if labels.len() == 2
        ));
        assert_eq!(job.job().environment().entries().len(), 2);
        assert_eq!(job.job().services().expect("aliased services").len(), 1);
        assert_eq!(job.job().steps().len(), 1);
    }

    let repeated = mapping_value(
        mapping_value(plan.expanded_document().root(), "jobs"),
        "repeated",
    );
    let repeated_env = mapping_value(repeated, "env");
    assert_eq!(
        plan.source().slice(repeated_env.span()),
        Some("*whole_job"),
        "outer alias use must remain the primary span"
    );
    assert!(
        repeated_env.alias_expansions().len() >= 2,
        "whole-job expansion must retain its nested env-alias provenance"
    );
}

#[test]
fn alias_use_spans_are_primary_and_definition_spans_are_retained() {
    let report = support::parse_accepted(include_str!("fixtures/aliases.yml"));
    let plan = report.plan().expect("source plan");
    let build = mapping_value(
        mapping_value(plan.expanded_document().root(), "jobs"),
        "build",
    );
    let environment = mapping_value(build, "env");
    assert_eq!(plan.source().slice(environment.span()), Some("*shared_env"));
    let [provenance] = environment.alias_expansions() else {
        panic!("one alias expansion provenance record");
    };
    assert_eq!(
        plan.source().slice(provenance.alias_use_span()),
        Some("*shared_env")
    );
    assert!(
        plan.source()
            .slice(provenance.definition_span())
            .is_some_and(|definition| definition.contains("MODE"))
    );
}

#[test]
fn duplicate_anchor_names_rebind_only_subsequent_aliases() {
    let report = support::parse_accepted(include_str!("fixtures/aliases-redefined.yml"));
    let jobs = report.plan().expect("source plan").workflow().jobs();
    assert_eq!(environment_value(jobs[0].job(), "GENERATION"), "first");
    assert_eq!(environment_value(jobs[1].job(), "GENERATION"), "second");
    assert_eq!(environment_value(jobs[2].job(), "GENERATION"), "second");
}

#[test]
fn alias_expansion_cannot_hide_a_duplicate_mapping_key_from_compilation() {
    let source = "on: push\njobs:\n  build:\n    &runner_key runs-on: linux\n    ? *runner_key\n    : windows\n    steps: [{run: echo build}]\n";
    let parsed = support::parse(source);
    assert!(
        parsed.plan().is_some(),
        "expanded workflow remains inspectable: {:#?}",
        parsed.diagnostics()
    );
    let compiled = support::compile(
        parsed.plan().expect("source plan"),
        WorkflowEventProvenance::new("github", "push"),
        None,
    );
    let diagnostic = compiled
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code() == "github.compile.duplicate_mapping_key")
        .expect("expanded duplicate key diagnostic");
    assert_eq!(
        parsed.source().slice(diagnostic.primary_span()),
        Some("*runner_key")
    );
}

#[test]
fn undefined_and_forward_aliases_have_stable_source_bound_diagnostics() {
    let cases = [
        (
            include_str!("fixtures/aliases-undefined.yml"),
            "github.yaml_undefined_alias",
            "*missing",
            0,
        ),
        (
            include_str!("fixtures/aliases-forward.yml"),
            "github.yaml_forward_alias",
            "*later",
            1,
        ),
    ];

    for (source, code, primary, related_count) in cases {
        let report = support::parse(source);
        assert!(report.plan().is_none());
        let diagnostic = report
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code() == code)
            .unwrap_or_else(|| panic!("missing {code}: {:#?}", report.diagnostics()));
        assert_eq!(diagnostic.kind(), DiagnosticKind::Semantic);
        assert_eq!(
            report.source().slice(diagnostic.primary_span()),
            Some(primary)
        );
        assert_eq!(diagnostic.related().len(), related_count);
        assert!(
            report
                .diagnostics()
                .iter()
                .all(|diagnostic| diagnostic.code() != "yaml.invalid_syntax")
        );
    }

    let punctuation_name = "on: push\nenv: *later?name\nlater: &later?name {}\njobs: {}\n";
    let report = support::parse(punctuation_name);
    let diagnostic = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code() == "github.yaml_forward_alias")
        .unwrap_or_else(|| {
            panic!(
                "missing punctuation-name diagnostic: {:#?}",
                report.diagnostics()
            )
        });
    assert_eq!(
        report.source().slice(diagnostic.primary_span()),
        Some("*later?name")
    );
    assert_eq!(diagnostic.related().len(), 1);
}

#[test]
fn cyclic_aliases_fail_before_semantic_decode() {
    let report = support::parse(include_str!("fixtures/aliases-cyclic.yml"));
    assert!(report.plan().is_none());
    let diagnostic = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code() == "github.yaml_alias_cycle")
        .expect("cycle diagnostic");
    assert_eq!(diagnostic.kind(), DiagnosticKind::Semantic);
    assert_eq!(
        report.source().slice(diagnostic.primary_span()),
        Some("*cycle")
    );
    assert_eq!(diagnostic.related().len(), 1);
}

#[test]
fn custom_tags_remain_rejected_when_their_anchored_values_expand() {
    let source = "on: push\nenv: &shared !!map\n  MODE: strict\njobs:\n  build:\n    runs-on: linux\n    env: *shared\n    steps: [{run: echo build}]\n";
    let report = support::parse(source);
    assert!(!report.is_accepted());
    assert!(
        report.plan().is_some(),
        "loss-aware plan should remain inspectable"
    );
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code() == "github.yaml_tag")
    );
}

#[test]
fn expansion_limits_are_independent_and_stable() {
    let source = include_str!("fixtures/aliases-amplification.yml");
    let cases = [
        (
            WorkflowParseLimits::default().with_max_alias_expansion_depth(1),
            "yaml.maximum_alias_expansion_depth_exceeded",
        ),
        (
            WorkflowParseLimits::default().with_max_expanded_nodes(30),
            "yaml.maximum_expanded_nodes_exceeded",
        ),
        (
            WorkflowParseLimits::default().with_max_expanded_scalar_bytes(64),
            "yaml.maximum_expanded_scalar_bytes_exceeded",
        ),
        (
            WorkflowParseLimits::default().with_max_alias_expansion_work(1),
            "yaml.maximum_alias_expansion_work_exceeded",
        ),
    ];

    for (limits, code) in cases {
        let report = GithubWorkflowFrontend::new(limits).parse(ParseWorkflowRequest::new(
            SourceProvenance::memory("amplification.yml"),
            source,
        ));
        assert!(report.plan().is_none(), "{code} must suppress the plan");
        assert!(
            report
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code() == code),
            "missing {code}: {:#?}",
            report.diagnostics()
        );
    }
}

#[test]
fn memoized_subtrees_cannot_bypass_the_alias_depth_limit() {
    let source = "name: &leaf linux\non: push\njobs:\n  define_one:\n    runs-on: &one [*leaf]\n    steps: [{run: echo one}]\n  use_one:\n    runs-on: *one\n    steps: [{run: echo one}]\n  define_two:\n    runs-on: &two [*one]\n    steps: [{run: echo two}]\n  use_two:\n    runs-on: *two\n    steps: [{run: echo two}]\n";
    let report = GithubWorkflowFrontend::new(
        WorkflowParseLimits::default().with_max_alias_expansion_depth(2),
    )
    .parse(ParseWorkflowRequest::new(
        SourceProvenance::memory("memo-depth.yml"),
        source,
    ));
    assert!(report.plan().is_none());
    assert!(report.diagnostics().iter().any(|diagnostic| {
        diagnostic.code() == "yaml.maximum_alias_expansion_depth_exceeded"
            && report.source().slice(diagnostic.primary_span()) == Some("*one")
    }));
}

#[test]
fn anchored_and_hand_expanded_workflows_compile_to_equivalent_logical_plans() {
    let anchored = compile(include_str!("fixtures/aliases-equivalent.yml"));
    let expanded = compile(include_str!("fixtures/aliases-hand-expanded.yml"));
    let mut anchored = serde_json::to_value(anchored).expect("serialize anchored plan");
    let mut expanded = serde_json::to_value(expanded).expect("serialize expanded plan");
    remove_source_spans(&mut anchored);
    remove_source_spans(&mut expanded);
    assert_eq!(anchored, expanded);
}

#[test]
fn scanner_ignores_anchor_spellings_in_quotes_comments_and_block_scalars() {
    let source = r#"name: "&later"
on: push
env: *later
# &later
description: literal &later
another-description: literal !fake &later
jobs:
  build:
    runs-on: linux
    steps:
      - run: |
          echo '&later'
"#;
    let report = support::parse(source);
    let diagnostic = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code() == "github.yaml_undefined_alias")
        .expect("undefined alias diagnostic");
    assert!(diagnostic.related().is_empty());
}

fn compile(source: &str) -> WorkflowPlan {
    let parsed = GithubWorkflowFrontend::default().parse(ParseWorkflowRequest::new(
        SourceProvenance::memory("equivalence.yml"),
        source,
    ));
    assert!(parsed.is_accepted(), "{:#?}", parsed.diagnostics());
    let compiled = support::compile(
        parsed.plan().expect("source plan"),
        WorkflowEventProvenance::new("github", "workflow_dispatch")
            .with_delivery_id("alias-equivalence")
            .with_commit_sha(
                automata_ci_core::GitObjectId::from_provider_hex(
                    "0123456789abcdef0123456789abcdef01234567",
                )
                .expect("revision"),
            )
            .with_git_ref("refs/heads/main"),
        None,
    );
    assert!(compiled.is_accepted(), "{:#?}", compiled.diagnostics());
    compiled.plan().expect("logical plan").clone()
}

fn remove_source_spans(value: &mut Value) {
    match value {
        Value::Array(values) => {
            for value in values {
                remove_source_spans(value);
            }
        }
        Value::Object(values) => {
            values.remove("span");
            values.remove("configured_trigger_span");
            for value in values.values_mut() {
                remove_source_spans(value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn mapping_value<'node>(node: &'node YamlNode, key: &str) -> &'node YamlNode {
    node.as_mapping()
        .expect("mapping")
        .iter()
        .find(|entry| {
            entry
                .key()
                .as_scalar()
                .is_some_and(|scalar| scalar.decoded() == key)
        })
        .unwrap_or_else(|| panic!("missing mapping key {key}"))
        .value()
}

fn contains_alias(node: &YamlNode) -> bool {
    matches!(node.kind(), YamlNodeKind::Alias(_)) || children(node).any(contains_alias)
}

fn contains_anchor(node: &YamlNode) -> bool {
    node.anchor().is_some() || children(node).any(contains_anchor)
}

fn children(node: &YamlNode) -> Box<dyn Iterator<Item = &YamlNode> + '_> {
    match node.kind() {
        YamlNodeKind::Sequence(items) => Box::new(items.iter()),
        YamlNodeKind::Mapping(entries) => Box::new(
            entries
                .iter()
                .flat_map(|entry| [entry.key(), entry.value()]),
        ),
        _ => Box::new(std::iter::empty()),
    }
}

fn environment_value<'job>(job: &'job automata_ci_workflow_github::Job, key: &str) -> &'job str {
    job.environment()
        .entries()
        .iter()
        .find(|entry| entry.key().value() == key)
        .unwrap_or_else(|| panic!("missing environment key {key}"))
        .value()
        .decoded()
}
