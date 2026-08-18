use crate::{EnvironmentVariables, GithubWorkflow, YamlNode};

use super::{
    DecodeContext,
    event::triggers,
    field_name,
    job::jobs,
    value::{concurrency, defaults, permissions, value_map},
};

pub(crate) fn decode_workflow(
    root: &YamlNode,
    diagnostics: &mut Vec<crate::Diagnostic>,
) -> Option<GithubWorkflow> {
    let mut context = DecodeContext::new(diagnostics);
    let entries = context.expect_mapping(root, "workflow")?;
    let mut name = None;
    let mut run_name = None;
    let mut workflow_triggers = None;
    let mut workflow_permissions = None;
    let mut environment = EnvironmentVariables::empty();
    let mut environment_seen = false;
    let mut workflow_defaults = None;
    let mut workflow_concurrency = None;
    let mut workflow_jobs = Vec::new();
    let mut jobs_seen = false;
    let mut extensions = Vec::new();

    for entry in entries {
        if context.is_exhausted() {
            break;
        }
        match field_name(entry) {
            Some("name") if name.is_none() => {
                name = context.text(&entry.value, "name");
            }
            Some("run-name") if run_name.is_none() => {
                run_name = context.text(&entry.value, "run-name");
            }
            Some("on") if workflow_triggers.is_none() => {
                workflow_triggers = triggers(&entry.value, "on", &mut context);
            }
            Some("permissions") if workflow_permissions.is_none() => {
                workflow_permissions = permissions(&entry.value, "permissions", &mut context);
            }
            Some("env") if !environment_seen => {
                environment = value_map(&entry.value, "env", &mut context);
                environment_seen = true;
            }
            Some("defaults") if workflow_defaults.is_none() => {
                workflow_defaults = defaults(&entry.value, "defaults", &mut context);
            }
            Some("concurrency") if workflow_concurrency.is_none() => {
                workflow_concurrency = concurrency(&entry.value, "concurrency", &mut context);
            }
            Some("jobs") if !jobs_seen => {
                workflow_jobs = jobs(&entry.value, "jobs", &mut context);
                jobs_seen = true;
            }
            Some(
                "name" | "run-name" | "on" | "permissions" | "env" | "defaults" | "concurrency"
                | "jobs",
            ) => {}
            _ => {
                if let Some(extension) = context.preserve_unknown("workflow", entry) {
                    extensions.push(extension);
                }
            }
        }
    }

    if context.is_exhausted() {
        return None;
    }
    if workflow_triggers.is_none() {
        context.semantic(
            "github.triggers_required",
            "workflow must define `on`",
            root.span.clone(),
        );
    }
    if context.is_exhausted() {
        return None;
    }
    if !jobs_seen {
        context.semantic(
            "github.jobs_required",
            "workflow must define `jobs`",
            root.span.clone(),
        );
    }

    if context.is_exhausted() {
        return None;
    }
    Some(GithubWorkflow {
        name,
        run_name,
        triggers: workflow_triggers,
        permissions: workflow_permissions,
        environment,
        defaults: workflow_defaults,
        concurrency: workflow_concurrency,
        jobs: workflow_jobs,
        extensions,
        span: root.span.clone(),
    })
}
