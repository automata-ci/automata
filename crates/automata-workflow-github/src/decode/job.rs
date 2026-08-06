use crate::{
    ActionStep, EnvironmentVariables, Job, JobId, Needs, PreservedField, RunStep, RunnerSelection,
    Spanned, Step, StepExecution, StepId, ValueMap, WorkflowJob, YamlNode,
};

use super::{
    DecodeContext, field_name, sequence_text, valid_identifier,
    value::{boolean, concurrency, defaults, permissions, positive_integer, value_map},
};

pub(super) fn jobs(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Vec<WorkflowJob> {
    let Some(entries) = context.expect_mapping(node, path) else {
        return Vec::new();
    };
    let mut jobs = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some(id_scalar) = entry.key.as_scalar() else {
            continue;
        };
        let id = Spanned::new(id_scalar.decoded.clone(), entry.key.span.clone());
        if !valid_identifier(&id.value) {
            context.semantic(
                "github.invalid_job_id",
                format!(
                    "job id `{}` must start with a letter or `_` and contain only letters, digits, `-`, or `_`",
                    id.value
                ),
                id.span.clone(),
            );
        }
        let job_path = format!("{path}.{}", id.value);
        if let Some(job) = job(&entry.value, &job_path, context) {
            jobs.push(WorkflowJob { id: JobId(id), job });
        }
    }
    if jobs.is_empty() {
        context.semantic(
            "github.empty_jobs",
            "workflow must contain at least one job",
            node.span.clone(),
        );
    }
    jobs
}

fn job(node: &YamlNode, path: &str, context: &mut DecodeContext<'_>) -> Option<Job> {
    let entries = context.expect_mapping(node, path)?;
    let mut name = None;
    let mut needs = None;
    let mut condition = None;
    let mut job_permissions = None;
    let mut job_concurrency = None;
    let mut environment = EnvironmentVariables::empty();
    let mut environment_seen = false;
    let mut job_defaults = None;
    let mut runner = None;
    let mut timeout_minutes = None;
    let mut continue_on_error = None;
    let mut steps = Vec::new();
    let mut steps_seen = false;
    let mut extensions = Vec::new();

    for entry in entries {
        match field_name(entry) {
            Some("name") if name.is_none() => {
                name = context.text(&entry.value, &format!("{path}.name"));
            }
            Some("needs") if needs.is_none() => {
                needs = parse_needs(&entry.value, &format!("{path}.needs"), context);
            }
            Some("if") if condition.is_none() => {
                condition = context.text(&entry.value, &format!("{path}.if"));
            }
            Some("permissions") if job_permissions.is_none() => {
                job_permissions =
                    permissions(&entry.value, &format!("{path}.permissions"), context);
            }
            Some("concurrency") if job_concurrency.is_none() => {
                job_concurrency =
                    concurrency(&entry.value, &format!("{path}.concurrency"), context);
            }
            Some("env") if !environment_seen => {
                environment = value_map(&entry.value, &format!("{path}.env"), context);
                environment_seen = true;
            }
            Some("defaults") if job_defaults.is_none() => {
                job_defaults = defaults(&entry.value, &format!("{path}.defaults"), context);
            }
            Some("runs-on") if runner.is_none() => {
                runner = runner_selection(&entry.value, &format!("{path}.runs-on"), context);
            }
            Some("timeout-minutes") if timeout_minutes.is_none() => {
                timeout_minutes =
                    positive_integer(&entry.value, &format!("{path}.timeout-minutes"), context);
            }
            Some("continue-on-error") if continue_on_error.is_none() => {
                continue_on_error =
                    boolean(&entry.value, &format!("{path}.continue-on-error"), context);
            }
            Some("steps") if !steps_seen => {
                steps = parse_steps(&entry.value, &format!("{path}.steps"), context);
                steps_seen = true;
            }
            Some(
                "name" | "needs" | "if" | "permissions" | "concurrency" | "env" | "defaults"
                | "runs-on" | "timeout-minutes" | "continue-on-error" | "steps",
            ) => {}
            _ => extensions.push(context.preserve_unknown(path, entry)),
        }
    }

    if runner.is_none() {
        context.semantic(
            "github.runner_required",
            format!("`{path}.runs-on` is required for a step-based job"),
            node.span.clone(),
        );
    }
    if !steps_seen {
        context.semantic(
            "github.steps_required",
            format!("`{path}.steps` is required for a step-based job"),
            node.span.clone(),
        );
    }

    Some(Job {
        name,
        needs,
        condition,
        permissions: job_permissions,
        concurrency: job_concurrency,
        environment,
        defaults: job_defaults,
        runner,
        timeout_minutes,
        continue_on_error,
        steps,
        extensions,
        span: node.span.clone(),
    })
}

fn parse_needs(node: &YamlNode, path: &str, context: &mut DecodeContext<'_>) -> Option<Needs> {
    if node.as_scalar().is_some() {
        return context.text(node, path).map(Needs::One);
    }
    let values = sequence_text(node, path, context);
    if values.is_empty() {
        context.semantic(
            "github.empty_needs",
            format!("`{path}` must contain at least one job id"),
            node.span.clone(),
        );
    }
    Some(Needs::Many(values))
}

fn runner_selection(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<RunnerSelection> {
    if node.as_scalar().is_some() {
        return context.text(node, path).map(RunnerSelection::Label);
    }
    if node.as_sequence().is_some() {
        let labels = sequence_text(node, path, context);
        if labels.is_empty() {
            context.semantic(
                "github.empty_runner_labels",
                format!("`{path}` must contain at least one runner label"),
                node.span.clone(),
            );
        }
        return Some(RunnerSelection::Labels(labels));
    }

    let entries = context.expect_mapping(node, path)?;
    let mut group = None;
    let mut labels = Vec::new();
    let mut labels_seen = false;
    let mut extensions: Vec<PreservedField> = Vec::new();
    for entry in entries {
        match field_name(entry) {
            Some("group") if group.is_none() => {
                group = context.text(&entry.value, &format!("{path}.group"));
            }
            Some("labels") if !labels_seen => {
                labels = if entry.value.as_scalar().is_some() {
                    context
                        .text(&entry.value, &format!("{path}.labels"))
                        .into_iter()
                        .collect()
                } else {
                    sequence_text(&entry.value, &format!("{path}.labels"), context)
                };
                labels_seen = true;
            }
            Some("group" | "labels") => {}
            _ => extensions.push(context.preserve_unknown(path, entry)),
        }
    }
    let Some(group) = group else {
        context.semantic(
            "github.runner_group_required",
            format!("`{path}.group` is required in the mapping form"),
            node.span.clone(),
        );
        return None;
    };
    Some(RunnerSelection::Group {
        group,
        labels,
        extensions,
        span: node.span.clone(),
    })
}

fn parse_steps(node: &YamlNode, path: &str, context: &mut DecodeContext<'_>) -> Vec<Step> {
    let Some(items) = node.as_sequence() else {
        context.semantic(
            "github.expected_sequence",
            format!("`{path}` must be a sequence"),
            node.span.clone(),
        );
        return Vec::new();
    };
    items
        .iter()
        .enumerate()
        .filter_map(|(index, item)| step(item, &format!("{path}[{index}]"), context))
        .collect()
}

#[allow(clippy::too_many_lines)]
fn step(node: &YamlNode, path: &str, context: &mut DecodeContext<'_>) -> Option<Step> {
    let entries = context.expect_mapping(node, path)?;
    let mut id = None;
    let mut name = None;
    let mut condition = None;
    let mut run = None;
    let mut uses = None;
    let mut inputs = ValueMap::empty();
    let mut inputs_seen = false;
    let mut shell = None;
    let mut working_directory = None;
    let mut environment = EnvironmentVariables::empty();
    let mut environment_seen = false;
    let mut continue_on_error = None;
    let mut timeout_minutes = None;
    let mut extensions = Vec::new();

    for entry in entries {
        match field_name(entry) {
            Some("id") if id.is_none() => {
                let parsed = context.text(&entry.value, &format!("{path}.id"));
                if let Some(parsed) = parsed {
                    if !valid_identifier(&parsed.value) {
                        context.semantic(
                            "github.invalid_step_id",
                            format!("step id `{}` is not a valid identifier", parsed.value),
                            parsed.span.clone(),
                        );
                    }
                    id = Some(StepId(parsed));
                }
            }
            Some("name") if name.is_none() => {
                name = context.text(&entry.value, &format!("{path}.name"));
            }
            Some("if") if condition.is_none() => {
                condition = context.text(&entry.value, &format!("{path}.if"));
            }
            Some("run") if run.is_none() => {
                run = context.text(&entry.value, &format!("{path}.run"));
            }
            Some("uses") if uses.is_none() => {
                uses = context.text(&entry.value, &format!("{path}.uses"));
            }
            Some("with") if !inputs_seen => {
                inputs = value_map(&entry.value, &format!("{path}.with"), context);
                inputs_seen = true;
            }
            Some("shell") if shell.is_none() => {
                shell = context.text(&entry.value, &format!("{path}.shell"));
            }
            Some("working-directory") if working_directory.is_none() => {
                working_directory =
                    context.text(&entry.value, &format!("{path}.working-directory"));
            }
            Some("env") if !environment_seen => {
                environment = value_map(&entry.value, &format!("{path}.env"), context);
                environment_seen = true;
            }
            Some("continue-on-error") if continue_on_error.is_none() => {
                continue_on_error =
                    boolean(&entry.value, &format!("{path}.continue-on-error"), context);
            }
            Some("timeout-minutes") if timeout_minutes.is_none() => {
                timeout_minutes =
                    positive_integer(&entry.value, &format!("{path}.timeout-minutes"), context);
            }
            Some(
                "id" | "name" | "if" | "run" | "uses" | "with" | "shell" | "working-directory"
                | "env" | "continue-on-error" | "timeout-minutes",
            ) => {}
            _ => extensions.push(context.preserve_unknown(path, entry)),
        }
    }

    let execution = match (run, uses) {
        (Some(script), None) => {
            if inputs_seen {
                context.semantic(
                    "github.with_on_run_step",
                    "`with` is only valid on an action step",
                    node.span.clone(),
                );
            }
            Some(StepExecution::Run(RunStep {
                script,
                shell,
                working_directory,
            }))
        }
        (None, Some(reference)) => {
            if shell.is_some() || working_directory.is_some() {
                context.semantic(
                    "github.run_options_on_action_step",
                    "`shell` and `working-directory` are only valid on a run step",
                    node.span.clone(),
                );
            }
            Some(StepExecution::Action(ActionStep { reference, inputs }))
        }
        (Some(_), Some(_)) => {
            context.semantic(
                "github.multiple_step_executions",
                "a step cannot contain both `run` and `uses`",
                node.span.clone(),
            );
            None
        }
        (None, None) => {
            context.semantic(
                "github.step_execution_required",
                "a step must contain exactly one of `run` or `uses`",
                node.span.clone(),
            );
            None
        }
    };

    Some(Step {
        id,
        name,
        condition,
        execution,
        environment,
        continue_on_error,
        timeout_minutes,
        extensions,
        span: node.span.clone(),
    })
}
