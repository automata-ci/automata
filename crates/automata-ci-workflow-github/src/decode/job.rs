use crate::{
    ActionStep, DetailedJobEnvironment, EnvironmentVariables, Job, JobEnvironment, JobId,
    JobOutputs, Needs, PreservedField, ReusableWorkflowCall, ReusableWorkflowInputs,
    ReusableWorkflowSecretMap, ReusableWorkflowSecrets, RunStep, RunnerSelection, SourceSpan,
    Spanned, Step, StepExecution, StepId, ValueMap, WorkflowJob, YamlNode,
};

use super::{
    DecodeContext,
    container::{job_container, job_services},
    field_name, sequence_text,
    strategy::strategy,
    valid_identifier,
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
        if context.is_exhausted() {
            break;
        }
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
        let Some(job_path) = context.child_path(path, &id.value, &entry.key.span) else {
            break;
        };
        if let Some(job) = job(&entry.value, &job_path, context) {
            jobs.push(WorkflowJob { id: JobId(id), job });
        }
    }
    if context.is_exhausted() {
        return Vec::new();
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

#[allow(clippy::too_many_lines)]
fn job(node: &YamlNode, path: &str, context: &mut DecodeContext<'_>) -> Option<Job> {
    let entries = context.expect_mapping(node, path)?;
    let mut name = None;
    let mut needs = None;
    let mut condition = None;
    let mut job_permissions = None;
    let mut job_concurrency = None;
    let mut job_strategy = None;
    let mut job_strategy_source_span = None;
    let mut environment = EnvironmentVariables::empty();
    let mut environment_seen = false;
    let mut outputs = None;
    let mut outputs_source_span = None;
    let mut deployment_environment = None;
    let mut deployment_environment_source_span = None;
    let mut job_defaults = None;
    let mut runner = None;
    let mut container = None;
    let mut container_source_span = None;
    let mut services = None;
    let mut services_source_span = None;
    let mut timeout_minutes = None;
    let mut continue_on_error = None;
    let mut steps = Vec::new();
    let mut steps_seen = false;
    let mut reusable_workflow_reference = None;
    let mut reusable_workflow_reference_seen = false;
    let mut reusable_workflow_inputs = None;
    let mut reusable_workflow_inputs_seen = false;
    let mut reusable_workflow_secrets = None;
    let mut reusable_workflow_secrets_seen = false;
    let mut reusable_workflow_inputs_span = None;
    let mut reusable_workflow_secrets_span = None;
    let mut step_job_fields = Vec::new();
    let mut extensions = Vec::new();

    for entry in entries {
        if context.is_exhausted() {
            break;
        }
        match field_name(entry) {
            Some("name") if name.is_none() => {
                let Some(field_path) = context.child_path(path, "name", &entry.key.span) else {
                    break;
                };
                name = context.text(&entry.value, &field_path);
            }
            Some("needs") if needs.is_none() => {
                let Some(field_path) = context.child_path(path, "needs", &entry.key.span) else {
                    break;
                };
                needs = parse_needs(&entry.value, &field_path, context);
            }
            Some("if") if condition.is_none() => {
                let Some(field_path) = context.child_path(path, "if", &entry.key.span) else {
                    break;
                };
                condition = context.text(&entry.value, &field_path);
            }
            Some("permissions") if job_permissions.is_none() => {
                let Some(field_path) = context.child_path(path, "permissions", &entry.key.span)
                else {
                    break;
                };
                job_permissions = permissions(&entry.value, &field_path, context);
            }
            Some("concurrency") if job_concurrency.is_none() => {
                let Some(field_path) = context.child_path(path, "concurrency", &entry.key.span)
                else {
                    break;
                };
                job_concurrency = concurrency(&entry.value, &field_path, context);
            }
            Some("strategy") if job_strategy_source_span.is_none() => {
                job_strategy_source_span = Some(entry.value.span.clone());
                let Some(field_path) = context.child_path(path, "strategy", &entry.key.span) else {
                    break;
                };
                job_strategy = strategy(&entry.value, &field_path, context);
            }
            Some("env") if !environment_seen => {
                step_job_fields.push(("env", entry.key.span.clone()));
                let Some(field_path) = context.child_path(path, "env", &entry.key.span) else {
                    break;
                };
                environment = value_map(&entry.value, &field_path, context);
                environment_seen = true;
            }
            Some("outputs") if outputs_source_span.is_none() => {
                step_job_fields.push(("outputs", entry.key.span.clone()));
                outputs_source_span = Some(entry.value.span.clone());
                let Some(field_path) = context.child_path(path, "outputs", &entry.key.span) else {
                    break;
                };
                outputs = job_outputs(&entry.value, &field_path, context);
            }
            Some("environment") if deployment_environment_source_span.is_none() => {
                step_job_fields.push(("environment", entry.key.span.clone()));
                deployment_environment_source_span = Some(entry.value.span.clone());
                let Some(field_path) = context.child_path(path, "environment", &entry.key.span)
                else {
                    break;
                };
                deployment_environment = job_environment(&entry.value, &field_path, context);
            }
            Some("defaults") if job_defaults.is_none() => {
                step_job_fields.push(("defaults", entry.key.span.clone()));
                let Some(field_path) = context.child_path(path, "defaults", &entry.key.span) else {
                    break;
                };
                job_defaults = defaults(&entry.value, &field_path, context);
            }
            Some("runs-on") if runner.is_none() => {
                step_job_fields.push(("runs-on", entry.key.span.clone()));
                let Some(field_path) = context.child_path(path, "runs-on", &entry.key.span) else {
                    break;
                };
                runner = runner_selection(&entry.value, &field_path, context);
            }
            Some("container") if container_source_span.is_none() => {
                step_job_fields.push(("container", entry.key.span.clone()));
                container_source_span = Some(entry.value.span.clone());
                let Some(field_path) = context.child_path(path, "container", &entry.key.span)
                else {
                    break;
                };
                container = job_container(&entry.value, &field_path, context);
            }
            Some("services") if services_source_span.is_none() => {
                step_job_fields.push(("services", entry.key.span.clone()));
                services_source_span = Some(entry.value.span.clone());
                let Some(field_path) = context.child_path(path, "services", &entry.key.span) else {
                    break;
                };
                services = job_services(&entry.value, &field_path, context);
            }
            Some("timeout-minutes") if timeout_minutes.is_none() => {
                step_job_fields.push(("timeout-minutes", entry.key.span.clone()));
                let Some(field_path) = context.child_path(path, "timeout-minutes", &entry.key.span)
                else {
                    break;
                };
                timeout_minutes = positive_integer(&entry.value, &field_path, context);
            }
            Some("continue-on-error") if continue_on_error.is_none() => {
                step_job_fields.push(("continue-on-error", entry.key.span.clone()));
                let Some(field_path) =
                    context.child_path(path, "continue-on-error", &entry.key.span)
                else {
                    break;
                };
                continue_on_error = boolean(&entry.value, &field_path, context);
            }
            Some("steps") if !steps_seen => {
                step_job_fields.push(("steps", entry.key.span.clone()));
                let Some(field_path) = context.child_path(path, "steps", &entry.key.span) else {
                    break;
                };
                steps = parse_steps(&entry.value, &field_path, context);
                steps_seen = true;
            }
            Some("uses") if !reusable_workflow_reference_seen => {
                let Some(field_path) = context.child_path(path, "uses", &entry.key.span) else {
                    break;
                };
                reusable_workflow_reference =
                    parse_reusable_workflow_reference(&entry.value, &field_path, context);
                reusable_workflow_reference_seen = true;
            }
            Some("with") if !reusable_workflow_inputs_seen => {
                let Some(field_path) = context.child_path(path, "with", &entry.key.span) else {
                    break;
                };
                reusable_workflow_inputs = Some(ReusableWorkflowInputs {
                    values: value_map(&entry.value, &field_path, context),
                    span: entry.value.span.clone(),
                });
                reusable_workflow_inputs_seen = true;
                reusable_workflow_inputs_span = Some(entry.key.span.clone());
            }
            Some("secrets") if !reusable_workflow_secrets_seen => {
                let Some(field_path) = context.child_path(path, "secrets", &entry.key.span) else {
                    break;
                };
                reusable_workflow_secrets =
                    parse_reusable_workflow_secrets(&entry.value, &field_path, context);
                reusable_workflow_secrets_seen = true;
                reusable_workflow_secrets_span = Some(entry.key.span.clone());
            }
            Some(
                "name" | "needs" | "if" | "permissions" | "concurrency" | "strategy" | "env"
                | "defaults" | "outputs" | "environment" | "runs-on" | "timeout-minutes"
                | "container" | "services" | "continue-on-error" | "steps" | "uses" | "with"
                | "secrets",
            ) => {}
            _ => {
                if let Some(extension) = context.preserve_unknown(path, entry) {
                    extensions.push(extension);
                }
            }
        }
    }

    if context.is_exhausted() {
        return None;
    }

    validate_job_execution_fields(
        reusable_workflow_reference_seen,
        reusable_workflow_inputs_span.as_ref(),
        reusable_workflow_secrets_span.as_ref(),
        &step_job_fields,
        runner.is_some(),
        steps_seen,
        path,
        node,
        context,
    );
    if context.is_exhausted() {
        return None;
    }

    let reusable_workflow_call = (reusable_workflow_reference_seen
        || reusable_workflow_inputs_seen
        || reusable_workflow_secrets_seen)
        .then(|| ReusableWorkflowCall {
            reference: reusable_workflow_reference,
            inputs: reusable_workflow_inputs,
            secrets: reusable_workflow_secrets,
            span: node.span.clone(),
        });

    Some(Job {
        name,
        needs,
        condition,
        permissions: job_permissions,
        concurrency: job_concurrency,
        strategy: job_strategy,
        strategy_source_span: job_strategy_source_span,
        environment,
        outputs,
        outputs_source_span,
        deployment_environment,
        deployment_environment_source_span,
        defaults: job_defaults,
        runner,
        container,
        container_source_span,
        services,
        services_source_span,
        timeout_minutes,
        continue_on_error,
        steps,
        reusable_workflow_call,
        extensions,
        span: node.span.clone(),
    })
}

fn parse_reusable_workflow_reference(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<Spanned<String>> {
    let scalar = context.scalar(node, path)?;
    if scalar.is_null() || scalar.decoded.trim().is_empty() {
        context.semantic(
            "github.reusable_workflow_reference_required",
            format!("`{path}` must name a reusable workflow"),
            node.span.clone(),
        );
        return None;
    }
    Some(Spanned::new(scalar.decoded.clone(), node.span.clone()))
}

#[allow(clippy::too_many_arguments)]
fn validate_job_execution_fields(
    has_reusable_workflow_reference: bool,
    reusable_workflow_inputs_span: Option<&SourceSpan>,
    reusable_workflow_secrets_span: Option<&SourceSpan>,
    step_job_fields: &[(&str, SourceSpan)],
    has_runner: bool,
    has_steps: bool,
    path: &str,
    node: &YamlNode,
    context: &mut DecodeContext<'_>,
) {
    if context.is_exhausted() {
        return;
    }
    if has_reusable_workflow_reference {
        for (field, span) in step_job_fields {
            if context.is_exhausted() {
                break;
            }
            context.semantic(
                "github.step_job_field_on_reusable_workflow_call",
                format!(
                    "`{path}.{field}` is only valid on a step-based job and cannot be combined with `{path}.uses`"
                ),
                span.clone(),
            );
        }
        return;
    }

    if let Some(span) = reusable_workflow_inputs_span {
        context.semantic(
            "github.reusable_workflow_with_requires_uses",
            format!("`{path}.with` requires `{path}.uses` to call a reusable workflow"),
            span.clone(),
        );
    }
    if context.is_exhausted() {
        return;
    }
    if let Some(span) = reusable_workflow_secrets_span {
        context.semantic(
            "github.reusable_workflow_secrets_requires_uses",
            format!("`{path}.secrets` requires `{path}.uses` to call a reusable workflow"),
            span.clone(),
        );
    }
    if context.is_exhausted() {
        return;
    }
    if !has_runner {
        context.semantic(
            "github.runner_required",
            format!("`{path}.runs-on` is required for a step-based job"),
            node.span.clone(),
        );
    }
    if context.is_exhausted() {
        return;
    }
    if !has_steps {
        context.semantic(
            "github.steps_required",
            format!("`{path}.steps` is required for a step-based job"),
            node.span.clone(),
        );
    }
}

fn parse_reusable_workflow_secrets(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<ReusableWorkflowSecrets> {
    if let Some(scalar) = node.as_scalar() {
        if scalar.decoded == "inherit" {
            return Some(ReusableWorkflowSecrets::Inherit(node.span.clone()));
        }
        context.semantic(
            "github.invalid_reusable_workflow_secrets",
            format!("`{path}` must be `inherit` or a mapping of secret names to values"),
            node.span.clone(),
        );
        return None;
    }
    if node.as_mapping().is_some() {
        return Some(ReusableWorkflowSecrets::Mapping(
            ReusableWorkflowSecretMap {
                values: value_map(node, path, context),
                span: node.span.clone(),
            },
        ));
    }
    context.semantic(
        "github.invalid_reusable_workflow_secrets",
        format!("`{path}` must be `inherit` or a mapping of secret names to values"),
        node.span.clone(),
    );
    None
}

fn job_outputs(node: &YamlNode, path: &str, context: &mut DecodeContext<'_>) -> Option<JobOutputs> {
    context.expect_mapping(node, path)?;
    Some(JobOutputs {
        values: value_map(node, path, context),
        span: node.span.clone(),
    })
}

fn job_environment(
    node: &YamlNode,
    path: &str,
    context: &mut DecodeContext<'_>,
) -> Option<JobEnvironment> {
    if node.as_scalar().is_some() {
        return context.text(node, path).map(JobEnvironment::Name);
    }

    let Some(entries) = node.as_mapping() else {
        context.semantic(
            "github.expected_job_environment",
            format!("`{path}` must be a scalar name or a mapping with a `name` field"),
            node.span.clone(),
        );
        return None;
    };
    let mut name = None;
    let mut name_seen = false;
    let mut url = None;
    let mut url_seen = false;
    let mut extensions = Vec::new();
    for entry in entries {
        if context.is_exhausted() {
            break;
        }
        match field_name(entry) {
            Some("name") if !name_seen => {
                let Some(field_path) = context.child_path(path, "name", &entry.key.span) else {
                    break;
                };
                name = context.text(&entry.value, &field_path);
                name_seen = true;
            }
            Some("url") if !url_seen => {
                let Some(field_path) = context.child_path(path, "url", &entry.key.span) else {
                    break;
                };
                url = context.text(&entry.value, &field_path);
                url_seen = true;
            }
            Some("name" | "url") => {}
            _ => {
                if let Some(extension) = context.preserve_unknown(path, entry) {
                    extensions.push(extension);
                }
            }
        }
    }
    if context.is_exhausted() {
        return None;
    }
    if !name_seen {
        context.semantic(
            "github.job_environment_name_required",
            format!("`{path}.name` is required in the mapping form"),
            node.span.clone(),
        );
    }
    Some(JobEnvironment::Detailed(DetailedJobEnvironment {
        name,
        url,
        extensions,
        span: node.span.clone(),
    }))
}

fn parse_needs(node: &YamlNode, path: &str, context: &mut DecodeContext<'_>) -> Option<Needs> {
    if node.as_scalar().is_some() {
        return context.text(node, path).map(Needs::One);
    }
    let values = sequence_text(node, path, context);
    if context.is_exhausted() {
        return None;
    }
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
        if context.is_exhausted() {
            return None;
        }
        if labels.is_empty() {
            context.semantic(
                "github.empty_runner_labels",
                format!("`{path}` must contain at least one runner label"),
                node.span.clone(),
            );
        }
        return Some(RunnerSelection::Labels {
            labels,
            span: node.span.clone(),
        });
    }

    let entries = context.expect_mapping(node, path)?;
    let mut group = None;
    let mut labels = Vec::new();
    let mut labels_seen = false;
    let mut extensions: Vec<PreservedField> = Vec::new();
    for entry in entries {
        if context.is_exhausted() {
            break;
        }
        match field_name(entry) {
            Some("group") if group.is_none() => {
                let Some(field_path) = context.child_path(path, "group", &entry.key.span) else {
                    break;
                };
                group = context.text(&entry.value, &field_path);
            }
            Some("labels") if !labels_seen => {
                let Some(field_path) = context.child_path(path, "labels", &entry.key.span) else {
                    break;
                };
                labels = if entry.value.as_scalar().is_some() {
                    context
                        .text(&entry.value, &field_path)
                        .into_iter()
                        .collect()
                } else {
                    sequence_text(&entry.value, &field_path, context)
                };
                labels_seen = true;
            }
            Some("group" | "labels") => {}
            _ => {
                if let Some(extension) = context.preserve_unknown(path, entry) {
                    extensions.push(extension);
                }
            }
        }
    }
    if context.is_exhausted() {
        return None;
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
    let mut steps = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        if context.is_exhausted() {
            break;
        }
        let Some(item_path) = context.indexed_path(path, index, &item.span) else {
            break;
        };
        if let Some(step) = step(item, &item_path, context) {
            steps.push(step);
        }
    }
    if context.is_exhausted() {
        return Vec::new();
    }
    steps
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
        if context.is_exhausted() {
            break;
        }
        match field_name(entry) {
            Some("id") if id.is_none() => {
                let Some(field_path) = context.child_path(path, "id", &entry.key.span) else {
                    break;
                };
                let parsed = context.text(&entry.value, &field_path);
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
                let Some(field_path) = context.child_path(path, "name", &entry.key.span) else {
                    break;
                };
                name = context.text(&entry.value, &field_path);
            }
            Some("if") if condition.is_none() => {
                let Some(field_path) = context.child_path(path, "if", &entry.key.span) else {
                    break;
                };
                condition = context.text(&entry.value, &field_path);
            }
            Some("run") if run.is_none() => {
                let Some(field_path) = context.child_path(path, "run", &entry.key.span) else {
                    break;
                };
                run = context.text(&entry.value, &field_path);
            }
            Some("uses") if uses.is_none() => {
                let Some(field_path) = context.child_path(path, "uses", &entry.key.span) else {
                    break;
                };
                uses = context.text(&entry.value, &field_path);
            }
            Some("with") if !inputs_seen => {
                let Some(field_path) = context.child_path(path, "with", &entry.key.span) else {
                    break;
                };
                inputs = value_map(&entry.value, &field_path, context);
                inputs_seen = true;
            }
            Some("shell") if shell.is_none() => {
                let Some(field_path) = context.child_path(path, "shell", &entry.key.span) else {
                    break;
                };
                shell = context.text(&entry.value, &field_path);
            }
            Some("working-directory") if working_directory.is_none() => {
                let Some(field_path) =
                    context.child_path(path, "working-directory", &entry.key.span)
                else {
                    break;
                };
                working_directory = context.text(&entry.value, &field_path);
            }
            Some("env") if !environment_seen => {
                let Some(field_path) = context.child_path(path, "env", &entry.key.span) else {
                    break;
                };
                environment = value_map(&entry.value, &field_path, context);
                environment_seen = true;
            }
            Some("continue-on-error") if continue_on_error.is_none() => {
                let Some(field_path) =
                    context.child_path(path, "continue-on-error", &entry.key.span)
                else {
                    break;
                };
                continue_on_error = boolean(&entry.value, &field_path, context);
            }
            Some("timeout-minutes") if timeout_minutes.is_none() => {
                let Some(field_path) = context.child_path(path, "timeout-minutes", &entry.key.span)
                else {
                    break;
                };
                timeout_minutes = positive_integer(&entry.value, &field_path, context);
            }
            Some(
                "id" | "name" | "if" | "run" | "uses" | "with" | "shell" | "working-directory"
                | "env" | "continue-on-error" | "timeout-minutes",
            ) => {}
            _ => {
                if let Some(extension) = context.preserve_unknown(path, entry) {
                    extensions.push(extension);
                }
            }
        }
    }

    if context.is_exhausted() {
        return None;
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

    if context.is_exhausted() {
        return None;
    }

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
