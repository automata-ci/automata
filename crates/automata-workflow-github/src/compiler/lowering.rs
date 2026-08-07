//! Semantic lowering of typed GitHub source nodes.

use automata_core::{
    ConcurrencyPlan, DeferredBoolean, EnvironmentPlan, Located, PermissionGrant, PlanValue,
    PlannedJob, PlannedStep, PlannedStepKind, QueuePolicy, RunDefaultsPlan, RunStepPlan,
    RunnerProfile, UsesStepPlan, WorkflowJobKey, WorkflowPermissions, WorkflowStepKey,
};

use crate::{
    BooleanValue, Concurrency, ConcurrencyQueue, Defaults, Needs, PermissionLevel, Permissions,
    RunnerSelection, ScalarValue, SourceSpan, Spanned, Step, StepExecution, ValueMap, WorkflowJob,
};

use super::{
    CompileContext,
    expression::{compile_condition, compile_expression, compile_value},
};

pub(super) fn compile_job(
    job: &WorkflowJob,
    context: &mut CompileContext<'_>,
) -> Option<PlannedJob> {
    let source_job = job.job();
    context.reject_extensions(source_job.extensions());
    let key = match WorkflowJobKey::new(job.id().as_str()) {
        Ok(key) => context.located(key, job.id().span())?,
        Err(error) => {
            context.semantic(
                "github.compile.invalid_job_key",
                error.to_string(),
                job.id().span().clone(),
            );
            return None;
        }
    };
    let name = source_job
        .name()
        .and_then(|value| located_text(value, context));
    let needs = compile_needs(source_job.needs(), context);
    let condition = source_job
        .condition()
        .and_then(|value| compile_condition(value, context));
    let permissions = source_job
        .permissions()
        .and_then(|value| compile_permissions(value, context));
    let concurrency = source_job
        .concurrency()
        .and_then(|value| compile_concurrency(value, context));
    let environment = compile_value_map(source_job.environment(), context);
    let run_defaults = compile_defaults(source_job.defaults(), context);
    let runner = source_job
        .runner()
        .and_then(|value| compile_runner(value, context))?;
    let timeout_seconds = compile_timeout(source_job.timeout_minutes(), source_job.span(), context);
    let continue_on_error = source_job
        .continue_on_error()
        .and_then(|value| compile_boolean(value, context));
    let steps = source_job
        .steps()
        .iter()
        .enumerate()
        .filter_map(|(index, step)| compile_step(index, step, context))
        .collect();
    let span = context.span(source_job.span())?;
    PlannedJob::builder(key, runner, steps, span)
        .name(name)
        .needs(needs)
        .condition(condition)
        .permissions(permissions)
        .concurrency(concurrency)
        .environment(environment)
        .run_defaults(run_defaults)
        .timeout_seconds(timeout_seconds)
        .continue_on_error(continue_on_error)
        .build()
        .map_err(|error| {
            context.semantic(
                "github.compile.invalid_job",
                error.to_string(),
                source_job.span().clone(),
            );
        })
        .ok()
}

pub(super) fn compile_needs(
    needs: Option<&Needs>,
    context: &mut CompileContext<'_>,
) -> Vec<Located<WorkflowJobKey>> {
    let values: &[Spanned<String>] = match needs {
        None => return Vec::new(),
        Some(Needs::One(value)) => std::slice::from_ref(value),
        Some(Needs::Many(values)) => values,
    };
    values
        .iter()
        .filter_map(|value| match WorkflowJobKey::new(value.value()) {
            Ok(key) => context.located(key, value.span()),
            Err(error) => {
                context.semantic(
                    "github.compile.invalid_dependency_key",
                    error.to_string(),
                    value.span().clone(),
                );
                None
            }
        })
        .collect()
}

pub(super) fn compile_runner(
    runner: &RunnerSelection,
    context: &mut CompileContext<'_>,
) -> Option<RunnerProfile> {
    let (group, labels, span) = match runner {
        RunnerSelection::Label(label) => (
            None,
            vec![located_spanned_value(label, context)?],
            label.span(),
        ),
        RunnerSelection::Labels { labels, span } => {
            labels.first()?;
            let labels = labels
                .iter()
                .filter_map(|label| located_spanned_value(label, context))
                .collect();
            (None, labels, span)
        }
        RunnerSelection::Group {
            group,
            labels,
            extensions,
            span,
        } => {
            context.reject_extensions(extensions);
            let group = located_spanned_value(group, context);
            let labels = labels
                .iter()
                .filter_map(|label| located_spanned_value(label, context))
                .collect();
            (group, labels, span)
        }
    };
    Some(RunnerProfile::new(group, labels, context.span(span)?))
}

pub(super) fn compile_step(
    index: usize,
    step: &Step,
    context: &mut CompileContext<'_>,
) -> Option<PlannedStep> {
    context.reject_extensions(step.extensions());
    let id = step
        .id()
        .and_then(|id| context.located(id.as_str().to_owned(), id.span()));
    let key_source = step.id().map_or_else(
        || format!("position/{index:08}"),
        |id| format!("id/{}", id.as_str()),
    );
    let key = match WorkflowStepKey::new(key_source) {
        Ok(key) => key,
        Err(error) => {
            context.semantic(
                "github.compile.invalid_step_key",
                error.to_string(),
                step.span().clone(),
            );
            return None;
        }
    };
    let name = step.name().and_then(|value| located_text(value, context));
    let condition = step
        .condition()
        .and_then(|value| compile_condition(value, context));
    let environment = compile_value_map(step.environment(), context);
    let continue_on_error = step
        .continue_on_error()
        .and_then(|value| compile_boolean(value, context));
    let timeout_seconds = compile_timeout(step.timeout_minutes(), step.span(), context);
    let execution = match step.execution() {
        Some(StepExecution::Run(run)) => {
            let script = located_spanned_value(run.script(), context)?;
            let shell = run
                .shell()
                .and_then(|value| located_spanned_value(value, context));
            let working_directory = run
                .working_directory()
                .and_then(|value| located_spanned_value(value, context));
            PlannedStepKind::Run(Box::new(RunStepPlan::new(script, shell, working_directory)))
        }
        Some(StepExecution::Action(action)) => {
            let reference = located_text(action.reference(), context)?;
            let inputs = compile_value_map(action.inputs(), context);
            PlannedStepKind::Uses(UsesStepPlan::new(reference, inputs))
        }
        None => {
            context.semantic(
                "github.compile.missing_step_execution",
                "step has no valid run or uses execution",
                step.span().clone(),
            );
            return None;
        }
    };
    let span = context.span(step.span())?;
    PlannedStep::builder(key, execution, span)
        .id(id)
        .name(name)
        .condition(condition)
        .environment(environment)
        .continue_on_error(continue_on_error)
        .timeout_seconds(timeout_seconds)
        .build()
        .map_err(|error| {
            context.semantic(
                "github.compile.invalid_step",
                error.to_string(),
                step.span().clone(),
            );
        })
        .ok()
}

pub(super) fn compile_timeout(
    timeout: Option<&ScalarValue>,
    owner_span: &SourceSpan,
    context: &mut CompileContext<'_>,
) -> Option<u32> {
    let timeout = timeout?;
    if timeout.contains_expression_candidate() {
        context.unsupported(
            "github.compile.dynamic_timeout",
            "expression-valued timeouts require runtime job expansion and are not in workflow-plan v1",
            timeout.span().clone(),
        );
        return None;
    }
    let normalized = timeout.decoded().replace('_', "");
    let Ok(minutes) = normalized.parse::<u32>() else {
        context.semantic(
            "github.compile.invalid_timeout",
            "timeout-minutes does not fit a 32-bit minute count",
            timeout.span().clone(),
        );
        return None;
    };
    match minutes.checked_mul(60) {
        Some(seconds) if seconds > 0 => Some(seconds),
        _ => {
            context.semantic(
                "github.compile.timeout_overflow",
                "timeout-minutes overflows the workflow-plan seconds representation",
                owner_span.clone(),
            );
            None
        }
    }
}

pub(super) fn compile_defaults(
    defaults: Option<&Defaults>,
    context: &mut CompileContext<'_>,
) -> RunDefaultsPlan {
    let Some(defaults) = defaults else {
        return RunDefaultsPlan::default();
    };
    context.reject_extensions(defaults.extensions());
    let Some(run) = defaults.run() else {
        return RunDefaultsPlan::default();
    };
    context.reject_extensions(run.extensions());
    RunDefaultsPlan::new(
        run.shell()
            .and_then(|value| located_spanned_value(value, context)),
        run.working_directory()
            .and_then(|value| located_spanned_value(value, context)),
    )
}

pub(super) fn compile_permissions(
    permissions: &Permissions,
    context: &mut CompileContext<'_>,
) -> Option<WorkflowPermissions> {
    match permissions {
        Permissions::ReadAll(span) => context.span(span).map(WorkflowPermissions::ReadAll),
        Permissions::WriteAll(span) => context.span(span).map(WorkflowPermissions::WriteAll),
        Permissions::Mapping { entries, .. } => {
            let grants = entries
                .iter()
                .filter_map(|entry| {
                    let name = located_text(entry.name(), context)?;
                    let level = match entry.level().value() {
                        PermissionLevel::Read => automata_core::PermissionLevel::Read,
                        PermissionLevel::Write => automata_core::PermissionLevel::Write,
                        PermissionLevel::None => automata_core::PermissionLevel::None,
                    };
                    let level = context.located(level, entry.level().span())?;
                    Some(PermissionGrant::new(name, level))
                })
                .collect();
            Some(WorkflowPermissions::Mapping(grants))
        }
    }
}

pub(super) fn compile_concurrency(
    concurrency: &Concurrency,
    context: &mut CompileContext<'_>,
) -> Option<ConcurrencyPlan> {
    match concurrency {
        Concurrency::Group(source_group) => {
            let expression =
                compile_expression(source_group.value(), source_group.span(), context)?;
            let group = context.located(expression, source_group.span())?;
            let span = context.span(source_group.span())?;
            Some(ConcurrencyPlan::new(group, None, QueuePolicy::Single, span))
        }
        Concurrency::Detailed(details) => {
            context.reject_extensions(details.extensions());
            let expression =
                compile_expression(details.group().value(), details.group().span(), context)?;
            let group = context.located(expression, details.group().span())?;
            let cancel = details
                .cancel_in_progress()
                .and_then(|value| compile_boolean(value, context));
            let queue = details
                .queue()
                .map_or(QueuePolicy::Single, |queue| match queue.value() {
                    ConcurrencyQueue::Single => QueuePolicy::Single,
                    ConcurrencyQueue::Max => QueuePolicy::Max,
                });
            let span = context.span(details.span())?;
            Some(ConcurrencyPlan::new(group, cancel, queue, span))
        }
    }
}

pub(super) fn compile_boolean(
    value: &BooleanValue,
    context: &mut CompileContext<'_>,
) -> Option<Located<DeferredBoolean>> {
    match value {
        BooleanValue::Literal(value) => {
            context.located(DeferredBoolean::Literal(*value.value()), value.span())
        }
        BooleanValue::Expression(value) => {
            let expression = compile_expression(value.value(), value.span(), context)?;
            context.located(DeferredBoolean::Expression(expression), value.span())
        }
    }
}

pub(super) fn compile_value_map(
    map: &ValueMap,
    context: &mut CompileContext<'_>,
) -> EnvironmentPlan {
    let entries = map
        .entries()
        .iter()
        .filter_map(|entry| {
            let key = located_text(entry.key(), context)?;
            let value = compile_scalar_value(entry.value(), context)?;
            Some((key, value))
        })
        .collect();
    EnvironmentPlan::new(entries)
}

pub(super) fn compile_scalar_value(
    value: &ScalarValue,
    context: &mut CompileContext<'_>,
) -> Option<Located<PlanValue>> {
    let compiled = compile_value(value.decoded(), value.span(), context)?;
    context.located(compiled, value.span())
}

pub(super) fn located_text(
    value: &Spanned<String>,
    context: &mut CompileContext<'_>,
) -> Option<Located<String>> {
    context.located(value.value().clone(), value.span())
}

pub(super) fn located_spanned_value(
    value: &Spanned<String>,
    context: &mut CompileContext<'_>,
) -> Option<Located<PlanValue>> {
    let compiled = compile_value(value.value(), value.span(), context)?;
    context.located(compiled, value.span())
}
