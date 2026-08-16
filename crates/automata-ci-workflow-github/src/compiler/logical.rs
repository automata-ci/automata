//! Explicit logical-workflow lowering into durable logical job templates.

use std::collections::{BTreeMap, BTreeSet};

use automata_ci_core::{
    CompiledBooleanTemplate, CompiledPositiveIntegerTemplate, CompiledValueTemplate, ContainerPort,
    DeploymentSelection, ExpressionContext, InvocationInputDefault, InvocationInputDefinition,
    InvocationInputType, InvocationSecretDefinition, Located, LogicalConcurrencyTemplate,
    LogicalJobKind, LogicalJobOutputDefinition, LogicalJobOutputSource,
    LogicalJobResourcesTemplate, LogicalJobTemplate, LogicalJobTemplateBuilder,
    LogicalOutputMergePolicy, LogicalResourceVectorTemplate, LogicalResultReference,
    LogicalResultValue, LogicalRunDefaultsTemplate, LogicalRunStepTemplate, LogicalRunnerTemplate,
    LogicalServiceContainerTemplate, LogicalStepKind, LogicalStepTemplate, LogicalTimeoutTemplate,
    LogicalUsesStepTemplate, MAX_MATRIX_EXPANSION, MatrixAxis, MatrixAxisValues, MatrixPatch,
    MatrixPatchSet, MatrixTemplate, MatrixValue as PlanMatrixValue, MatrixValueTemplate,
    OutputSensitivity, PermissionSnapshotRequest, PlanEvaluationPhase, PlanSourceSpan, QueuePolicy,
    ReusableInputBinding, ReusableSecretBinding, ReusableSecretForwarding,
    ReusableWorkflowInvocation, StepJobTemplate, TemplateValueMap, TransportProtocol,
    WorkflowInputKey, WorkflowInvocationContract, WorkflowJobKey, WorkflowOutputDefinition,
    WorkflowOutputKey, WorkflowSecretKey, WorkflowServiceKey, WorkflowStepKey,
    WorkflowStrategyTemplate, parse_cpu_quantity, parse_storage_quantity,
};

use crate::{
    BooleanValue, CompilationDisposition, CompilationReport, CompileWorkflowRequest, Concurrency,
    ConcurrencyQueue, Defaults, GithubConditionPhase, JobContainer, JobResourceVector,
    JobResources, JobService, JobStrategy, MatrixConfiguration, MatrixConfigurations,
    MatrixDimensionValues, MatrixValue, Permissions, ReusableWorkflowCall, ReusableWorkflowSecrets,
    RunnerSelection, ScalarResolution, ScalarValue, SourceSpan, Spanned, Step, StepExecution,
    StrategyMatrix, TriggerConfiguration, ValueMap, WorkflowJob, YamlMappingEntry, YamlNode,
};

use super::{
    CompileContext, CompiledEvent, compile_event, compile_source,
    expression::{
        Analyzed, ParsedNeedReference, ParsedNeedValue, ValueExpressionPolicy,
        compile_boolean_template, compile_condition_template, compile_positive_integer_template,
        compile_reusable_input_template, compile_single_expression, compile_template,
        exact_reference_path,
    },
    has_errors,
    lowering::{compile_needs, compile_permissions, located_text},
    safety::scan_lossy_yaml,
};

const RUN_NAME_CONTEXTS: &[ExpressionContext] =
    &[ExpressionContext::Github, ExpressionContext::Inputs];
const WORKFLOW_CONCURRENCY_CONTEXTS: &[ExpressionContext] = &[
    ExpressionContext::Github,
    ExpressionContext::Inputs,
    ExpressionContext::Vars,
];
const WORKFLOW_ENV_CONTEXTS: &[ExpressionContext] = &[
    ExpressionContext::Github,
    ExpressionContext::Inputs,
    ExpressionContext::Vars,
    ExpressionContext::Secrets,
];
const JOB_IF_CONTEXTS: &[ExpressionContext] = &[
    ExpressionContext::Github,
    ExpressionContext::Inputs,
    ExpressionContext::Vars,
    ExpressionContext::Needs,
];
const STRATEGY_CONTEXTS: &[ExpressionContext] = JOB_IF_CONTEXTS;
const JOB_ACTIVATION_CONTEXTS: &[ExpressionContext] = &[
    ExpressionContext::Github,
    ExpressionContext::Inputs,
    ExpressionContext::Vars,
    ExpressionContext::Needs,
    ExpressionContext::Strategy,
    ExpressionContext::Matrix,
];
const JOB_ENV_CONTEXTS: &[ExpressionContext] = &[
    ExpressionContext::Github,
    ExpressionContext::Inputs,
    ExpressionContext::Vars,
    ExpressionContext::Needs,
    ExpressionContext::Strategy,
    ExpressionContext::Matrix,
    ExpressionContext::Secrets,
];
const JOB_DEFAULT_CONTEXTS: &[ExpressionContext] = &[
    ExpressionContext::Github,
    ExpressionContext::Inputs,
    ExpressionContext::Vars,
    ExpressionContext::Needs,
    ExpressionContext::Strategy,
    ExpressionContext::Matrix,
    ExpressionContext::Env,
];
const STEP_CONTEXTS: &[ExpressionContext] = &[
    ExpressionContext::Github,
    ExpressionContext::Inputs,
    ExpressionContext::Vars,
    ExpressionContext::Needs,
    ExpressionContext::Strategy,
    ExpressionContext::Matrix,
    ExpressionContext::Env,
    ExpressionContext::Secrets,
    ExpressionContext::Job,
    ExpressionContext::Runner,
    ExpressionContext::Steps,
];
const OUTPUT_CONTEXTS: &[ExpressionContext] = STEP_CONTEXTS;
const REUSABLE_INPUT_CONTEXTS: &[ExpressionContext] = JOB_ACTIVATION_CONTEXTS;
const REUSABLE_SECRET_CONTEXTS: &[ExpressionContext] = &[
    ExpressionContext::Github,
    ExpressionContext::Inputs,
    ExpressionContext::Vars,
    ExpressionContext::Needs,
    ExpressionContext::Strategy,
    ExpressionContext::Matrix,
    ExpressionContext::Secrets,
];
const WORKFLOW_OUTPUT_CONTEXTS: &[ExpressionContext] = &[ExpressionContext::Jobs];

const RUN_NAME_POLICY: ValueExpressionPolicy = ValueExpressionPolicy::new(
    "workflow run-name",
    PlanEvaluationPhase::Admission,
    RUN_NAME_CONTEXTS,
    false,
);
const WORKFLOW_ENV_POLICY: ValueExpressionPolicy = ValueExpressionPolicy::new(
    "workflow environment",
    PlanEvaluationPhase::JobExecution,
    WORKFLOW_ENV_CONTEXTS,
    false,
);
const WORKFLOW_CONCURRENCY_POLICY: ValueExpressionPolicy = ValueExpressionPolicy::new(
    "workflow concurrency",
    PlanEvaluationPhase::Admission,
    WORKFLOW_CONCURRENCY_CONTEXTS,
    false,
);
const STRATEGY_POLICY: ValueExpressionPolicy = ValueExpressionPolicy::new(
    "job strategy",
    PlanEvaluationPhase::JobActivation,
    STRATEGY_CONTEXTS,
    false,
);
const JOB_ACTIVATION_POLICY: ValueExpressionPolicy = ValueExpressionPolicy::new(
    "job activation field",
    PlanEvaluationPhase::JobActivation,
    JOB_ACTIVATION_CONTEXTS,
    false,
);
const JOB_RESOURCE_POLICY: ValueExpressionPolicy = ValueExpressionPolicy::new(
    "job resource quantity",
    PlanEvaluationPhase::JobActivation,
    JOB_ACTIVATION_CONTEXTS,
    false,
);
const JOB_ENV_POLICY: ValueExpressionPolicy = ValueExpressionPolicy::new(
    "job environment value",
    PlanEvaluationPhase::JobExecution,
    JOB_ENV_CONTEXTS,
    false,
);
const JOB_DEFAULT_POLICY: ValueExpressionPolicy = ValueExpressionPolicy::new(
    "job run defaults",
    PlanEvaluationPhase::JobExecution,
    JOB_DEFAULT_CONTEXTS,
    false,
);
const STEP_POLICY: ValueExpressionPolicy = ValueExpressionPolicy::new(
    "step field",
    PlanEvaluationPhase::JobExecution,
    STEP_CONTEXTS,
    true,
);
const OUTPUT_POLICY: ValueExpressionPolicy = ValueExpressionPolicy::new(
    "job output",
    PlanEvaluationPhase::JobFinalization,
    OUTPUT_CONTEXTS,
    false,
);
const REUSABLE_INPUT_POLICY: ValueExpressionPolicy = ValueExpressionPolicy::new(
    "reusable workflow input",
    PlanEvaluationPhase::JobActivation,
    REUSABLE_INPUT_CONTEXTS,
    false,
);
const REUSABLE_SECRET_POLICY: ValueExpressionPolicy = ValueExpressionPolicy::new(
    "reusable workflow secret binding",
    PlanEvaluationPhase::JobActivation,
    REUSABLE_SECRET_CONTEXTS,
    false,
);
const WORKFLOW_OUTPUT_POLICY: ValueExpressionPolicy = ValueExpressionPolicy::new(
    "reusable workflow output",
    PlanEvaluationPhase::WorkflowFinalization,
    WORKFLOW_OUTPUT_CONTEXTS,
    false,
);

struct PendingJob {
    key: WorkflowJobKey,
    needs: BTreeSet<String>,
    references: BTreeMap<ParsedNeedReference, SourceSpan>,
    builder: LogicalJobTemplateBuilder,
    outputs: Vec<LogicalJobOutputDefinition>,
    output_keys: BTreeSet<String>,
    reusable: bool,
    has_strategy: bool,
    span: SourceSpan,
}

struct CompiledJobBody {
    execution: LogicalJobKind,
    environment: TemplateValueMap,
    run_defaults: LogicalRunDefaultsTemplate,
    timeout: Option<Located<LogicalTimeoutTemplate>>,
    continue_on_error: Option<Located<CompiledBooleanTemplate>>,
    outputs: Vec<LogicalJobOutputDefinition>,
    deployment: Option<DeploymentSelection>,
}

pub(super) fn compile(request: CompileWorkflowRequest<'_>) -> CompilationReport {
    let source_provider = request.selection.source_provider();
    let mut context = CompileContext {
        source: request.source_plan,
        diagnostics: Vec::new(),
    };
    scan_lossy_yaml(request.source_plan, &mut context);

    let workflow = request.source_plan.workflow();
    context.reject_extensions(workflow.extensions());
    let event = compile_event(request.event, &request.selection, &mut context);
    if !matches!(event, CompiledEvent::Selected { .. }) {
        return finish_compilation(event, None, context.diagnostics);
    }
    let source = compile_source(&context, source_provider);
    let name = compile_workflow_name(workflow.name(), &mut context);
    let mut workflow_references = BTreeMap::new();
    let run_name = workflow.run_name().and_then(|value| {
        compile_located_template(
            value,
            RUN_NAME_POLICY,
            &mut workflow_references,
            &mut context,
        )
    });
    let permissions = workflow
        .permissions()
        .and_then(|value| compile_permission_snapshot(value, &mut context));
    let environment = compile_template_map(
        workflow.environment(),
        WORKFLOW_ENV_POLICY,
        &mut workflow_references,
        &mut context,
    );
    let run_defaults = compile_defaults(
        workflow.defaults(),
        None,
        &mut workflow_references,
        &mut context,
    );
    let concurrency = workflow.concurrency().and_then(|value| {
        compile_concurrency(
            value,
            WORKFLOW_CONCURRENCY_POLICY,
            &mut workflow_references,
            &mut context,
        )
    });
    reject_workflow_need_references(&workflow_references, workflow.span(), &mut context);

    let mut pending = workflow
        .jobs()
        .iter()
        .enumerate()
        .filter_map(|(index, job)| compile_job(index, job, &mut context))
        .collect::<Vec<_>>();
    validate_and_infer_result_edges(&mut pending, &mut context);
    let jobs = pending
        .into_iter()
        .filter_map(|job| finish_job(job, &mut context))
        .collect::<Vec<_>>();
    let span = context.span(workflow.span());
    let invocation = match &event {
        CompiledEvent::Selected { event, .. } => Some(event),
        CompiledEvent::RequiresChangedFiles
        | CompiledEvent::NotSelected(_)
        | CompiledEvent::Rejected => None,
    }
    .and_then(|event| compile_invocation_contract(workflow, event.name(), &jobs, &mut context));

    let plan = match (&event, span) {
        (CompiledEvent::Selected { event, .. }, Some(span))
            if !has_errors(&context.diagnostics) =>
        {
            let event = event.as_ref().clone();
            match automata_ci_core::WorkflowPlan::logical_builder(source, event, jobs, span)
                .name(name)
                .invocation(invocation)
                .run_name(run_name)
                .permissions(permissions)
                .environment(environment)
                .run_defaults(run_defaults)
                .concurrency(concurrency)
                .build()
            {
                Ok(plan) => Some(plan),
                Err(error) => {
                    context.semantic(
                        "github.compile.invalid_logical_workflow_plan",
                        error.to_string(),
                        workflow.span().clone(),
                    );
                    None
                }
            }
        }
        _ => None,
    };
    finish_compilation(event, plan, context.diagnostics)
}

fn reject_workflow_need_references(
    references: &BTreeMap<ParsedNeedReference, SourceSpan>,
    workflow_span: &SourceSpan,
    context: &mut CompileContext<'_>,
) {
    if !references.is_empty() {
        context.semantic(
            "github.compile.workflow_needs_reference",
            "workflow-level fields cannot reference job results",
            workflow_span.clone(),
        );
    }
}

fn finish_compilation(
    event: CompiledEvent,
    plan: Option<automata_ci_core::WorkflowPlan>,
    diagnostics: Vec<crate::Diagnostic>,
) -> CompilationReport {
    let disposition = compilation_disposition(&event, plan.as_ref(), &diagnostics);
    let (workflow_dispatch_contract, workflow_dispatch_inputs) =
        if matches!(disposition, CompilationDisposition::Accepted) {
            match event {
                CompiledEvent::Selected {
                    workflow_dispatch: Some(workflow_dispatch),
                    ..
                } => (
                    Some(workflow_dispatch.contract),
                    Some(workflow_dispatch.inputs),
                ),
                _ => (None, None),
            }
        } else {
            (None, None)
        };
    CompilationReport {
        plan,
        diagnostics,
        disposition,
        workflow_dispatch_contract,
        workflow_dispatch_inputs,
    }
}

fn compilation_disposition(
    event: &CompiledEvent,
    plan: Option<&automata_ci_core::WorkflowPlan>,
    diagnostics: &[crate::Diagnostic],
) -> CompilationDisposition {
    if has_errors(diagnostics) {
        return CompilationDisposition::Rejected;
    }
    match event {
        CompiledEvent::Selected { .. } if plan.is_some() => CompilationDisposition::Accepted,
        CompiledEvent::RequiresChangedFiles => CompilationDisposition::RequiresChangedFiles,
        CompiledEvent::NotSelected(reason) => CompilationDisposition::NotSelected(*reason),
        CompiledEvent::Selected { .. } | CompiledEvent::Rejected => {
            CompilationDisposition::Rejected
        }
    }
}

fn compile_workflow_name(
    name: Option<&Spanned<String>>,
    context: &mut CompileContext<'_>,
) -> Option<Located<String>> {
    let name = name?;
    if name.value().contains("${{") {
        context.unsupported(
            "github.compile.dynamic_workflow_name",
            "workflow `name` does not accept expressions",
            name.span().clone(),
        );
        return None;
    }
    located_text(name, context)
}

fn compile_permission_snapshot(
    permissions: &Permissions,
    context: &mut CompileContext<'_>,
) -> Option<PermissionSnapshotRequest> {
    let compiled = compile_permissions(permissions, context)?;
    Some(PermissionSnapshotRequest::new(
        compiled,
        context.span(permissions.span())?,
    ))
}

fn compile_invocation_contract(
    workflow: &crate::GithubWorkflow,
    event_name: &str,
    jobs: &[LogicalJobTemplate],
    context: &mut CompileContext<'_>,
) -> Option<WorkflowInvocationContract> {
    if event_name != "workflow_call" {
        return None;
    }
    let trigger = workflow
        .triggers()?
        .events()
        .iter()
        .find(|trigger| matches!(trigger.name().value(), crate::EventName::WorkflowCall))?;
    let TriggerConfiguration::WorkflowCall(configuration) = trigger.configuration() else {
        return Some(WorkflowInvocationContract::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            context.span(trigger.span())?,
        ));
    };
    compile_workflow_call_contract(configuration, jobs, context)
}

fn compile_workflow_call_contract(
    configuration: &YamlNode,
    jobs: &[LogicalJobTemplate],
    context: &mut CompileContext<'_>,
) -> Option<WorkflowInvocationContract> {
    if configuration
        .as_scalar()
        .is_some_and(crate::YamlScalar::is_null)
    {
        return Some(WorkflowInvocationContract::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            context.span(configuration.span())?,
        ));
    }
    let entries = configuration.as_mapping()?;
    let mut inputs = None;
    let mut secrets = None;
    let mut outputs = None;
    for entry in entries {
        match yaml_key(entry, "on.workflow_call", context).as_deref() {
            Some("inputs") => set_contract_field(&mut inputs, entry, context),
            Some("secrets") => set_contract_field(&mut secrets, entry, context),
            Some("outputs") => set_contract_field(&mut outputs, entry, context),
            Some(_) | None => {}
        }
    }
    Some(WorkflowInvocationContract::new(
        inputs
            .map(|node| compile_invocation_inputs(node, context))
            .unwrap_or_default(),
        secrets
            .map(|node| compile_invocation_secrets(node, context))
            .unwrap_or_default(),
        outputs
            .map(|node| compile_invocation_outputs(node, jobs, context))
            .unwrap_or_default(),
        context.span(configuration.span())?,
    ))
}

fn set_contract_field<'a>(
    slot: &mut Option<&'a YamlNode>,
    entry: &'a YamlMappingEntry,
    context: &mut CompileContext<'_>,
) {
    if slot.replace(entry.value()).is_some() {
        context.semantic(
            "github.compile.duplicate_workflow_call_field",
            "`on.workflow_call` contract fields must be unique",
            entry.key().span().clone(),
        );
    }
}

fn compile_invocation_inputs(
    node: &YamlNode,
    context: &mut CompileContext<'_>,
) -> Vec<InvocationInputDefinition> {
    let Some(entries) = node.as_mapping() else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|entry| compile_invocation_input(entry, context))
        .collect()
}

fn compile_invocation_input(
    entry: &YamlMappingEntry,
    context: &mut CompileContext<'_>,
) -> Option<InvocationInputDefinition> {
    let raw_key = yaml_key(entry, "on.workflow_call.inputs", context)?;
    let key = match WorkflowInputKey::new(&raw_key) {
        Ok(key) => context.located(key, entry.key().span())?,
        Err(error) => {
            context.semantic(
                "github.compile.invalid_workflow_call_input_key",
                error.to_string(),
                entry.key().span().clone(),
            );
            return None;
        }
    };
    let fields = contract_definition_fields(
        entry.value(),
        "on.workflow_call.inputs",
        &["type", "required", "default", "description"],
        context,
    )?;
    let input_type = fields
        .get("type")
        .and_then(|value| compile_input_type(value, context));
    if input_type.is_none() {
        context.semantic(
            "github.compile.workflow_call_input_type_required",
            "every `on.workflow_call` input requires `type`",
            entry.value().span().clone(),
        );
    }
    let input_type = input_type?;
    let required = fields
        .get("required")
        .and_then(|value| yaml_boolean(value, "workflow-call input required", context))
        .unwrap_or(false);
    let default = fields.get("default").and_then(|value| {
        compile_input_default(value, *input_type.value(), context)
            .and_then(|default| context.located(default, value.span()))
    });
    if required && default.is_some() {
        context.semantic(
            "github.compile.required_workflow_call_input_has_default",
            "a required `on.workflow_call` input cannot also declare a default",
            entry.value().span().clone(),
        );
    }
    let description = fields.get("description").and_then(|value| {
        yaml_text(value, "workflow-call input description", context)
            .and_then(|text| context.located(text, value.span()))
    });
    Some(InvocationInputDefinition::new(
        key,
        input_type,
        required,
        default,
        description,
        context.span(entry.span())?,
    ))
}

fn compile_input_type(
    node: &YamlNode,
    context: &mut CompileContext<'_>,
) -> Option<Located<InvocationInputType>> {
    let value = yaml_text(node, "workflow-call input type", context)?;
    let input_type = match value.as_str() {
        "boolean" => InvocationInputType::Boolean,
        "number" => InvocationInputType::Number,
        "string" => InvocationInputType::String,
        _ => {
            context.semantic(
                "github.compile.invalid_workflow_call_input_type",
                "`on.workflow_call` input type must be `boolean`, `number`, or `string`",
                node.span().clone(),
            );
            return None;
        }
    };
    context.located(input_type, node.span())
}

fn compile_input_default(
    node: &YamlNode,
    input_type: InvocationInputType,
    context: &mut CompileContext<'_>,
) -> Option<InvocationInputDefault> {
    match input_type {
        InvocationInputType::Boolean => {
            yaml_boolean(node, "workflow-call boolean default", context)
                .map(InvocationInputDefault::Boolean)
        }
        InvocationInputType::Number => {
            normalized_yaml_number(node, context).map(InvocationInputDefault::Number)
        }
        InvocationInputType::String => {
            let scalar = node.as_scalar();
            if scalar.is_none_or(|scalar| scalar.resolution() != ScalarResolution::String) {
                context.semantic(
                    "github.compile.workflow_call_default_type",
                    "workflow-call string defaults must be YAML strings",
                    node.span().clone(),
                );
                None
            } else {
                scalar.map(|scalar| InvocationInputDefault::String(scalar.decoded().to_owned()))
            }
        }
    }
}

fn compile_invocation_secrets(
    node: &YamlNode,
    context: &mut CompileContext<'_>,
) -> Vec<InvocationSecretDefinition> {
    let Some(entries) = node.as_mapping() else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|entry| compile_invocation_secret(entry, context))
        .collect()
}

fn compile_invocation_secret(
    entry: &YamlMappingEntry,
    context: &mut CompileContext<'_>,
) -> Option<InvocationSecretDefinition> {
    let raw_key = yaml_key(entry, "on.workflow_call.secrets", context)?;
    let key = match WorkflowSecretKey::new(&raw_key) {
        Ok(key) => context.located(key, entry.key().span())?,
        Err(error) => {
            context.semantic(
                "github.compile.invalid_workflow_call_secret_key",
                error.to_string(),
                entry.key().span().clone(),
            );
            return None;
        }
    };
    let fields = contract_definition_fields(
        entry.value(),
        "on.workflow_call.secrets",
        &["required", "description"],
        context,
    )?;
    let required = fields
        .get("required")
        .and_then(|value| yaml_boolean(value, "workflow-call secret required", context))
        .unwrap_or(false);
    let description = fields.get("description").and_then(|value| {
        yaml_text(value, "workflow-call secret description", context)
            .and_then(|text| context.located(text, value.span()))
    });
    Some(InvocationSecretDefinition::new(
        key,
        required,
        description,
        context.span(entry.span())?,
    ))
}

fn compile_invocation_outputs(
    node: &YamlNode,
    jobs: &[LogicalJobTemplate],
    context: &mut CompileContext<'_>,
) -> Vec<WorkflowOutputDefinition> {
    let Some(entries) = node.as_mapping() else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|entry| compile_invocation_output(entry, jobs, context))
        .collect()
}

fn compile_invocation_output(
    entry: &YamlMappingEntry,
    jobs: &[LogicalJobTemplate],
    context: &mut CompileContext<'_>,
) -> Option<WorkflowOutputDefinition> {
    let raw_key = yaml_key(entry, "on.workflow_call.outputs", context)?;
    let key = match WorkflowOutputKey::new(&raw_key) {
        Ok(key) => context.located(key, entry.key().span())?,
        Err(error) => {
            context.semantic(
                "github.compile.invalid_workflow_call_output_key",
                error.to_string(),
                entry.key().span().clone(),
            );
            return None;
        }
    };
    let fields = contract_definition_fields(
        entry.value(),
        "on.workflow_call.outputs",
        &["value", "description"],
        context,
    )?;
    let value_node = fields.get("value").copied();
    if value_node.is_none() {
        context.semantic(
            "github.compile.workflow_call_output_value_required",
            "every `on.workflow_call` output requires `value`",
            entry.value().span().clone(),
        );
    }
    let value_node = value_node?;
    let value_source = yaml_text(value_node, "workflow-call output value", context)?;
    let analyzed = compile_template(
        &value_source,
        value_node.span(),
        WORKFLOW_OUTPUT_POLICY,
        context,
    )?;
    let value = context.located(analyzed.value, value_node.span())?;
    let reference = compile_workflow_output_reference(&value_source, value_node, jobs, context)?;
    let sensitivity = referenced_output_sensitivity(&reference, jobs, value_node.span(), context)?;
    let description = fields.get("description").and_then(|value| {
        yaml_text(value, "workflow-call output description", context)
            .and_then(|text| context.located(text, value.span()))
    });
    Some(WorkflowOutputDefinition::new(
        key,
        value,
        vec![context.located(reference, value_node.span())?],
        sensitivity,
        description,
        context.span(entry.span())?,
    ))
}

fn compile_workflow_output_reference(
    source: &str,
    node: &YamlNode,
    jobs: &[LogicalJobTemplate],
    context: &mut CompileContext<'_>,
) -> Option<LogicalResultReference> {
    let path = exact_reference_path(source, node.span(), WORKFLOW_OUTPUT_POLICY, context)?;
    let [root, job, outputs, output] = path.as_slice() else {
        context.unsupported(
            "github.compile.workflow_call_output_reference_shape",
            "workflow-call outputs must be one exact `jobs.<job>.outputs.<output>` reference",
            node.span().clone(),
        );
        return None;
    };
    if root != "jobs" || !outputs.eq_ignore_ascii_case("outputs") {
        context.unsupported(
            "github.compile.workflow_call_output_reference_shape",
            "workflow-call outputs must be one exact `jobs.<job>.outputs.<output>` reference",
            node.span().clone(),
        );
        return None;
    }
    let job = WorkflowJobKey::new(job)
        .map_err(|error| {
            context.semantic(
                "github.compile.invalid_workflow_call_output_reference",
                error.to_string(),
                node.span().clone(),
            );
        })
        .ok()?;
    let output = WorkflowOutputKey::new(output)
        .map_err(|error| {
            context.semantic(
                "github.compile.invalid_workflow_call_output_reference",
                error.to_string(),
                node.span().clone(),
            );
        })
        .ok()?;
    if jobs.iter().all(|candidate| candidate.key().value() != &job) {
        context.semantic(
            "github.compile.unknown_workflow_call_output_job",
            "workflow-call output references an unknown job",
            node.span().clone(),
        );
        return None;
    }
    Some(LogicalResultReference::new(
        job,
        LogicalResultValue::Output(output),
    ))
}

fn referenced_output_sensitivity(
    reference: &LogicalResultReference,
    jobs: &[LogicalJobTemplate],
    span: &SourceSpan,
    context: &mut CompileContext<'_>,
) -> Option<OutputSensitivity> {
    let LogicalResultValue::Output(output) = reference.value() else {
        return None;
    };
    let definition = jobs
        .iter()
        .find(|job| job.key().value() == reference.job())
        .and_then(|job| {
            job.outputs()
                .iter()
                .find(|definition| definition.key().value() == output)
        });
    let Some(definition) = definition else {
        context.semantic(
            "github.compile.unknown_workflow_call_job_output",
            "workflow-call output references an undeclared job output",
            span.clone(),
        );
        return None;
    };
    Some(definition.sensitivity())
}

fn contract_definition_fields<'a>(
    node: &'a YamlNode,
    path: &str,
    supported: &[&str],
    context: &mut CompileContext<'_>,
) -> Option<BTreeMap<String, &'a YamlNode>> {
    let Some(entries) = node.as_mapping() else {
        context.semantic(
            "github.compile.invalid_workflow_call_definition",
            format!("`{path}` definitions must be mappings"),
            node.span().clone(),
        );
        return None;
    };
    let mut fields = BTreeMap::new();
    for entry in entries {
        let Some(key) = yaml_key(entry, path, context) else {
            continue;
        };
        if !supported.contains(&key.as_str()) {
            context.unsupported(
                "github.compile.workflow_call_definition_field",
                format!("`{path}.{key}` is not supported"),
                entry.key().span().clone(),
            );
            continue;
        }
        if fields.insert(key, entry.value()).is_some() {
            context.semantic(
                "github.compile.duplicate_workflow_call_definition_field",
                "workflow-call definition fields must be unique",
                entry.key().span().clone(),
            );
        }
    }
    Some(fields)
}

fn yaml_key(
    entry: &YamlMappingEntry,
    path: &str,
    context: &mut CompileContext<'_>,
) -> Option<String> {
    let Some(scalar) = entry.key().as_scalar() else {
        context.semantic(
            "github.compile.invalid_workflow_call_key",
            format!("`{path}` field names must be scalar text"),
            entry.key().span().clone(),
        );
        return None;
    };
    if scalar.resolution() != ScalarResolution::String || scalar.decoded().is_empty() {
        context.semantic(
            "github.compile.invalid_workflow_call_key",
            format!("`{path}` field names must be non-empty text"),
            entry.key().span().clone(),
        );
        return None;
    }
    Some(scalar.decoded().to_owned())
}

fn yaml_text(node: &YamlNode, field: &str, context: &mut CompileContext<'_>) -> Option<String> {
    let Some(scalar) = node.as_scalar() else {
        context.semantic(
            "github.compile.invalid_workflow_call_scalar",
            format!("{field} must be scalar text"),
            node.span().clone(),
        );
        return None;
    };
    if scalar.is_null() {
        context.semantic(
            "github.compile.invalid_workflow_call_scalar",
            format!("{field} must not be null"),
            node.span().clone(),
        );
        return None;
    }
    Some(scalar.decoded().to_owned())
}

fn yaml_boolean(node: &YamlNode, field: &str, context: &mut CompileContext<'_>) -> Option<bool> {
    let Some(scalar) = node.as_scalar() else {
        context.semantic(
            "github.compile.invalid_workflow_call_boolean",
            format!("{field} must be a YAML boolean"),
            node.span().clone(),
        );
        return None;
    };
    if scalar.resolution() != ScalarResolution::Boolean {
        context.semantic(
            "github.compile.invalid_workflow_call_boolean",
            format!("{field} must be a YAML boolean"),
            node.span().clone(),
        );
        return None;
    }
    Some(scalar.decoded().eq_ignore_ascii_case("true"))
}

fn normalized_yaml_number(node: &YamlNode, context: &mut CompileContext<'_>) -> Option<String> {
    let Some(scalar) = node.as_scalar() else {
        context.semantic(
            "github.compile.workflow_call_default_type",
            "workflow-call number defaults must be finite YAML numbers",
            node.span().clone(),
        );
        return None;
    };
    if !matches!(
        scalar.resolution(),
        ScalarResolution::Integer | ScalarResolution::Float
    ) {
        context.semantic(
            "github.compile.workflow_call_default_type",
            "workflow-call number defaults must be finite YAML numbers",
            node.span().clone(),
        );
        return None;
    }
    let value = scalar
        .decoded()
        .strip_prefix('+')
        .unwrap_or(scalar.decoded());
    if value.parse::<f64>().is_ok_and(f64::is_finite) {
        Some(value.to_owned())
    } else {
        context.semantic(
            "github.compile.workflow_call_default_type",
            "workflow-call number defaults must be finite decimal numbers",
            node.span().clone(),
        );
        None
    }
}

fn compile_job(
    index: usize,
    job: &WorkflowJob,
    context: &mut CompileContext<'_>,
) -> Option<PendingJob> {
    let source_job = job.job();
    context.reject_extensions(source_job.extensions());
    reject_malformed_job_presence(job, context);
    let source_order = compile_source_order(index, source_job.span(), context)?;
    let key = match WorkflowJobKey::new(job.id().as_str()) {
        Ok(key) => key,
        Err(error) => {
            context.semantic(
                "github.compile.invalid_job_key",
                error.to_string(),
                job.id().span().clone(),
            );
            return None;
        }
    };
    let located_key = context.located(key.clone(), job.id().span())?;
    let span = context.span(source_job.span())?;
    let needs = compile_needs(source_job.needs(), context);
    let need_names = needs
        .iter()
        .map(|need| need.value().as_str().to_owned())
        .collect::<BTreeSet<_>>();
    let mut references = BTreeMap::new();

    let name = source_job.name().and_then(|value| {
        compile_located_template(value, JOB_ACTIVATION_POLICY, &mut references, context)
    });
    let condition = source_job.condition().and_then(|value| {
        let analyzed = compile_condition_template(
            value,
            GithubConditionPhase::Job,
            PlanEvaluationPhase::JobActivation,
            context,
        )?;
        locate_analyzed(analyzed, value.span(), &mut references, context)
    });
    let reusable = source_job.reusable_workflow_call().is_some();
    let strategy = source_job.strategy().and_then(|strategy| {
        if reusable {
            context.unsupported(
                "github.compile.reusable_workflow_matrix_unavailable",
                "matrix strategies on reusable-workflow calls require durable per-cell call coordination and must be rejected before publication",
                strategy
                    .matrix()
                    .map_or_else(|| strategy.span().clone(), |matrix| matrix.span().clone()),
            );
            None
        } else {
            compile_strategy(strategy, &mut references, context)
        }
    });
    let has_strategy = strategy.is_some();
    let permissions = source_job
        .permissions()
        .and_then(|permissions| compile_permission_snapshot(permissions, context));
    let concurrency = source_job.concurrency().and_then(|concurrency| {
        context.unsupported(
            "github.compile.job_concurrency_unavailable",
            "job-level `concurrency` is not runnable and must be rejected before publication",
            concurrency_span(concurrency).clone(),
        );
        None
    });

    let body = compile_job_body(job, has_strategy, span.clone(), &mut references, context)?;

    let output_keys = body
        .outputs
        .iter()
        .map(|output| output.key().value().as_str().to_owned())
        .collect();
    let builder = LogicalJobTemplate::builder(located_key, source_order, body.execution, span)
        .name(name)
        .needs(needs)
        .condition(condition)
        .strategy(strategy)
        .permissions(permissions)
        .concurrency(concurrency)
        .environment(body.environment)
        .run_defaults(body.run_defaults)
        .timeout(body.timeout)
        .continue_on_error(body.continue_on_error)
        .deployment(body.deployment);
    Some(PendingJob {
        key,
        needs: need_names,
        references,
        builder,
        outputs: body.outputs,
        output_keys,
        reusable,
        has_strategy,
        span: source_job.span().clone(),
    })
}

fn compile_source_order(
    index: usize,
    span: &SourceSpan,
    context: &mut CompileContext<'_>,
) -> Option<u32> {
    let Ok(source_order) = u32::try_from(index) else {
        context.semantic(
            "github.compile.job_order_overflow",
            "job source order exceeds the workflow-plan representation",
            span.clone(),
        );
        return None;
    };
    Some(source_order)
}

fn compile_job_body(
    job: &WorkflowJob,
    has_strategy: bool,
    span: PlanSourceSpan,
    references: &mut BTreeMap<ParsedNeedReference, SourceSpan>,
    context: &mut CompileContext<'_>,
) -> Option<CompiledJobBody> {
    if let Some(call) = job.job().reusable_workflow_call() {
        reject_reusable_step_fields(job, context);
        return Some(CompiledJobBody {
            execution: LogicalJobKind::ReusableWorkflow(compile_reusable_invocation(
                call, references, context,
            )?),
            environment: TemplateValueMap::default(),
            run_defaults: LogicalRunDefaultsTemplate::default(),
            timeout: None,
            continue_on_error: None,
            outputs: Vec::new(),
            deployment: None,
        });
    }
    compile_step_job_body(job, has_strategy, span, references, context)
}

fn compile_step_job_body(
    job: &WorkflowJob,
    has_strategy: bool,
    span: PlanSourceSpan,
    references: &mut BTreeMap<ParsedNeedReference, SourceSpan>,
    context: &mut CompileContext<'_>,
) -> Option<CompiledJobBody> {
    let source_job = job.job();
    let Some(runner) = source_job.runner() else {
        context.semantic(
            "github.compile.missing_runner",
            format!("step job `{}` requires `runs-on`", job.id().as_str()),
            source_job.span().clone(),
        );
        return None;
    };
    let runner = compile_runner(runner, references, context)?;
    let steps = source_job
        .steps()
        .iter()
        .enumerate()
        .filter_map(|(index, step)| compile_step(index, step, references, context))
        .collect::<Vec<_>>();
    let services = source_job.services().map_or_else(Vec::new, |services| {
        services
            .entries()
            .iter()
            .filter_map(|service| compile_service(service, references, context))
            .collect()
    });
    let resources = source_job
        .resources()
        .and_then(|resources| compile_job_resources(resources, references, context));
    let environment = compile_template_map(
        source_job.environment(),
        JOB_ENV_POLICY,
        references,
        context,
    );
    let run_defaults = compile_defaults(
        source_job.defaults(),
        Some(JOB_DEFAULT_POLICY),
        references,
        context,
    );
    let timeout = source_job
        .timeout_minutes()
        .and_then(|value| compile_timeout(value, JOB_ACTIVATION_POLICY, references, context));
    let continue_on_error = source_job.continue_on_error().and_then(|value| {
        let analyzed = compile_boolean_template(value, JOB_ACTIVATION_POLICY, context)?;
        locate_analyzed(analyzed, boolean_span(value), references, context)
    });
    let outputs = source_job.outputs().map_or_else(Vec::new, |outputs| {
        compile_outputs(outputs.values(), has_strategy, references, context)
    });
    let deployment = source_job.deployment_environment().and_then(|environment| {
        context.unsupported(
            "github.compile.deployment_environment_unavailable",
            "deployment environments are not runnable and must be rejected before publication",
            environment
                .name()
                .map_or_else(|| environment.span().clone(), |name| name.span().clone()),
        );
        None
    });
    Some(CompiledJobBody {
        execution: LogicalJobKind::Steps(
            StepJobTemplate::new(runner, steps, span)
                .with_resources(resources)
                .with_services(services),
        ),
        environment,
        run_defaults,
        timeout,
        continue_on_error,
        outputs,
        deployment,
    })
}

fn reject_malformed_job_presence(job: &WorkflowJob, context: &mut CompileContext<'_>) {
    let source_job = job.job();
    if let Some(span) = source_job.container_source_span() {
        context.unsupported(
            "github.compile.job_container",
            format!(
                "`jobs.{}.container` is typed by the GitHub frontend, but the logical plan has no production container execution contract yet",
                job.id().as_str()
            ),
            span.clone(),
        );
    }
    if let Some(span) = source_job.services_source_span()
        && source_job.services().is_none()
    {
        context.semantic(
            "github.compile.invalid_job_services",
            format!("`jobs.{}.services` could not be lowered", job.id().as_str()),
            span.clone(),
        );
    }
    if let Some(span) = source_job.resources_source_span()
        && source_job.resources().is_none()
    {
        context.semantic(
            "github.compile.invalid_job_resources",
            format!(
                "`jobs.{}.resources` could not be lowered",
                job.id().as_str()
            ),
            span.clone(),
        );
    }
    if let Some(span) = source_job.strategy_source_span()
        && source_job.strategy().is_none()
    {
        context.semantic(
            "github.compile.invalid_job_strategy",
            format!("`jobs.{}.strategy` could not be lowered", job.id().as_str()),
            span.clone(),
        );
    }
    if let Some(span) = source_job.outputs_source_span()
        && source_job.outputs().is_none()
    {
        context.semantic(
            "github.compile.invalid_job_outputs",
            format!("`jobs.{}.outputs` could not be lowered", job.id().as_str()),
            span.clone(),
        );
    }
    if let Some(span) = source_job.deployment_environment_source_span()
        && source_job.deployment_environment().is_none()
    {
        context.semantic(
            "github.compile.invalid_job_environment",
            format!(
                "`jobs.{}.environment` could not be lowered",
                job.id().as_str()
            ),
            span.clone(),
        );
    }
}

fn compile_service(
    service: &JobService,
    references: &mut BTreeMap<ParsedNeedReference, SourceSpan>,
    context: &mut CompileContext<'_>,
) -> Option<LogicalServiceContainerTemplate> {
    let key = match WorkflowServiceKey::new(service.id().value().clone()) {
        Ok(key) => context.located(key, service.id().span())?,
        Err(error) => {
            context.semantic(
                "github.compile.invalid_service_key",
                error.to_string(),
                service.id().span().clone(),
            );
            return None;
        }
    };
    let (image, environment, ports, options) = match service.container() {
        JobContainer::Image(image) => (
            compile_service_image(image, context)?,
            TemplateValueMap::default(),
            Vec::new(),
            Vec::new(),
        ),
        JobContainer::Detailed(container) => {
            context.reject_extensions(container.extensions());
            if let Some(credentials) = container.credentials() {
                context.unsupported(
                    "github.compile.service_credentials",
                    "service-container registry credentials are not yet supported",
                    credentials.span().clone(),
                );
            }
            if let Some(volumes) = container.volumes()
                && !volumes.values().is_empty()
            {
                context.unsupported(
                    "github.compile.service_volumes",
                    "service-container volumes are not yet supported",
                    volumes.span().clone(),
                );
            }
            let Some(image) = container.image() else {
                context.semantic(
                    "github.compile.service_image_required",
                    "every service container requires an image",
                    container.span().clone(),
                );
                return None;
            };
            let image = compile_service_image(image, context)?;
            let environment =
                container
                    .environment()
                    .map_or_else(TemplateValueMap::default, |environment| {
                        compile_template_map(
                            environment.values(),
                            JOB_ENV_POLICY,
                            references,
                            context,
                        )
                    });
            let ports = container.ports().map_or_else(Vec::new, |ports| {
                ports
                    .values()
                    .iter()
                    .filter_map(|port| compile_service_port(port, context))
                    .collect()
            });
            let options = container.options().map_or_else(Vec::new, |options| {
                compile_service_options(options, context)
            });
            (image, environment, ports, options)
        }
    };
    Some(LogicalServiceContainerTemplate::new(
        key,
        image,
        environment,
        ports,
        options,
        context.span(service.span())?,
    ))
}

fn compile_service_image(
    image: &ScalarValue,
    context: &mut CompileContext<'_>,
) -> Option<Located<String>> {
    if image.contains_expression_candidate() {
        context.unsupported(
            "github.compile.dynamic_service_image",
            "service-container images must currently be immutable literal references",
            image.span().clone(),
        );
        return None;
    }
    let value = image.decoded();
    let valid = value.len() <= 512
        && value.is_ascii()
        && !value.bytes().any(|byte| byte.is_ascii_whitespace())
        && value
            .rsplit_once("@sha256:")
            .is_some_and(|(repository, digest)| {
                !repository.is_empty()
                    && !repository.contains('@')
                    && repository.contains('/')
                    && repository
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"./:_-".contains(&byte))
                    && digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            });
    if !valid {
        context.unsupported(
            "github.compile.mutable_service_image",
            "service-container images must be registry-qualified and pinned to a lowercase SHA-256 digest",
            image.span().clone(),
        );
        return None;
    }
    context.located(value.to_owned(), image.span())
}

fn compile_service_port(
    port: &ScalarValue,
    context: &mut CompileContext<'_>,
) -> Option<Located<ContainerPort>> {
    if port.contains_expression_candidate() {
        context.unsupported(
            "github.compile.dynamic_service_port",
            "service-container ports must currently be literal values",
            port.span().clone(),
        );
        return None;
    }
    let (mapping, protocol) = if let Some(mapping) = port.decoded().strip_suffix("/udp") {
        (mapping, TransportProtocol::Udp)
    } else if let Some(mapping) = port.decoded().strip_suffix("/tcp") {
        (mapping, TransportProtocol::Tcp)
    } else {
        (port.decoded(), TransportProtocol::Tcp)
    };
    let mut components = mapping.split(':');
    let first = components.next();
    let second = components.next();
    if components.next().is_some() {
        return invalid_service_port(port, context);
    }
    let (requested_host_port, container_port) = match (first, second) {
        (Some(container), None) => (None, parse_nonzero_port(container)),
        (Some(host), Some(container)) => (parse_nonzero_port(host), parse_nonzero_port(container)),
        _ => return invalid_service_port(port, context),
    };
    let Some(container_port) = container_port else {
        return invalid_service_port(port, context);
    };
    if second.is_some() && requested_host_port.is_none() {
        return invalid_service_port(port, context);
    }
    context.located(
        ContainerPort::new(container_port, requested_host_port, protocol),
        port.span(),
    )
}

fn parse_nonzero_port(value: &str) -> Option<u16> {
    value.parse::<u16>().ok().filter(|value| *value != 0)
}

fn invalid_service_port(
    port: &ScalarValue,
    context: &mut CompileContext<'_>,
) -> Option<Located<ContainerPort>> {
    context.semantic(
        "github.compile.invalid_service_port",
        "service ports must be `container[/protocol]` or `host:container[/protocol]` with non-zero 16-bit ports",
        port.span().clone(),
    );
    None
}

fn compile_service_options(
    options: &ScalarValue,
    context: &mut CompileContext<'_>,
) -> Vec<Located<String>> {
    if options.contains_expression_candidate() {
        context.unsupported(
            "github.compile.dynamic_service_options",
            "service-container options must currently be literal health-check options",
            options.span().clone(),
        );
        return Vec::new();
    }
    let Some(tokens) = split_service_options(options.decoded()) else {
        context.semantic(
            "github.compile.invalid_service_options",
            "service-container options contain invalid or unterminated quoting",
            options.span().clone(),
        );
        return Vec::new();
    };
    if !health_only_service_options(&tokens) {
        context.unsupported(
            "github.compile.service_options",
            "only bounded health-check service-container options are supported",
            options.span().clone(),
        );
        return Vec::new();
    }
    tokens
        .into_iter()
        .filter_map(|token| context.located(token, options.span()))
        .collect()
}

fn split_service_options(source: &str) -> Option<Vec<String>> {
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Quote {
        None,
        Single,
        Double,
    }

    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut active = false;
    let mut quote = Quote::None;
    let mut escaped = false;
    for character in source.chars() {
        if escaped {
            if character.is_control() && !character.is_ascii_whitespace() {
                return None;
            }
            token.push(character);
            active = true;
            escaped = false;
            continue;
        }
        match quote {
            Quote::None => match character {
                '\\' => {
                    escaped = true;
                    active = true;
                }
                '\'' => {
                    quote = Quote::Single;
                    active = true;
                }
                '"' => {
                    quote = Quote::Double;
                    active = true;
                }
                character if character.is_ascii_whitespace() => {
                    if active {
                        tokens.push(std::mem::take(&mut token));
                        active = false;
                    }
                }
                character if character.is_control() => return None,
                character => {
                    token.push(character);
                    active = true;
                }
            },
            Quote::Single if character == '\'' => quote = Quote::None,
            Quote::Double if character == '"' => quote = Quote::None,
            Quote::Double if character == '\\' => escaped = true,
            Quote::Single | Quote::Double => {
                if character.is_control() && !character.is_ascii_whitespace() {
                    return None;
                }
                token.push(character);
            }
        }
    }
    if escaped || quote != Quote::None {
        return None;
    }
    if active {
        tokens.push(token);
    }
    Some(tokens)
}

fn health_only_service_options(tokens: &[String]) -> bool {
    let mut seen = BTreeSet::new();
    let mut index = 0;
    while index < tokens.len() {
        let token = &tokens[index];
        if token == "--no-healthcheck" {
            return tokens.len() == 1;
        }
        let (name, inline) = token
            .split_once('=')
            .map_or((token.as_str(), None), |(name, value)| (name, Some(value)));
        let supported = matches!(
            name,
            "--health-cmd"
                | "--health-interval"
                | "--health-timeout"
                | "--health-start-period"
                | "--health-retries"
        );
        if !supported || !seen.insert(name) {
            return false;
        }
        let value = if let Some(value) = inline {
            value
        } else {
            index += 1;
            let Some(value) = tokens.get(index) else {
                return false;
            };
            value
        };
        if value.is_empty() {
            return false;
        }
        index += 1;
    }
    !tokens.is_empty()
}

fn reject_reusable_step_fields(job: &WorkflowJob, context: &mut CompileContext<'_>) {
    let source_job = job.job();
    let mut reject = |field: &'static str, span: SourceSpan| {
        context.semantic(
            "github.compile.step_job_field_on_reusable_workflow_call",
            format!(
                "`jobs.{}` cannot combine reusable workflow `uses` with `{field}`",
                job.id().as_str()
            ),
            span,
        );
    };
    if let Some(runner) = source_job.runner() {
        reject("runs-on", runner_span(runner).clone());
    }
    if let Some(first) = source_job.steps().first() {
        reject("steps", first.span().clone());
    }
    if let Some(first) = source_job.environment().entries().first() {
        reject("env", first.key().span().clone());
    }
    if source_job.defaults().is_some() {
        reject("defaults", source_job.span().clone());
    }
    if let Some(value) = source_job.timeout_minutes() {
        reject("timeout-minutes", value.span().clone());
    }
    if let Some(value) = source_job.continue_on_error() {
        reject("continue-on-error", boolean_span(value).clone());
    }
    if let Some(resources) = source_job.resources() {
        reject("resources", resources.span().clone());
    }
    if let Some(span) = source_job.outputs_source_span() {
        reject("outputs", span.clone());
    }
    if let Some(span) = source_job.deployment_environment_source_span() {
        reject("environment", span.clone());
    }
}

fn compile_job_resources(
    resources: &JobResources,
    references: &mut BTreeMap<ParsedNeedReference, SourceSpan>,
    context: &mut CompileContext<'_>,
) -> Option<LogicalJobResourcesTemplate> {
    context.reject_extensions(resources.extensions());
    let requests = resources
        .requests()
        .and_then(|values| compile_resource_vector(values, references, context));
    let limits = resources
        .limits()
        .and_then(|values| compile_resource_vector(values, references, context));
    Some(LogicalJobResourcesTemplate::new(
        requests,
        limits,
        context.span(resources.span())?,
    ))
}

#[derive(Clone, Copy)]
enum ResourceQuantityKind {
    Cpu,
    Storage,
    Gpu,
}

fn compile_resource_vector(
    values: &JobResourceVector,
    references: &mut BTreeMap<ParsedNeedReference, SourceSpan>,
    context: &mut CompileContext<'_>,
) -> Option<LogicalResourceVectorTemplate> {
    context.reject_extensions(values.extensions());
    let cpu =
        compile_resource_quantity(values.cpu(), ResourceQuantityKind::Cpu, references, context);
    let memory = compile_resource_quantity(
        values.memory(),
        ResourceQuantityKind::Storage,
        references,
        context,
    );
    let ephemeral_storage = compile_resource_quantity(
        values.ephemeral_storage(),
        ResourceQuantityKind::Storage,
        references,
        context,
    );
    let gpu =
        compile_resource_quantity(values.gpu(), ResourceQuantityKind::Gpu, references, context);
    Some(LogicalResourceVectorTemplate::new(
        cpu,
        memory,
        ephemeral_storage,
        gpu,
        context.span(values.span())?,
    ))
}

fn compile_resource_quantity(
    value: Option<&ScalarValue>,
    kind: ResourceQuantityKind,
    references: &mut BTreeMap<ParsedNeedReference, SourceSpan>,
    context: &mut CompileContext<'_>,
) -> Option<Located<CompiledValueTemplate>> {
    let value = value?;
    if !value.contains_expression_candidate() {
        let valid = match kind {
            ResourceQuantityKind::Cpu => parse_cpu_quantity(value.decoded()).is_ok(),
            ResourceQuantityKind::Storage => parse_storage_quantity(value.decoded()).is_ok(),
            ResourceQuantityKind::Gpu => value
                .decoded()
                .parse::<u16>()
                .is_ok_and(|quantity| quantity > 0),
        };
        if !valid {
            context.semantic(
                "github.compile.invalid_resource_quantity",
                "resource quantity is invalid or outside the supported Kubernetes-style grammar",
                value.span().clone(),
            );
            return None;
        }
    }
    compile_scalar_template(value, JOB_RESOURCE_POLICY, references, context)
}

fn finish_job(job: PendingJob, context: &mut CompileContext<'_>) -> Option<LogicalJobTemplate> {
    let references = job
        .references
        .into_iter()
        .filter_map(|(reference, span)| compile_result_reference(reference, &span, context))
        .collect();
    job.builder
        .result_references(references)
        .outputs(job.outputs)
        .build()
        .map_err(|error| {
            context.semantic(
                "github.compile.invalid_logical_job",
                error.to_string(),
                job.span,
            );
        })
        .ok()
}

fn compile_result_reference(
    reference: ParsedNeedReference,
    span: &SourceSpan,
    context: &mut CompileContext<'_>,
) -> Option<Located<LogicalResultReference>> {
    let job = match WorkflowJobKey::new(reference.job) {
        Ok(job) => job,
        Err(error) => {
            context.semantic(
                "github.compile.invalid_needs_job_reference",
                error.to_string(),
                span.clone(),
            );
            return None;
        }
    };
    let value = match reference.value {
        ParsedNeedValue::Result => LogicalResultValue::Result,
        ParsedNeedValue::Output(output) => {
            let output = match WorkflowOutputKey::new(output) {
                Ok(output) => output,
                Err(error) => {
                    context.semantic(
                        "github.compile.invalid_needs_output_reference",
                        error.to_string(),
                        span.clone(),
                    );
                    return None;
                }
            };
            LogicalResultValue::Output(output)
        }
    };
    context.located(LogicalResultReference::new(job, value), span)
}

fn validate_and_infer_result_edges(jobs: &mut [PendingJob], context: &mut CompileContext<'_>) {
    let indexes = jobs
        .iter()
        .enumerate()
        .map(|(index, job)| (job.key.as_str().to_owned(), index))
        .collect::<BTreeMap<_, _>>();
    let uses = jobs
        .iter()
        .flat_map(|job| {
            job.references.iter().map(|(reference, span)| {
                (
                    job.key.as_str().to_owned(),
                    job.needs.clone(),
                    reference.clone(),
                    span.clone(),
                )
            })
        })
        .collect::<Vec<_>>();

    for (consumer, needs, reference, span) in uses {
        if !needs.contains(&reference.job) {
            context.semantic(
                "github.compile.needs_reference_not_dependency",
                format!(
                    "job `{consumer}` references `needs.{}` without declaring it in `needs`",
                    reference.job
                ),
                span.clone(),
            );
            continue;
        }
        let Some(&producer_index) = indexes.get(&reference.job) else {
            context.semantic(
                "github.compile.unknown_needs_reference",
                format!(
                    "job `{consumer}` references unknown job `{}`",
                    reference.job
                ),
                span.clone(),
            );
            continue;
        };
        let ParsedNeedValue::Output(output) = &reference.value else {
            continue;
        };
        let producer = &mut jobs[producer_index];
        if producer.output_keys.contains(output) {
            continue;
        }
        if !producer.reusable {
            context.semantic(
                "github.compile.unknown_needs_output",
                format!(
                    "job `{consumer}` references undeclared output `needs.{}.outputs.{output}`",
                    reference.job
                ),
                span,
            );
            continue;
        }
        let key = match WorkflowOutputKey::new(output) {
            Ok(key) => key,
            Err(error) => {
                context.semantic(
                    "github.compile.invalid_needs_output_reference",
                    error.to_string(),
                    span,
                );
                continue;
            }
        };
        let Some(located_key) = context.located(key.clone(), &span) else {
            continue;
        };
        let Some(source) = context.located(key, &span) else {
            continue;
        };
        let Some(definition_span) = context.span(&span) else {
            continue;
        };
        producer.outputs.push(LogicalJobOutputDefinition::new(
            located_key,
            LogicalJobOutputSource::InvocationOutput(source),
            output_merge_policy(producer.has_strategy),
            OutputSensitivity::SecretDerived,
            definition_span,
        ));
        producer.output_keys.insert(output.clone());
    }
}

fn capture_references<T>(
    analyzed: Analyzed<T>,
    span: &SourceSpan,
    references: &mut BTreeMap<ParsedNeedReference, SourceSpan>,
) -> T {
    for reference in analyzed.references {
        references.entry(reference).or_insert_with(|| span.clone());
    }
    analyzed.value
}

fn locate_analyzed<T>(
    analyzed: Analyzed<T>,
    span: &SourceSpan,
    references: &mut BTreeMap<ParsedNeedReference, SourceSpan>,
    context: &mut CompileContext<'_>,
) -> Option<Located<T>> {
    let value = capture_references(analyzed, span, references);
    context.located(value, span)
}

fn compile_located_template(
    value: &Spanned<String>,
    policy: ValueExpressionPolicy,
    references: &mut BTreeMap<ParsedNeedReference, SourceSpan>,
    context: &mut CompileContext<'_>,
) -> Option<Located<CompiledValueTemplate>> {
    let analyzed = compile_template(value.value(), value.span(), policy, context)?;
    locate_analyzed(analyzed, value.span(), references, context)
}

fn compile_scalar_template(
    value: &ScalarValue,
    policy: ValueExpressionPolicy,
    references: &mut BTreeMap<ParsedNeedReference, SourceSpan>,
    context: &mut CompileContext<'_>,
) -> Option<Located<CompiledValueTemplate>> {
    let analyzed = compile_template(value.decoded(), value.span(), policy, context)?;
    locate_analyzed(analyzed, value.span(), references, context)
}

fn compile_template_map(
    map: &ValueMap,
    policy: ValueExpressionPolicy,
    references: &mut BTreeMap<ParsedNeedReference, SourceSpan>,
    context: &mut CompileContext<'_>,
) -> TemplateValueMap {
    let entries = map
        .entries()
        .iter()
        .filter_map(|entry| {
            if entry.key().value().contains("${{") {
                context.semantic(
                    "github.compile.dynamic_mapping_key",
                    "mapping keys cannot contain expressions",
                    entry.key().span().clone(),
                );
                return None;
            }
            let key = located_text(entry.key(), context)?;
            let value = compile_scalar_template(entry.value(), policy, references, context)?;
            Some((key, value))
        })
        .collect();
    TemplateValueMap::new(entries)
}

fn compile_defaults(
    defaults: Option<&Defaults>,
    policy: Option<ValueExpressionPolicy>,
    references: &mut BTreeMap<ParsedNeedReference, SourceSpan>,
    context: &mut CompileContext<'_>,
) -> LogicalRunDefaultsTemplate {
    let Some(defaults) = defaults else {
        return LogicalRunDefaultsTemplate::default();
    };
    context.reject_extensions(defaults.extensions());
    let Some(run) = defaults.run() else {
        return LogicalRunDefaultsTemplate::default();
    };
    context.reject_extensions(run.extensions());
    let mut compile = |value: &Spanned<String>, context: &mut CompileContext<'_>| {
        if let Some(policy) = policy {
            compile_located_template(value, policy, references, context)
        } else if value.value().contains("${{") {
            context.semantic(
                "github.compile.workflow_defaults_expression",
                "workflow-level `defaults.run` does not accept contexts or expressions",
                value.span().clone(),
            );
            None
        } else {
            context.located(
                CompiledValueTemplate::Literal(value.value().clone()),
                value.span(),
            )
        }
    };
    LogicalRunDefaultsTemplate::new(
        run.shell().and_then(|value| compile(value, context)),
        run.working_directory()
            .and_then(|value| compile(value, context)),
    )
}

fn compile_concurrency(
    concurrency: &Concurrency,
    policy: ValueExpressionPolicy,
    references: &mut BTreeMap<ParsedNeedReference, SourceSpan>,
    context: &mut CompileContext<'_>,
) -> Option<LogicalConcurrencyTemplate> {
    match concurrency {
        Concurrency::Group(group) => {
            let compiled = compile_located_template(group, policy, references, context)?;
            Some(LogicalConcurrencyTemplate::new(
                compiled,
                None,
                QueuePolicy::Single,
                context.span(group.span())?,
            ))
        }
        Concurrency::Detailed(details) => {
            context.reject_extensions(details.extensions());
            let group = compile_located_template(details.group(), policy, references, context)?;
            let cancel = details.cancel_in_progress().and_then(|value| {
                let analyzed = compile_boolean_template(value, policy, context)?;
                locate_analyzed(analyzed, boolean_span(value), references, context)
            });
            let queue = details
                .queue()
                .map_or(QueuePolicy::Single, |queue| match queue.value() {
                    ConcurrencyQueue::Single => QueuePolicy::Single,
                    ConcurrencyQueue::Max => QueuePolicy::Max,
                });
            Some(LogicalConcurrencyTemplate::new(
                group,
                cancel,
                queue,
                context.span(details.span())?,
            ))
        }
    }
}

fn compile_timeout(
    value: &ScalarValue,
    policy: ValueExpressionPolicy,
    references: &mut BTreeMap<ParsedNeedReference, SourceSpan>,
    context: &mut CompileContext<'_>,
) -> Option<Located<LogicalTimeoutTemplate>> {
    let analyzed = compile_positive_integer_template(value, policy, context)?;
    let compiled = capture_references(analyzed, value.span(), references);
    context.located(LogicalTimeoutTemplate::minutes(compiled), value.span())
}

fn boolean_span(value: &BooleanValue) -> &SourceSpan {
    match value {
        BooleanValue::Literal(value) => value.span(),
        BooleanValue::Expression(value) => value.span(),
    }
}

fn runner_span(runner: &RunnerSelection) -> &SourceSpan {
    match runner {
        RunnerSelection::Label(value) => value.span(),
        RunnerSelection::Labels { span, .. } | RunnerSelection::Group { span, .. } => span,
    }
}

fn concurrency_span(concurrency: &Concurrency) -> &SourceSpan {
    match concurrency {
        Concurrency::Group(group) => group.span(),
        Concurrency::Detailed(details) => details.span(),
    }
}

fn output_merge_policy(has_strategy: bool) -> LogicalOutputMergePolicy {
    if has_strategy {
        LogicalOutputMergePolicy::LastSuccessfulCompletion
    } else {
        LogicalOutputMergePolicy::SingleInstance
    }
}

fn compile_runner(
    runner: &RunnerSelection,
    references: &mut BTreeMap<ParsedNeedReference, SourceSpan>,
    context: &mut CompileContext<'_>,
) -> Option<LogicalRunnerTemplate> {
    let (group, labels, span) = match runner {
        RunnerSelection::Label(label) => (
            None,
            vec![compile_located_template(
                label,
                JOB_ACTIVATION_POLICY,
                references,
                context,
            )?],
            label.span(),
        ),
        RunnerSelection::Labels { labels, span } => {
            if labels.is_empty() {
                context.semantic(
                    "github.compile.empty_runner_labels",
                    "`runs-on` label lists cannot be empty",
                    span.clone(),
                );
            }
            let labels = labels
                .iter()
                .filter_map(|label| {
                    compile_located_template(label, JOB_ACTIVATION_POLICY, references, context)
                })
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
            let group = compile_located_template(group, JOB_ACTIVATION_POLICY, references, context);
            let labels = labels
                .iter()
                .filter_map(|label| {
                    compile_located_template(label, JOB_ACTIVATION_POLICY, references, context)
                })
                .collect();
            (group, labels, span)
        }
    };
    Some(LogicalRunnerTemplate::new(
        group,
        labels,
        context.span(span)?,
    ))
}

fn compile_step(
    index: usize,
    step: &Step,
    references: &mut BTreeMap<ParsedNeedReference, SourceSpan>,
    context: &mut CompileContext<'_>,
) -> Option<LogicalStepTemplate> {
    context.reject_extensions(step.extensions());
    let id = step.id().and_then(|id| {
        if id.as_str().contains("${{") {
            context.semantic(
                "github.compile.dynamic_step_id",
                "step `id` cannot contain expressions",
                id.span().clone(),
            );
            None
        } else {
            context.located(id.as_str().to_owned(), id.span())
        }
    });
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
    let located_key = context.located(key, step.span())?;
    let name = step
        .name()
        .and_then(|value| compile_located_template(value, STEP_POLICY, references, context));
    let condition = step.condition().and_then(|value| {
        let analyzed = compile_condition_template(
            value,
            GithubConditionPhase::Step,
            PlanEvaluationPhase::JobExecution,
            context,
        )?;
        locate_analyzed(analyzed, value.span(), references, context)
    });
    let environment = compile_template_map(step.environment(), STEP_POLICY, references, context);
    let continue_on_error = step.continue_on_error().and_then(|value| {
        let analyzed = compile_boolean_template(value, STEP_POLICY, context)?;
        locate_analyzed(analyzed, boolean_span(value), references, context)
    });
    let timeout = step
        .timeout_minutes()
        .and_then(|value| compile_timeout(value, STEP_POLICY, references, context));
    let execution = compile_step_execution(step, references, context)?;
    let span = context.span(step.span())?;
    LogicalStepTemplate::builder(located_key, execution, span)
        .id(id)
        .name(name)
        .condition(condition)
        .environment(environment)
        .continue_on_error(continue_on_error)
        .timeout(timeout)
        .build()
        .map_err(|error| {
            context.semantic(
                "github.compile.invalid_logical_step",
                error.to_string(),
                step.span().clone(),
            );
        })
        .ok()
}

fn compile_step_execution(
    step: &Step,
    references: &mut BTreeMap<ParsedNeedReference, SourceSpan>,
    context: &mut CompileContext<'_>,
) -> Option<LogicalStepKind> {
    Some(match step.execution() {
        Some(StepExecution::Run(run)) => {
            let script = compile_located_template(run.script(), STEP_POLICY, references, context)?;
            let shell = run.shell().and_then(|value| {
                compile_located_template(value, STEP_POLICY, references, context)
            });
            let working_directory = run.working_directory().and_then(|value| {
                compile_located_template(value, STEP_POLICY, references, context)
            });
            LogicalStepKind::Run(Box::new(LogicalRunStepTemplate::new(
                script,
                shell,
                working_directory,
            )))
        }
        Some(StepExecution::Action(action)) => {
            if action.reference().value().contains("${{") {
                context.unsupported(
                    "github.compile.dynamic_action_reference",
                    "action `uses` references cannot contain expressions",
                    action.reference().span().clone(),
                );
                return None;
            }
            if action.reference().value().starts_with("docker://") {
                context.unsupported(
                    "github.compile.container_action_unavailable",
                    "direct container actions are not runnable and must be rejected before publication",
                    action.reference().span().clone(),
                );
                return None;
            }
            let reference = located_text(action.reference(), context)?;
            let inputs = compile_template_map(action.inputs(), STEP_POLICY, references, context);
            LogicalStepKind::Uses(LogicalUsesStepTemplate::new(reference, inputs))
        }
        None => {
            context.semantic(
                "github.compile.missing_step_execution",
                "step has no valid `run` or `uses` execution",
                step.span().clone(),
            );
            return None;
        }
    })
}

fn compile_reusable_invocation(
    call: &ReusableWorkflowCall,
    references: &mut BTreeMap<ParsedNeedReference, SourceSpan>,
    context: &mut CompileContext<'_>,
) -> Option<ReusableWorkflowInvocation> {
    let reference = match call.reference() {
        Some(reference) if !reference.value().contains("${{") => located_text(reference, context)?,
        Some(reference) => {
            context.unsupported(
                "github.compile.dynamic_reusable_workflow_reference",
                "reusable workflow `uses` references cannot contain expressions",
                reference.span().clone(),
            );
            return None;
        }
        None => {
            context.semantic(
                "github.compile.missing_reusable_workflow_reference",
                "reusable workflow call has no valid `uses` reference",
                call.span().clone(),
            );
            return None;
        }
    };
    let inputs = call.inputs().map_or_else(Vec::new, |inputs| {
        inputs
            .values()
            .entries()
            .iter()
            .filter_map(|entry| {
                let key = match WorkflowInputKey::new(entry.key().value()) {
                    Ok(key) => context.located(key, entry.key().span())?,
                    Err(error) => {
                        context.semantic(
                            "github.compile.invalid_reusable_input_key",
                            error.to_string(),
                            entry.key().span().clone(),
                        );
                        return None;
                    }
                };
                let analyzed =
                    compile_reusable_input_template(entry.value(), REUSABLE_INPUT_POLICY, context)?;
                let value = locate_analyzed(analyzed, entry.value().span(), references, context)?;
                Some(ReusableInputBinding::new(key, value))
            })
            .collect()
    });
    let secrets = compile_reusable_secrets(call, context)?;
    Some(ReusableWorkflowInvocation::new(
        reference,
        inputs,
        secrets,
        context.span(call.span())?,
    ))
}

fn compile_reusable_secrets(
    call: &ReusableWorkflowCall,
    context: &mut CompileContext<'_>,
) -> Option<ReusableSecretForwarding> {
    Some(match call.secrets() {
        None => ReusableSecretForwarding::Mapping(Vec::new()),
        Some(ReusableWorkflowSecrets::Inherit(span)) => {
            ReusableSecretForwarding::Inherit(context.span(span)?)
        }
        Some(ReusableWorkflowSecrets::Mapping(mapping)) => {
            let bindings = mapping
                .values()
                .entries()
                .iter()
                .filter_map(|entry| {
                    let target = match WorkflowSecretKey::new(entry.key().value()) {
                        Ok(key) => context.located(key, entry.key().span())?,
                        Err(error) => {
                            context.semantic(
                                "github.compile.invalid_reusable_secret_target",
                                error.to_string(),
                                entry.key().span().clone(),
                            );
                            return None;
                        }
                    };
                    let path = exact_reference_path(
                        entry.value().decoded(),
                        entry.value().span(),
                        REUSABLE_SECRET_POLICY,
                        context,
                    )?;
                    let [root, source] = path.as_slice() else {
                        context.unsupported(
                            "github.compile.reusable_secret_binding_shape",
                            "reusable secret bindings must be one exact `secrets.<name>` reference",
                            entry.value().span().clone(),
                        );
                        return None;
                    };
                    if root != "secrets" {
                        context.unsupported(
                            "github.compile.reusable_secret_binding_shape",
                            "reusable secret bindings must be one exact `secrets.<name>` reference",
                            entry.value().span().clone(),
                        );
                        return None;
                    }
                    let source = match WorkflowSecretKey::new(source) {
                        Ok(key) => context.located(key, entry.value().span())?,
                        Err(error) => {
                            context.semantic(
                                "github.compile.invalid_reusable_secret_source",
                                error.to_string(),
                                entry.value().span().clone(),
                            );
                            return None;
                        }
                    };
                    Some(ReusableSecretBinding::new(target, source))
                })
                .collect();
            ReusableSecretForwarding::Mapping(bindings)
        }
    })
}

fn compile_outputs(
    outputs: &ValueMap,
    has_strategy: bool,
    references: &mut BTreeMap<ParsedNeedReference, SourceSpan>,
    context: &mut CompileContext<'_>,
) -> Vec<LogicalJobOutputDefinition> {
    outputs
        .entries()
        .iter()
        .filter_map(|entry| {
            if entry.key().value().contains("${{") {
                context.semantic(
                    "github.compile.dynamic_output_key",
                    "job output names cannot contain expressions",
                    entry.key().span().clone(),
                );
                return None;
            }
            let key = match WorkflowOutputKey::new(entry.key().value()) {
                Ok(key) => context.located(key, entry.key().span())?,
                Err(error) => {
                    context.semantic(
                        "github.compile.invalid_output_key",
                        error.to_string(),
                        entry.key().span().clone(),
                    );
                    return None;
                }
            };
            let analyzed = compile_template(
                entry.value().decoded(),
                entry.value().span(),
                OUTPUT_POLICY,
                context,
            )?;
            let sensitivity = if analyzed
                .value
                .references_context(ExpressionContext::Secrets)
            {
                OutputSensitivity::SecretDerived
            } else {
                OutputSensitivity::Public
            };
            let value = locate_analyzed(analyzed, entry.value().span(), references, context)?;
            Some(LogicalJobOutputDefinition::new(
                key,
                LogicalJobOutputSource::Template(value),
                output_merge_policy(has_strategy),
                sensitivity,
                context.span(entry.value().span())?,
            ))
        })
        .collect()
}

fn compile_strategy(
    strategy: &JobStrategy,
    references: &mut BTreeMap<ParsedNeedReference, SourceSpan>,
    context: &mut CompileContext<'_>,
) -> Option<WorkflowStrategyTemplate> {
    context.reject_extensions(strategy.extensions());
    let fail_fast = strategy.fail_fast().and_then(|value| {
        let analyzed = compile_boolean_template(value, STRATEGY_POLICY, context)?;
        locate_analyzed(analyzed, boolean_span(value), references, context)
    });
    let max_parallel = strategy
        .max_parallel()
        .and_then(|value| compile_max_parallel(value, references, context));
    let Some(matrix) = strategy.matrix() else {
        context.semantic(
            "github.compile.strategy_matrix_required",
            "a retained strategy must define a matrix before it can affect execution",
            strategy.span().clone(),
        );
        return None;
    };
    let matrix = compile_matrix(matrix, references, context)?;
    Some(WorkflowStrategyTemplate::new(
        fail_fast,
        max_parallel,
        matrix,
        u16::try_from(MAX_MATRIX_EXPANSION).expect("matrix limit fits u16"),
        context.span(strategy.span())?,
    ))
}

fn compile_max_parallel(
    value: &ScalarValue,
    references: &mut BTreeMap<ParsedNeedReference, SourceSpan>,
    context: &mut CompileContext<'_>,
) -> Option<Located<CompiledPositiveIntegerTemplate>> {
    if value.contains_expression_candidate() {
        let analyzed = compile_positive_integer_template(value, STRATEGY_POLICY, context)?;
        return locate_analyzed(analyzed, value.span(), references, context);
    }
    let Ok(number) = value.decoded().parse::<u32>() else {
        context.semantic(
            "github.compile.invalid_max_parallel",
            "strategy max-parallel must be a positive integer or one complete expression",
            value.span().clone(),
        );
        return None;
    };
    if number == 0 {
        context.semantic(
            "github.compile.invalid_max_parallel",
            "strategy max-parallel must be greater than zero",
            value.span().clone(),
        );
        return None;
    }
    context.located(
        CompiledPositiveIntegerTemplate::Literal(number),
        value.span(),
    )
}

fn compile_matrix(
    matrix: &StrategyMatrix,
    references: &mut BTreeMap<ParsedNeedReference, SourceSpan>,
    context: &mut CompileContext<'_>,
) -> Option<MatrixTemplate> {
    match matrix {
        StrategyMatrix::Expression(expression) => {
            let analyzed = compile_single_expression(
                expression.decoded(),
                expression.span(),
                STRATEGY_POLICY,
                context,
            )?;
            let expression = locate_analyzed(analyzed, expression.span(), references, context)?;
            Some(MatrixTemplate::from_expression(
                expression,
                context.span(matrix.span())?,
            ))
        }
        StrategyMatrix::Mapping(matrix) => {
            context.reject_extensions(matrix.extensions());
            let axes = matrix
                .dimensions()
                .iter()
                .filter_map(|dimension| {
                    let name = if dimension.name().value().contains("${{") {
                        context.semantic(
                            "github.compile.dynamic_matrix_axis",
                            "matrix axis names cannot contain expressions",
                            dimension.name().span().clone(),
                        );
                        return None;
                    } else {
                        located_text(dimension.name(), context)?
                    };
                    let values = match dimension.values() {
                        MatrixDimensionValues::Expression(expression) => {
                            let analyzed = compile_single_expression(
                                expression.decoded(),
                                expression.span(),
                                STRATEGY_POLICY,
                                context,
                            )?;
                            MatrixAxisValues::Expression(locate_analyzed(
                                analyzed,
                                expression.span(),
                                references,
                                context,
                            )?)
                        }
                        MatrixDimensionValues::Sequence { values, .. } => {
                            let values = values
                                .iter()
                                .filter_map(|value| {
                                    let compiled = compile_matrix_value_template(
                                        value, true, references, context,
                                    )?;
                                    context.located(compiled, value.span())
                                })
                                .collect();
                            MatrixAxisValues::Static(values)
                        }
                    };
                    Some(MatrixAxis::new(
                        name,
                        values,
                        context.span(dimension.span())?,
                    ))
                })
                .collect();
            let include =
                compile_matrix_patch_set(matrix.include(), "include", references, context);
            let exclude =
                compile_matrix_patch_set(matrix.exclude(), "exclude", references, context);
            Some(MatrixTemplate::new(
                axes,
                include,
                exclude,
                context.span(matrix.span())?,
            ))
        }
    }
}

fn compile_matrix_patch_set(
    configurations: Option<&MatrixConfigurations>,
    field: &'static str,
    references: &mut BTreeMap<ParsedNeedReference, SourceSpan>,
    context: &mut CompileContext<'_>,
) -> MatrixPatchSet {
    match configurations {
        None => MatrixPatchSet::Static(Vec::new()),
        Some(MatrixConfigurations::Expression(expression)) => {
            let Some(analyzed) = compile_single_expression(
                expression.decoded(),
                expression.span(),
                STRATEGY_POLICY,
                context,
            ) else {
                return MatrixPatchSet::Static(Vec::new());
            };
            let Some(expression) =
                locate_analyzed(analyzed, expression.span(), references, context)
            else {
                return MatrixPatchSet::Static(Vec::new());
            };
            MatrixPatchSet::Expression(expression)
        }
        Some(MatrixConfigurations::Sequence {
            configurations,
            span,
        }) => {
            if configurations.is_empty() {
                context.semantic(
                    "github.compile.empty_matrix_configurations",
                    format!("matrix `{field}` must contain at least one configuration"),
                    span.clone(),
                );
            }
            MatrixPatchSet::Static(
                configurations
                    .iter()
                    .filter_map(|configuration| {
                        compile_matrix_patch(configuration, references, context)
                    })
                    .collect(),
            )
        }
    }
}

fn compile_matrix_patch(
    configuration: &MatrixConfiguration,
    references: &mut BTreeMap<ParsedNeedReference, SourceSpan>,
    context: &mut CompileContext<'_>,
) -> Option<MatrixPatch> {
    context.reject_extensions(configuration.extensions());
    let entries = configuration
        .entries()
        .iter()
        .filter_map(|entry| {
            if entry.key().value().contains("${{") {
                context.semantic(
                    "github.compile.dynamic_matrix_key",
                    "matrix configuration keys cannot contain expressions",
                    entry.key().span().clone(),
                );
                return None;
            }
            let key = located_text(entry.key(), context)?;
            let value = compile_matrix_value_template(entry.value(), true, references, context)?;
            let value = context.located(value, entry.value().span())?;
            Some((key, value))
        })
        .collect();
    Some(MatrixPatch::new(
        entries,
        context.span(configuration.span())?,
    ))
}

fn compile_matrix_value_template(
    value: &MatrixValue,
    allow_expression: bool,
    references: &mut BTreeMap<ParsedNeedReference, SourceSpan>,
    context: &mut CompileContext<'_>,
) -> Option<MatrixValueTemplate> {
    if let MatrixValue::Scalar(value) = value
        && value.contains_expression_candidate()
    {
        if !allow_expression {
            context.unsupported(
                "github.compile.nested_matrix_expression",
                "expressions nested inside matrix arrays or objects cannot be represented safely",
                value.span().clone(),
            );
            return None;
        }
        let analyzed =
            compile_single_expression(value.decoded(), value.span(), STRATEGY_POLICY, context)?;
        let expression = capture_references(analyzed, value.span(), references);
        return Some(MatrixValueTemplate::Expression(expression));
    }
    compile_matrix_literal(value, context).map(MatrixValueTemplate::Literal)
}

fn compile_matrix_literal(
    value: &MatrixValue,
    context: &mut CompileContext<'_>,
) -> Option<PlanMatrixValue> {
    match value {
        MatrixValue::Scalar(value) => compile_matrix_scalar(value, context),
        MatrixValue::Sequence { values, .. } => values
            .iter()
            .map(|value| {
                if matches!(value, MatrixValue::Scalar(value) if value.contains_expression_candidate())
                {
                    context.unsupported(
                        "github.compile.nested_matrix_expression",
                        "expressions nested inside matrix arrays or objects cannot be represented safely",
                        value.span().clone(),
                    );
                    return None;
                }
                compile_matrix_literal(value, context)
            })
            .collect::<Option<Vec<_>>>()
            .map(PlanMatrixValue::Array),
        MatrixValue::Mapping {
            entries,
            extensions,
            ..
        } => {
            context.reject_extensions(extensions);
            let mut compiled = entries
                .iter()
                .filter_map(|entry| {
                    if entry.key().value().contains("${{") {
                        context.semantic(
                            "github.compile.dynamic_matrix_key",
                            "matrix object keys cannot contain expressions",
                            entry.key().span().clone(),
                        );
                        return None;
                    }
                    if matches!(entry.value(), MatrixValue::Scalar(value) if value.contains_expression_candidate())
                    {
                        context.unsupported(
                            "github.compile.nested_matrix_expression",
                            "expressions nested inside matrix arrays or objects cannot be represented safely",
                            entry.value().span().clone(),
                        );
                        return None;
                    }
                    Some((
                        entry.key().value().clone(),
                        compile_matrix_literal(entry.value(), context)?,
                    ))
                })
                .collect::<Vec<_>>();
            compiled.sort_by(|left, right| left.0.cmp(&right.0));
            Some(PlanMatrixValue::Object(compiled))
        }
    }
}

fn compile_matrix_scalar(
    value: &ScalarValue,
    context: &mut CompileContext<'_>,
) -> Option<PlanMatrixValue> {
    Some(match value.resolution() {
        ScalarResolution::Null => PlanMatrixValue::Null,
        ScalarResolution::Boolean => {
            PlanMatrixValue::Boolean(value.decoded().eq_ignore_ascii_case("true"))
        }
        ScalarResolution::Integer | ScalarResolution::Float => {
            PlanMatrixValue::Number(normalize_matrix_number(value, context)?)
        }
        ScalarResolution::String => PlanMatrixValue::String(value.decoded().to_owned()),
    })
}

fn normalize_matrix_number(
    value: &ScalarValue,
    context: &mut CompileContext<'_>,
) -> Option<String> {
    let normalized = value.decoded();
    let negative = normalized.starts_with('-');
    let signed = normalized.strip_prefix(['+', '-']).unwrap_or(normalized);
    let converted = if let Some(hexadecimal) = signed.strip_prefix("0x") {
        u128::from_str_radix(hexadecimal, 16)
            .ok()
            .map(|number| number.to_string())
    } else if let Some(octal) = signed.strip_prefix("0o") {
        u128::from_str_radix(octal, 8)
            .ok()
            .map(|number| number.to_string())
    } else if value.resolution() == ScalarResolution::Integer {
        signed.parse::<u128>().ok().map(|number| number.to_string())
    } else {
        normalized
            .parse::<f64>()
            .ok()
            .filter(|number| number.is_finite())
            .map(|number| number.to_string())
    };
    let Some(mut converted) = converted else {
        context.unsupported(
            "github.compile.matrix_number_representation",
            "matrix number cannot be represented as a finite durable decimal",
            value.span().clone(),
        );
        return None;
    };
    if negative && converted != "0" {
        converted.insert(0, '-');
    }
    Some(converted)
}
