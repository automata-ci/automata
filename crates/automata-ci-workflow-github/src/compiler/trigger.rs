use std::collections::{BTreeMap, BTreeSet};

use automata_ci_core::{ContextValue, PlanSourceSpan, WorkflowEventProvenance, WorkflowInputKey};

use crate::{
    EventName, GithubChangedFilesV1, GithubEventMetadataV1, GithubWorkflowDispatchContract,
    GithubWorkflowDispatchInputDefault, GithubWorkflowDispatchInputDefinition,
    GithubWorkflowDispatchInputType, GithubWorkflowDispatchInputValue,
    MAX_GITHUB_WORKFLOW_DISPATCH_INPUTS, PushPullRequestFilter, ScalarResolution, SourceSpan,
    Spanned, TriggerConfiguration, YamlMappingEntry, YamlNode,
};

use super::{CompileContext, CompiledEvent, CompiledWorkflowDispatch, WorkflowNotSelectedReason};

const DEFAULT_PULL_REQUEST_ACTIONS: &[&str] = &["opened", "synchronize", "reopened"];
const MAX_PATTERN_BYTES: usize = 4_096;
const MAX_CANDIDATE_BYTES: usize = 4_096;
const MAX_CHANGED_FILES: usize = 3_000;
const MAX_CHANGED_FILE_BYTES: usize = MAX_CHANGED_FILES * MAX_CANDIDATE_BYTES;

pub(super) enum TriggerSelection {
    Selected(Option<CompiledWorkflowDispatch>),
    RequiresChangedFiles,
    NotSelected(WorkflowNotSelectedReason),
    Rejected,
}

impl TriggerSelection {
    pub(super) fn with_event(
        self,
        event: WorkflowEventProvenance,
        span: PlanSourceSpan,
    ) -> CompiledEvent {
        match self {
            Self::Selected(workflow_dispatch) => CompiledEvent::Selected {
                event: event.with_configured_trigger_span(span),
                workflow_dispatch: workflow_dispatch.map(Box::new),
            },
            Self::RequiresChangedFiles => CompiledEvent::RequiresChangedFiles,
            Self::NotSelected(reason) => CompiledEvent::NotSelected(reason),
            Self::Rejected => CompiledEvent::Rejected,
        }
    }
}

pub(super) fn validate_configuration(
    event_name: &EventName,
    configuration: &TriggerConfiguration,
    trigger_span: &SourceSpan,
    context: &mut CompileContext<'_>,
) -> Option<GithubWorkflowDispatchContract> {
    match configuration {
        TriggerConfiguration::Push(filter) => {
            validate_filter(filter, false, trigger_span, context);
            None
        }
        TriggerConfiguration::PullRequest(filter) => {
            validate_filter(filter, true, trigger_span, context);
            if filter.tags_configured() || filter.tags_ignore_configured() {
                context.semantic(
                    "github.compile.pull_request_tag_filter",
                    "GitHub pull_request triggers do not support tag filters",
                    trigger_span.clone(),
                );
            }
            None
        }
        TriggerConfiguration::WorkflowDispatch(Some(configuration)) => {
            compile_workflow_dispatch_contract(configuration, context)
        }
        TriggerConfiguration::WorkflowDispatch(None) => {
            Some(GithubWorkflowDispatchContract::default())
        }
        TriggerConfiguration::Schedule(configuration) => {
            validate_schedule(configuration, context);
            None
        }
        TriggerConfiguration::WorkflowCall(configuration) => {
            validate_workflow_call(configuration, context);
            None
        }
        TriggerConfiguration::Empty => {
            if matches!(event_name, EventName::Schedule) {
                context.semantic(
                    "github.compile.schedule_configuration_required",
                    "`on.schedule` requires at least one configured cron entry",
                    trigger_span.clone(),
                );
            }
            if matches!(event_name, EventName::WorkflowDispatch) {
                Some(GithubWorkflowDispatchContract::default())
            } else {
                None
            }
        }
        TriggerConfiguration::Preserved(_) => None,
    }
}

pub(super) fn event_matches(
    event: &WorkflowEventProvenance,
    configuration: &TriggerConfiguration,
    workflow_dispatch_contract: Option<&GithubWorkflowDispatchContract>,
    metadata: Option<&GithubEventMetadataV1>,
    trigger_span: &SourceSpan,
    context: &mut CompileContext<'_>,
) -> TriggerSelection {
    match event.name() {
        "push" => push_matches(event, configuration, metadata, trigger_span, context),
        "pull_request" => pull_request_matches(configuration, metadata, trigger_span, context),
        "merge_group" => merge_group_matches(configuration, metadata, trigger_span, context),
        "workflow_dispatch" => {
            workflow_dispatch_matches(workflow_dispatch_contract, metadata, trigger_span, context)
        }
        "schedule" => schedule_matches(configuration, metadata, trigger_span, context),
        _ => {
            if metadata.is_some() {
                metadata_mismatch(event.name(), trigger_span, context);
                TriggerSelection::Rejected
            } else {
                TriggerSelection::Selected(None)
            }
        }
    }
}

fn merge_group_matches(
    configuration: &TriggerConfiguration,
    metadata: Option<&GithubEventMetadataV1>,
    trigger_span: &SourceSpan,
    context: &mut CompileContext<'_>,
) -> TriggerSelection {
    let (action, base_ref) = match metadata {
        Some(GithubEventMetadataV1::MergeGroup { action, base_ref }) => {
            (action.as_str(), base_ref.as_str())
        }
        Some(_) => {
            metadata_mismatch("merge_group", trigger_span, context);
            return TriggerSelection::Rejected;
        }
        None => {
            missing_metadata("merge_group", trigger_span, context);
            return TriggerSelection::Rejected;
        }
    };
    if action.is_empty()
        || action.len() > MAX_CANDIDATE_BYTES
        || GithubRef::parse(base_ref).is_none()
        || base_ref.len() > MAX_CANDIDATE_BYTES
    {
        context.semantic(
            "github.compile.invalid_merge_group_metadata",
            "merge_group metadata requires a bounded action and fully qualified base branch ref",
            trigger_span.clone(),
        );
        return TriggerSelection::Rejected;
    }
    if !matches!(configuration, TriggerConfiguration::Empty) {
        context.semantic(
            "github.compile.unsupported_merge_group_configuration",
            "this compiler version accepts merge_group only without event configuration",
            trigger_span.clone(),
        );
        return TriggerSelection::Rejected;
    }
    match action {
        "checks_requested" => TriggerSelection::Selected(None),
        "destroyed" => {
            TriggerSelection::NotSelected(WorkflowNotSelectedReason::EventFiltersNotMatched)
        }
        _ => {
            context.semantic(
                "github.compile.invalid_merge_group_action",
                "merge_group metadata contains an unsupported action",
                trigger_span.clone(),
            );
            TriggerSelection::Rejected
        }
    }
}

fn compile_workflow_dispatch_contract(
    configuration: &YamlNode,
    context: &mut CompileContext<'_>,
) -> Option<GithubWorkflowDispatchContract> {
    if configuration
        .as_scalar()
        .is_some_and(crate::YamlScalar::is_null)
    {
        return Some(GithubWorkflowDispatchContract::default());
    }
    let Some(entries) = configuration.as_mapping() else {
        context.semantic(
            "github.compile.invalid_workflow_dispatch_configuration",
            "`on.workflow_dispatch` must be null or a mapping",
            configuration.span().clone(),
        );
        return None;
    };

    let mut inputs = None;
    for entry in entries {
        match dispatch_mapping_key(entry, "on.workflow_dispatch", context).as_deref() {
            Some("inputs") => {
                if inputs.replace(entry.value()).is_some() {
                    context.semantic(
                        "github.compile.duplicate_workflow_dispatch_field",
                        "`on.workflow_dispatch` fields must be unique",
                        entry.key().span().clone(),
                    );
                }
            }
            Some(field) => context.unsupported(
                "github.compile.workflow_dispatch_configuration",
                format!("`on.workflow_dispatch.{field}` is not supported by this frontend version"),
                entry.key().span().clone(),
            ),
            None => {}
        }
    }

    match inputs {
        Some(inputs) => compile_workflow_dispatch_inputs(inputs, context),
        None => Some(GithubWorkflowDispatchContract::default()),
    }
}

fn compile_workflow_dispatch_inputs(
    node: &YamlNode,
    context: &mut CompileContext<'_>,
) -> Option<GithubWorkflowDispatchContract> {
    let Some(entries) = node.as_mapping() else {
        context.semantic(
            "github.compile.invalid_event_contract",
            "`on.workflow_dispatch.inputs` must be a mapping",
            node.span().clone(),
        );
        return None;
    };
    if entries.len() > MAX_GITHUB_WORKFLOW_DISPATCH_INPUTS {
        context.semantic(
            "github.compile.too_many_workflow_dispatch_inputs",
            format!(
                "`on.workflow_dispatch.inputs` may contain at most {MAX_GITHUB_WORKFLOW_DISPATCH_INPUTS} definitions"
            ),
            node.span().clone(),
        );
    }

    let mut inputs = BTreeMap::new();
    for entry in entries {
        let Some((key, definition)) = compile_workflow_dispatch_input(entry, context) else {
            continue;
        };
        if inputs.insert(key, definition).is_some() {
            context.semantic(
                "github.compile.duplicate_workflow_dispatch_input",
                "`on.workflow_dispatch.inputs` identifiers must be unique",
                entry.key().span().clone(),
            );
        }
    }
    Some(GithubWorkflowDispatchContract::new(inputs))
}

fn compile_workflow_dispatch_input(
    entry: &YamlMappingEntry,
    context: &mut CompileContext<'_>,
) -> Option<(WorkflowInputKey, GithubWorkflowDispatchInputDefinition)> {
    let raw_key = dispatch_mapping_key(entry, "on.workflow_dispatch.inputs", context)?;
    let key = WorkflowInputKey::new(raw_key)
        .map_err(|error| {
            context.semantic(
                "github.compile.invalid_workflow_dispatch_input_key",
                error.to_string(),
                entry.key().span().clone(),
            );
        })
        .ok()?;
    let Some(entries) = entry.value().as_mapping() else {
        context.semantic(
            "github.compile.invalid_workflow_dispatch_input_definition",
            "each `on.workflow_dispatch.inputs` definition must be a mapping",
            entry.value().span().clone(),
        );
        return None;
    };

    let mut fields = BTreeMap::new();
    for field in entries {
        let Some(name) =
            dispatch_mapping_key(field, "on.workflow_dispatch.inputs.<input>", context)
        else {
            continue;
        };
        if !["type", "required", "default", "options", "description"].contains(&name.as_str()) {
            context.unsupported(
                "github.compile.workflow_dispatch_input_field",
                format!("`on.workflow_dispatch.inputs.<input>.{name}` is not supported"),
                field.key().span().clone(),
            );
            continue;
        }
        if fields.insert(name, field.value()).is_some() {
            context.semantic(
                "github.compile.duplicate_workflow_dispatch_input_field",
                "workflow_dispatch input definition fields must be unique",
                field.key().span().clone(),
            );
        }
    }

    let Some(type_node) = fields.get("type") else {
        context.semantic(
            "github.compile.workflow_dispatch_input_type_required",
            "every `on.workflow_dispatch` input requires `type`",
            entry.value().span().clone(),
        );
        return None;
    };
    let input_type = compile_workflow_dispatch_input_type(type_node, context)?;
    let required = match fields.get("required") {
        Some(node) => dispatch_boolean(node, "workflow_dispatch input required", context)?,
        None => false,
    };
    let description = match fields.get("description") {
        Some(node) => Some(dispatch_text(
            node,
            "workflow_dispatch input description",
            context,
        )?),
        None => None,
    };
    let options = compile_workflow_dispatch_options(
        input_type,
        fields.get("options").copied(),
        entry.value(),
        context,
    )?;
    let default = match fields.get("default") {
        Some(node) => Some(compile_workflow_dispatch_default(
            input_type, node, &options, context,
        )?),
        None => None,
    };

    Some((
        key,
        GithubWorkflowDispatchInputDefinition::new(
            input_type,
            required,
            default,
            options,
            description,
        ),
    ))
}

fn compile_workflow_dispatch_input_type(
    node: &YamlNode,
    context: &mut CompileContext<'_>,
) -> Option<GithubWorkflowDispatchInputType> {
    let value = dispatch_text(node, "workflow_dispatch input type", context)?;
    match value.as_str() {
        "boolean" => Some(GithubWorkflowDispatchInputType::Boolean),
        "choice" => Some(GithubWorkflowDispatchInputType::Choice),
        "string" => Some(GithubWorkflowDispatchInputType::String),
        _ => {
            context.unsupported(
                "github.compile.unsupported_workflow_dispatch_input_type",
                "workflow_dispatch input types currently support `boolean`, `choice`, and `string`",
                node.span().clone(),
            );
            None
        }
    }
}

fn compile_workflow_dispatch_options(
    input_type: GithubWorkflowDispatchInputType,
    node: Option<&YamlNode>,
    definition: &YamlNode,
    context: &mut CompileContext<'_>,
) -> Option<Vec<String>> {
    if input_type != GithubWorkflowDispatchInputType::Choice {
        if let Some(node) = node {
            context.semantic(
                "github.compile.workflow_dispatch_options_require_choice",
                "workflow_dispatch `options` may be declared only for a `choice` input",
                node.span().clone(),
            );
            return None;
        }
        return Some(Vec::new());
    }
    let Some(node) = node else {
        context.semantic(
            "github.compile.workflow_dispatch_choice_options_required",
            "workflow_dispatch choice inputs require a non-empty `options` sequence",
            definition.span().clone(),
        );
        return None;
    };
    let Some(entries) = node.as_sequence() else {
        context.semantic(
            "github.compile.invalid_workflow_dispatch_options",
            "workflow_dispatch choice `options` must be a non-empty sequence of strings",
            node.span().clone(),
        );
        return None;
    };
    if entries.is_empty() {
        context.semantic(
            "github.compile.invalid_workflow_dispatch_options",
            "workflow_dispatch choice `options` must not be empty",
            node.span().clone(),
        );
        return None;
    }
    let mut options = Vec::with_capacity(entries.len());
    let mut seen = BTreeSet::new();
    for entry in entries {
        let option = dispatch_text(entry, "workflow_dispatch choice option", context)?;
        if !seen.insert(option.clone()) {
            context.semantic(
                "github.compile.duplicate_workflow_dispatch_option",
                "workflow_dispatch choice options must be unique",
                entry.span().clone(),
            );
            return None;
        }
        options.push(option);
    }
    Some(options)
}

fn compile_workflow_dispatch_default(
    input_type: GithubWorkflowDispatchInputType,
    node: &YamlNode,
    options: &[String],
    context: &mut CompileContext<'_>,
) -> Option<GithubWorkflowDispatchInputDefault> {
    match input_type {
        GithubWorkflowDispatchInputType::Boolean => {
            dispatch_boolean(node, "workflow_dispatch boolean default", context)
                .map(GithubWorkflowDispatchInputDefault::Boolean)
        }
        GithubWorkflowDispatchInputType::Choice => {
            let value = dispatch_text(node, "workflow_dispatch choice default", context)?;
            if options.contains(&value) {
                Some(GithubWorkflowDispatchInputDefault::String(value))
            } else {
                context.semantic(
                    "github.compile.workflow_dispatch_choice_default_not_allowed",
                    "workflow_dispatch choice defaults must exactly match one configured option",
                    node.span().clone(),
                );
                None
            }
        }
        GithubWorkflowDispatchInputType::String => {
            dispatch_text(node, "workflow_dispatch string default", context)
                .map(GithubWorkflowDispatchInputDefault::String)
        }
    }
}

fn dispatch_mapping_key(
    entry: &YamlMappingEntry,
    path: &str,
    context: &mut CompileContext<'_>,
) -> Option<String> {
    let Some(scalar) = entry.key().as_scalar() else {
        context.semantic(
            "github.compile.invalid_workflow_dispatch_key",
            format!("`{path}` field names must be non-empty strings"),
            entry.key().span().clone(),
        );
        return None;
    };
    if scalar.resolution() != ScalarResolution::String || scalar.decoded().is_empty() {
        context.semantic(
            "github.compile.invalid_workflow_dispatch_key",
            format!("`{path}` field names must be non-empty strings"),
            entry.key().span().clone(),
        );
        return None;
    }
    Some(scalar.decoded().to_owned())
}

fn dispatch_text(node: &YamlNode, field: &str, context: &mut CompileContext<'_>) -> Option<String> {
    let Some(scalar) = node.as_scalar() else {
        context.semantic(
            "github.compile.invalid_workflow_dispatch_string",
            format!("{field} must be a YAML string"),
            node.span().clone(),
        );
        return None;
    };
    if scalar.resolution() != ScalarResolution::String {
        context.semantic(
            "github.compile.invalid_workflow_dispatch_string",
            format!("{field} must be a YAML string"),
            node.span().clone(),
        );
        return None;
    }
    Some(scalar.decoded().to_owned())
}

fn dispatch_boolean(
    node: &YamlNode,
    field: &str,
    context: &mut CompileContext<'_>,
) -> Option<bool> {
    let Some(scalar) = node.as_scalar() else {
        context.semantic(
            "github.compile.invalid_workflow_dispatch_boolean",
            format!("{field} must be a YAML boolean"),
            node.span().clone(),
        );
        return None;
    };
    if scalar.resolution() != ScalarResolution::Boolean {
        context.semantic(
            "github.compile.invalid_workflow_dispatch_boolean",
            format!("{field} must be a YAML boolean"),
            node.span().clone(),
        );
        return None;
    }
    Some(scalar.decoded().eq_ignore_ascii_case("true"))
}

fn workflow_dispatch_matches(
    contract: Option<&GithubWorkflowDispatchContract>,
    metadata: Option<&GithubEventMetadataV1>,
    trigger_span: &SourceSpan,
    context: &mut CompileContext<'_>,
) -> TriggerSelection {
    let Some(contract) = contract else {
        return TriggerSelection::Rejected;
    };
    let inputs = match metadata {
        Some(GithubEventMetadataV1::WorkflowDispatch { inputs }) => inputs,
        Some(_) => {
            metadata_mismatch("workflow_dispatch", trigger_span, context);
            return TriggerSelection::Rejected;
        }
        None if contract.is_empty() => {
            return TriggerSelection::Selected(Some(CompiledWorkflowDispatch {
                contract: contract.clone(),
                inputs: ContextValue::empty_object(),
            }));
        }
        None => {
            missing_metadata("workflow_dispatch", trigger_span, context);
            return TriggerSelection::Rejected;
        }
    };
    let Some(inputs) = resolve_workflow_dispatch_inputs(contract, inputs, trigger_span, context)
    else {
        return TriggerSelection::Rejected;
    };
    TriggerSelection::Selected(Some(CompiledWorkflowDispatch {
        contract: contract.clone(),
        inputs,
    }))
}

fn resolve_workflow_dispatch_inputs(
    contract: &GithubWorkflowDispatchContract,
    payload: &crate::GithubWorkflowDispatchInputsV1,
    trigger_span: &SourceSpan,
    context: &mut CompileContext<'_>,
) -> Option<ContextValue> {
    let mut valid = true;
    for key in payload.values().keys() {
        if !contract.inputs().contains_key(key) {
            context.semantic(
                "github.compile.unknown_workflow_dispatch_input",
                format!("verified workflow_dispatch payload supplied undeclared input `{key}`"),
                trigger_span.clone(),
            );
            valid = false;
        }
    }

    let mut values = BTreeMap::new();
    for (key, definition) in contract.inputs() {
        let value = match payload.values().get(key) {
            Some(value) => {
                coerce_workflow_dispatch_input(key, definition, value, trigger_span, context)
            }
            None => default_workflow_dispatch_input(key, definition, trigger_span, context),
        };
        match value {
            Some(value) => {
                values.insert(key.as_str().to_owned(), value);
            }
            None => valid = false,
        }
    }
    if !valid {
        return None;
    }
    ContextValue::object(values)
        .map_err(|error| {
            context.semantic(
                "github.compile.invalid_workflow_dispatch_context",
                error.to_string(),
                trigger_span.clone(),
            );
        })
        .ok()
}

fn coerce_workflow_dispatch_input(
    key: &WorkflowInputKey,
    definition: &GithubWorkflowDispatchInputDefinition,
    value: &GithubWorkflowDispatchInputValue,
    trigger_span: &SourceSpan,
    context: &mut CompileContext<'_>,
) -> Option<ContextValue> {
    match (definition.input_type(), value) {
        (
            GithubWorkflowDispatchInputType::Boolean,
            GithubWorkflowDispatchInputValue::Boolean(value),
        ) => Some(ContextValue::boolean(*value)),
        (
            GithubWorkflowDispatchInputType::Boolean,
            GithubWorkflowDispatchInputValue::String(value),
        ) => match value.as_str() {
            "true" => Some(ContextValue::boolean(true)),
            "false" => Some(ContextValue::boolean(false)),
            _ => {
                context.semantic(
                    "github.compile.invalid_workflow_dispatch_boolean_input",
                    format!("workflow_dispatch Boolean input `{key}` must be `true` or `false`"),
                    trigger_span.clone(),
                );
                None
            }
        },
        (
            GithubWorkflowDispatchInputType::String,
            GithubWorkflowDispatchInputValue::String(value),
        ) => Some(ContextValue::string(value.clone())),
        (
            GithubWorkflowDispatchInputType::Choice,
            GithubWorkflowDispatchInputValue::String(value),
        ) => {
            if definition.options().contains(value) {
                Some(ContextValue::string(value.clone()))
            } else {
                context.semantic(
                    "github.compile.invalid_workflow_dispatch_choice_input",
                    format!("workflow_dispatch choice input `{key}` must exactly match one configured option"),
                    trigger_span.clone(),
                );
                None
            }
        }
        (
            GithubWorkflowDispatchInputType::String | GithubWorkflowDispatchInputType::Choice,
            GithubWorkflowDispatchInputValue::Boolean(_),
        ) => {
            context.semantic(
                "github.compile.workflow_dispatch_input_type_mismatch",
                format!("workflow_dispatch input `{key}` requires a string payload value"),
                trigger_span.clone(),
            );
            None
        }
    }
}

fn default_workflow_dispatch_input(
    key: &WorkflowInputKey,
    definition: &GithubWorkflowDispatchInputDefinition,
    trigger_span: &SourceSpan,
    context: &mut CompileContext<'_>,
) -> Option<ContextValue> {
    match definition.default() {
        Some(GithubWorkflowDispatchInputDefault::Boolean(value)) => {
            Some(ContextValue::boolean(*value))
        }
        Some(GithubWorkflowDispatchInputDefault::String(value)) => {
            Some(ContextValue::string(value.clone()))
        }
        None if definition.required() => {
            context.semantic(
                "github.compile.required_workflow_dispatch_input_missing",
                format!("verified workflow_dispatch payload omitted required input `{key}`"),
                trigger_span.clone(),
            );
            None
        }
        None => match definition.input_type() {
            GithubWorkflowDispatchInputType::Boolean => Some(ContextValue::boolean(false)),
            GithubWorkflowDispatchInputType::String | GithubWorkflowDispatchInputType::Choice => {
                Some(ContextValue::string(String::new()))
            }
        },
    }
}

fn validate_workflow_call(configuration: &YamlNode, context: &mut CompileContext<'_>) {
    if configuration
        .as_scalar()
        .is_some_and(crate::YamlScalar::is_null)
    {
        return;
    }
    let Some(entries) = configuration.as_mapping() else {
        context.semantic(
            "github.compile.invalid_workflow_call_configuration",
            "`on.workflow_call` must be null or a mapping",
            configuration.span().clone(),
        );
        return;
    };

    for entry in entries {
        let Some(field) = mapping_key(entry) else {
            context.semantic(
                "github.compile.invalid_workflow_call_configuration",
                "`on.workflow_call` field names must be scalar text",
                entry.key().span().clone(),
            );
            continue;
        };
        match field {
            "inputs" | "secrets" | "outputs" => validate_contract_mapping(
                entry.value(),
                &format!("on.workflow_call.{field}"),
                context,
            ),
            field => {
                context.unsupported(
                    "github.compile.workflow_call_configuration",
                    format!("`on.workflow_call.{field}` is not supported by this frontend version"),
                    entry.key().span().clone(),
                );
            }
        }
    }
}

fn validate_contract_mapping(node: &YamlNode, path: &str, context: &mut CompileContext<'_>) {
    if node.as_mapping().is_none() {
        context.semantic(
            "github.compile.invalid_event_contract",
            format!("`{path}` must be a mapping"),
            node.span().clone(),
        );
    }
}

fn validate_schedule(configuration: &YamlNode, context: &mut CompileContext<'_>) {
    let Some(entries) = configuration.as_sequence() else {
        context.semantic(
            "github.compile.invalid_schedule_configuration",
            "`on.schedule` must be a sequence of cron mappings",
            configuration.span().clone(),
        );
        return;
    };
    if entries.is_empty() {
        context.semantic(
            "github.compile.empty_schedule",
            "`on.schedule` must contain at least one cron entry",
            configuration.span().clone(),
        );
    }

    for entry in entries {
        validate_schedule_entry(entry, context);
    }
}

fn validate_schedule_entry(entry: &YamlNode, context: &mut CompileContext<'_>) {
    let Some(fields) = entry.as_mapping() else {
        context.semantic(
            "github.compile.invalid_schedule_entry",
            "each `on.schedule` entry must be a mapping containing `cron`",
            entry.span().clone(),
        );
        return;
    };
    let mut cron_count = 0_u8;
    for field in fields {
        match mapping_key(field) {
            Some("cron") => {
                cron_count = cron_count.saturating_add(1);
                validate_cron_scalar(field.value(), context);
            }
            Some("timezone") => context.unsupported(
                "github.compile.schedule_timezone_requires_scheduler_support",
                "timezone-aware schedules require scheduler timezone and daylight-saving semantics",
                field.value().span().clone(),
            ),
            Some(name) => context.unsupported(
                "github.compile.schedule_configuration",
                format!("`on.schedule[].{name}` is not supported by this frontend version"),
                field.key().span().clone(),
            ),
            None => context.semantic(
                "github.compile.invalid_schedule_entry",
                "`on.schedule` field names must be scalar text",
                field.key().span().clone(),
            ),
        }
    }
    if cron_count == 0 {
        context.semantic(
            "github.compile.schedule_cron_required",
            "each `on.schedule` entry must contain `cron`",
            entry.span().clone(),
        );
    }
}

fn validate_cron_scalar(node: &YamlNode, context: &mut CompileContext<'_>) {
    let Some(scalar) = node.as_scalar().filter(|scalar| !scalar.is_null()) else {
        context.semantic(
            "github.compile.invalid_schedule_cron",
            "`on.schedule[].cron` must be a non-null scalar",
            node.span().clone(),
        );
        return;
    };
    let cron = scalar.decoded();
    if cron.len() > MAX_CANDIDATE_BYTES {
        context.semantic(
            "github.compile.schedule_cron_too_long",
            "schedule cron expressions must not exceed 4096 bytes",
            node.span().clone(),
        );
    } else if cron.split_ascii_whitespace().count() != 5 {
        context.semantic(
            "github.compile.invalid_schedule_cron",
            "GitHub schedule cron expressions must contain exactly five fields",
            node.span().clone(),
        );
    }
}

fn schedule_matches(
    configuration: &TriggerConfiguration,
    metadata: Option<&GithubEventMetadataV1>,
    trigger_span: &SourceSpan,
    context: &mut CompileContext<'_>,
) -> TriggerSelection {
    let cron = match metadata {
        Some(GithubEventMetadataV1::Schedule { cron }) => cron.as_str(),
        Some(_) => {
            metadata_mismatch("schedule", trigger_span, context);
            return TriggerSelection::Rejected;
        }
        None => {
            missing_metadata("schedule", trigger_span, context);
            return TriggerSelection::Rejected;
        }
    };
    if cron.is_empty() || cron.len() > MAX_CANDIDATE_BYTES {
        context.semantic(
            "github.compile.invalid_schedule_metadata",
            "schedule metadata requires a non-empty cron expression of at most 4096 bytes",
            trigger_span.clone(),
        );
        return TriggerSelection::Rejected;
    }

    let matched = match configuration {
        TriggerConfiguration::Schedule(configuration) => configuration
            .as_sequence()
            .into_iter()
            .flatten()
            .filter_map(YamlNode::as_mapping)
            .flatten()
            .filter(|field| mapping_key(field) == Some("cron"))
            .filter_map(|field| field.value().as_scalar())
            .any(|configured| configured.decoded() == cron),
        _ => false,
    };
    if matched {
        TriggerSelection::Selected(None)
    } else {
        TriggerSelection::NotSelected(WorkflowNotSelectedReason::ScheduleNotConfigured)
    }
}

fn mapping_key(entry: &YamlMappingEntry) -> Option<&str> {
    entry.key().as_scalar().map(crate::YamlScalar::decoded)
}

fn validate_filter(
    filter: &PushPullRequestFilter,
    allow_types: bool,
    trigger_span: &SourceSpan,
    context: &mut CompileContext<'_>,
) {
    validate_mutually_exclusive_filters(
        "branches",
        filter.branches_configured(),
        "branches-ignore",
        filter.branches_ignore_configured(),
        trigger_span,
        context,
    );
    validate_mutually_exclusive_filters(
        "tags",
        filter.tags_configured(),
        "tags-ignore",
        filter.tags_ignore_configured(),
        trigger_span,
        context,
    );
    validate_mutually_exclusive_filters(
        "paths",
        filter.paths_configured(),
        "paths-ignore",
        filter.paths_ignore_configured(),
        trigger_span,
        context,
    );
    validate_pattern_list(
        "branches",
        filter.branches_configured(),
        filter.branches(),
        true,
        trigger_span,
        context,
    );
    validate_pattern_list(
        "branches-ignore",
        filter.branches_ignore_configured(),
        filter.branches_ignore(),
        false,
        trigger_span,
        context,
    );
    validate_pattern_list(
        "tags",
        filter.tags_configured(),
        filter.tags(),
        true,
        trigger_span,
        context,
    );
    validate_pattern_list(
        "tags-ignore",
        filter.tags_ignore_configured(),
        filter.tags_ignore(),
        false,
        trigger_span,
        context,
    );

    validate_pattern_list(
        "paths",
        filter.paths_configured(),
        filter.paths(),
        true,
        trigger_span,
        context,
    );
    validate_pattern_list(
        "paths-ignore",
        filter.paths_ignore_configured(),
        filter.paths_ignore(),
        false,
        trigger_span,
        context,
    );

    if allow_types && filter.types_configured() && filter.types().is_empty() {
        context.semantic(
            "github.compile.empty_event_filter",
            "`on.pull_request.types` must contain at least one activity type",
            trigger_span.clone(),
        );
    }
    for activity in filter.types() {
        if activity.value().is_empty() {
            context.semantic(
                "github.compile.empty_event_filter_value",
                "`on.pull_request.types` values must not be empty",
                activity.span().clone(),
            );
        }
    }
}

fn validate_mutually_exclusive_filters(
    include_name: &str,
    include_configured: bool,
    ignore_name: &str,
    ignore_configured: bool,
    trigger_span: &SourceSpan,
    context: &mut CompileContext<'_>,
) {
    if include_configured && ignore_configured {
        context.semantic(
            "github.compile.mutually_exclusive_filters",
            format!(
                "`on.<event>.{include_name}` and `on.<event>.{ignore_name}` cannot both be configured"
            ),
            trigger_span.clone(),
        );
    }
}

fn validate_pattern_list(
    name: &str,
    configured: bool,
    patterns: &[Spanned<String>],
    allow_negative: bool,
    trigger_span: &SourceSpan,
    context: &mut CompileContext<'_>,
) {
    if !configured {
        return;
    }
    if patterns.is_empty() {
        context.semantic(
            "github.compile.empty_event_filter",
            format!("`on.<event>.{name}` must contain at least one pattern"),
            trigger_span.clone(),
        );
        return;
    }

    let mut has_positive = false;
    for pattern in patterns {
        match GithubGlob::parse(pattern.value()) {
            Ok(parsed) => {
                if parsed.negative {
                    if !allow_negative {
                        context.semantic(
                            "github.compile.negative_ignore_pattern",
                            format!(
                                "`on.<event>.{name}` cannot contain a leading `!`; use positive ignore patterns"
                            ),
                            pattern.span().clone(),
                        );
                    }
                } else {
                    has_positive = true;
                }
            }
            Err(message) => context.semantic(
                "github.compile.invalid_filter_pattern",
                format!(
                    "invalid GitHub filter pattern `{}`: {message}",
                    pattern.value()
                ),
                pattern.span().clone(),
            ),
        }
    }
    if allow_negative && !has_positive {
        context.semantic(
            "github.compile.negative_filter_without_positive",
            format!("`on.<event>.{name}` must contain a positive pattern before exclusions"),
            patterns[0].span().clone(),
        );
    }
}

fn push_matches(
    event: &WorkflowEventProvenance,
    configuration: &TriggerConfiguration,
    metadata: Option<&GithubEventMetadataV1>,
    trigger_span: &SourceSpan,
    context: &mut CompileContext<'_>,
) -> TriggerSelection {
    let (deleted, changed_files) = match metadata {
        Some(GithubEventMetadataV1::Push {
            deleted,
            changed_files,
        }) => (*deleted, changed_files.as_ref()),
        Some(_) => {
            metadata_mismatch("push", trigger_span, context);
            return TriggerSelection::Rejected;
        }
        None => {
            missing_metadata("push", trigger_span, context);
            return TriggerSelection::Rejected;
        }
    };
    if deleted {
        return TriggerSelection::NotSelected(WorkflowNotSelectedReason::DeletedPush);
    }

    let Some(git_ref) = event.git_ref() else {
        context.semantic(
            "github.compile.push_ref_required",
            "GitHub push selection requires the payload's fully qualified `ref`",
            trigger_span.clone(),
        );
        return TriggerSelection::Rejected;
    };
    if git_ref.len() > MAX_CANDIDATE_BYTES {
        context.semantic(
            "github.compile.push_ref_too_long",
            "GitHub push ref exceeds the supported 4096-byte selection limit",
            trigger_span.clone(),
        );
        return TriggerSelection::Rejected;
    }
    let Some(reference) = GithubRef::parse(git_ref) else {
        context.semantic(
            "github.compile.invalid_push_ref",
            "GitHub push refs must be non-empty `refs/heads/<name>` or `refs/tags/<name>` values",
            trigger_span.clone(),
        );
        return TriggerSelection::Rejected;
    };

    let matched = match configuration {
        TriggerConfiguration::Push(filter) => match reference {
            GithubRef::Branch(name) => {
                let reference_matches = ref_filter_matches(
                    name,
                    filter.branches_configured(),
                    filter.branches(),
                    filter.branches_ignore_configured(),
                    filter.branches_ignore(),
                    filter.tags_configured() || filter.tags_ignore_configured(),
                );
                if reference_matches {
                    match path_filter_matches(filter, changed_files, trigger_span, context) {
                        PathFilterSelection::Matched(paths_match) => paths_match,
                        PathFilterSelection::RequiresChangedFiles => {
                            return TriggerSelection::RequiresChangedFiles;
                        }
                        PathFilterSelection::Rejected => return TriggerSelection::Rejected,
                    }
                } else {
                    false
                }
            }
            GithubRef::Tag(name) => ref_filter_matches(
                name,
                filter.tags_configured(),
                filter.tags(),
                filter.tags_ignore_configured(),
                filter.tags_ignore(),
                filter.branches_configured() || filter.branches_ignore_configured(),
            ),
        },
        TriggerConfiguration::Empty => true,
        _ => false,
    };
    if matched {
        TriggerSelection::Selected(None)
    } else {
        TriggerSelection::NotSelected(WorkflowNotSelectedReason::EventFiltersNotMatched)
    }
}

fn pull_request_matches(
    configuration: &TriggerConfiguration,
    metadata: Option<&GithubEventMetadataV1>,
    trigger_span: &SourceSpan,
    context: &mut CompileContext<'_>,
) -> TriggerSelection {
    let (action, base_ref, changed_files) = match metadata {
        Some(GithubEventMetadataV1::PullRequest {
            action,
            base_ref,
            changed_files,
        }) => (action.as_str(), base_ref.as_str(), changed_files.as_ref()),
        Some(_) => {
            metadata_mismatch("pull_request", trigger_span, context);
            return TriggerSelection::Rejected;
        }
        None => {
            missing_metadata("pull_request", trigger_span, context);
            return TriggerSelection::Rejected;
        }
    };
    if action.is_empty() || base_ref.is_empty() || base_ref.starts_with("refs/") {
        context.semantic(
            "github.compile.invalid_pull_request_metadata",
            "pull_request metadata requires a non-empty action and unqualified `pull_request.base.ref`",
            trigger_span.clone(),
        );
        return TriggerSelection::Rejected;
    }
    if action.len() > MAX_CANDIDATE_BYTES || base_ref.len() > MAX_CANDIDATE_BYTES {
        context.semantic(
            "github.compile.pull_request_metadata_too_long",
            "pull_request action or base ref exceeds the supported 4096-byte selection limit",
            trigger_span.clone(),
        );
        return TriggerSelection::Rejected;
    }

    let matched = match configuration {
        TriggerConfiguration::PullRequest(filter) => {
            let action_matches = if filter.types_configured() {
                filter
                    .types()
                    .iter()
                    .any(|configured| configured.value() == action)
            } else {
                DEFAULT_PULL_REQUEST_ACTIONS.contains(&action)
            };
            let reference_matches = action_matches
                && ref_filter_matches(
                    base_ref,
                    filter.branches_configured(),
                    filter.branches(),
                    filter.branches_ignore_configured(),
                    filter.branches_ignore(),
                    false,
                );
            if reference_matches {
                match path_filter_matches(filter, changed_files, trigger_span, context) {
                    PathFilterSelection::Matched(paths_match) => paths_match,
                    PathFilterSelection::RequiresChangedFiles => {
                        return TriggerSelection::RequiresChangedFiles;
                    }
                    PathFilterSelection::Rejected => return TriggerSelection::Rejected,
                }
            } else {
                false
            }
        }
        TriggerConfiguration::Empty => DEFAULT_PULL_REQUEST_ACTIONS.contains(&action),
        _ => false,
    };
    if matched {
        TriggerSelection::Selected(None)
    } else {
        TriggerSelection::NotSelected(WorkflowNotSelectedReason::EventFiltersNotMatched)
    }
}

fn path_filter_matches(
    filter: &PushPullRequestFilter,
    changed_files: Option<&GithubChangedFilesV1>,
    trigger_span: &SourceSpan,
    context: &mut CompileContext<'_>,
) -> PathFilterSelection {
    if !filter.paths_configured() && !filter.paths_ignore_configured() {
        return PathFilterSelection::Matched(true);
    }
    let Some(changed_files) = changed_files else {
        return PathFilterSelection::RequiresChangedFiles;
    };
    let GithubChangedFilesV1::Complete(files) = changed_files else {
        return PathFilterSelection::Matched(true);
    };
    if !valid_changed_files(files) {
        context.semantic(
            "github.compile.invalid_changed_files_metadata",
            "changed-file metadata exceeds provider bounds or contains an invalid repository-relative path",
            trigger_span.clone(),
        );
        return PathFilterSelection::Rejected;
    }
    if filter.paths_configured() {
        return PathFilterSelection::Matched(
            files
                .iter()
                .any(|path| ordered_patterns_match(path, filter.paths())),
        );
    }
    PathFilterSelection::Matched(files.iter().any(|path| {
        !filter.paths_ignore().iter().any(|pattern| {
            GithubGlob::parse(pattern.value()).is_ok_and(|pattern| pattern.matches(path))
        })
    }))
}

enum PathFilterSelection {
    Matched(bool),
    RequiresChangedFiles,
    Rejected,
}

fn valid_changed_files(files: &[String]) -> bool {
    if files.len() > MAX_CHANGED_FILES {
        return false;
    }
    let mut bytes = 0_usize;
    for path in files {
        let Some(next_bytes) = bytes.checked_add(path.len()) else {
            return false;
        };
        bytes = next_bytes;
        if bytes > MAX_CHANGED_FILE_BYTES
            || path.is_empty()
            || path.len() > MAX_CANDIDATE_BYTES
            || path.starts_with('/')
            || path.chars().any(char::is_control)
            || path
                .split('/')
                .any(|component| component.is_empty() || matches!(component, "." | ".."))
        {
            return false;
        }
    }
    true
}

fn ref_filter_matches(
    candidate: &str,
    include_configured: bool,
    includes: &[Spanned<String>],
    ignore_configured: bool,
    ignores: &[Spanned<String>],
    opposite_ref_kind_configured: bool,
) -> bool {
    if include_configured {
        ordered_patterns_match(candidate, includes)
    } else if ignore_configured {
        !ignores.iter().any(|pattern| {
            GithubGlob::parse(pattern.value()).is_ok_and(|pattern| pattern.matches(candidate))
        })
    } else {
        !opposite_ref_kind_configured
    }
}

fn ordered_patterns_match(candidate: &str, patterns: &[Spanned<String>]) -> bool {
    let mut included = false;
    for pattern in patterns {
        let Ok(pattern) = GithubGlob::parse(pattern.value()) else {
            return false;
        };
        if pattern.matches(candidate) {
            included = !pattern.negative;
        }
    }
    included
}

fn missing_metadata(event_name: &str, span: &SourceSpan, context: &mut CompileContext<'_>) {
    context.semantic(
        "github.compile.event_metadata_required",
        format!(
            "GitHub `{event_name}` selection requires versioned GithubEventMetadataV1 payload fields"
        ),
        span.clone(),
    );
}

fn metadata_mismatch(event_name: &str, span: &SourceSpan, context: &mut CompileContext<'_>) {
    context.semantic(
        "github.compile.event_metadata_mismatch",
        format!("GithubEventMetadataV1 does not describe the `{event_name}` event"),
        span.clone(),
    );
}

enum GithubRef<'value> {
    Branch(&'value str),
    Tag(&'value str),
}

impl<'value> GithubRef<'value> {
    fn parse(value: &'value str) -> Option<Self> {
        value
            .strip_prefix("refs/heads/")
            .filter(|name| !name.is_empty())
            .map(Self::Branch)
            .or_else(|| {
                value
                    .strip_prefix("refs/tags/")
                    .filter(|name| !name.is_empty())
                    .map(Self::Tag)
            })
    }
}

#[derive(Clone, Debug)]
enum Atom {
    Literal(char),
    AnyNonSlash,
    Any,
    Class(CharacterClass),
}

impl Atom {
    fn matches(&self, candidate: char) -> bool {
        match self {
            Self::Literal(expected) => *expected == candidate,
            Self::AnyNonSlash => candidate != '/',
            Self::Any => true,
            Self::Class(class) => candidate != '/' && class.matches(candidate),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Repetition {
    Once,
    Optional,
    ZeroOrMore,
}

impl Repetition {
    const fn has_epsilon(self) -> bool {
        matches!(self, Self::Optional | Self::ZeroOrMore)
    }
}

#[derive(Clone, Debug)]
struct Piece {
    atom: Atom,
    repetition: Repetition,
}

#[derive(Clone, Debug)]
struct GithubGlob {
    negative: bool,
    pieces: Vec<Piece>,
}

impl GithubGlob {
    fn parse(source: &str) -> Result<Self, &'static str> {
        if source.is_empty() {
            return Err("patterns must not be empty");
        }
        if source.len() > MAX_PATTERN_BYTES {
            return Err("patterns must not exceed 4096 bytes");
        }

        let (negative, body) = source
            .strip_prefix('!')
            .map_or((false, source), |body| (true, body));
        if body.is_empty() {
            return Err("negative patterns must contain a pattern after `!`");
        }

        let characters = body.chars().collect::<Vec<_>>();
        let mut pieces = Vec::new();
        let mut index = 0;
        while index < characters.len() {
            let (atom, consumed, quantifiable) = match characters[index] {
                '\\' => {
                    let Some(literal) = characters.get(index + 1).copied() else {
                        return Err("a trailing escape has no escaped character");
                    };
                    (Atom::Literal(literal), 2, true)
                }
                '*' if characters.get(index + 1) == Some(&'*') => (Atom::Any, 2, false),
                '*' => (Atom::AnyNonSlash, 1, false),
                '[' => {
                    let (class, class_length) = CharacterClass::parse(&characters[index..])?;
                    (Atom::Class(class), class_length, true)
                }
                '?' | '+' => return Err("`?` and `+` must follow a literal or character class"),
                ']' => return Err("literal `]` characters must be escaped with `\\`"),
                literal => (Atom::Literal(literal), 1, true),
            };
            index += consumed;

            let quantifier = characters.get(index).copied();
            match quantifier {
                Some('?') if quantifiable => {
                    pieces.push(Piece {
                        atom,
                        repetition: Repetition::Optional,
                    });
                    index += 1;
                }
                Some('+') if quantifiable => {
                    pieces.push(Piece {
                        atom: atom.clone(),
                        repetition: Repetition::Once,
                    });
                    pieces.push(Piece {
                        atom,
                        repetition: Repetition::ZeroOrMore,
                    });
                    index += 1;
                }
                Some('?' | '+') => {
                    return Err("`?` and `+` cannot quantify a wildcard expression");
                }
                _ => pieces.push(Piece {
                    atom,
                    repetition: if matches!(characters[index - consumed], '*') {
                        Repetition::ZeroOrMore
                    } else {
                        Repetition::Once
                    },
                }),
            }
        }
        Ok(Self { negative, pieces })
    }

    fn matches(&self, candidate: &str) -> bool {
        if candidate.len() > MAX_CANDIDATE_BYTES {
            return false;
        }
        let mut states = vec![false; self.pieces.len() + 1];
        states[0] = true;
        epsilon_closure(&self.pieces, &mut states);
        for character in candidate.chars() {
            let mut next = vec![false; states.len()];
            for (index, piece) in self.pieces.iter().enumerate() {
                if states[index] && piece.atom.matches(character) {
                    match piece.repetition {
                        Repetition::Once | Repetition::Optional => next[index + 1] = true,
                        Repetition::ZeroOrMore => next[index] = true,
                    }
                }
            }
            epsilon_closure(&self.pieces, &mut next);
            states = next;
        }
        states[self.pieces.len()]
    }
}

fn epsilon_closure(pieces: &[Piece], states: &mut [bool]) {
    for (index, piece) in pieces.iter().enumerate() {
        if states[index] && piece.repetition.has_epsilon() {
            states[index + 1] = true;
        }
    }
}

#[derive(Clone, Debug)]
struct CharacterClass {
    members: Vec<ClassMember>,
}

impl CharacterClass {
    fn parse(source: &[char]) -> Result<(Self, usize), &'static str> {
        debug_assert_eq!(source.first(), Some(&'['));
        let mut index = 1;
        if matches!(source.get(index), Some('!' | '^')) {
            return Err("negated character classes are not part of GitHub filter syntax");
        }
        let mut literals = Vec::new();
        let mut closed = false;
        while index < source.len() {
            match source[index] {
                ']' if !literals.is_empty() => {
                    closed = true;
                    index += 1;
                    break;
                }
                '\\' => {
                    let Some(literal) = source.get(index + 1).copied() else {
                        return Err("a character class has a trailing escape");
                    };
                    literals.push(literal);
                    index += 2;
                }
                literal => {
                    literals.push(literal);
                    index += 1;
                }
            }
        }
        if !closed {
            return Err("a character class is not closed with `]`");
        }
        if literals.is_empty() {
            return Err("character classes must not be empty");
        }

        let mut members = Vec::new();
        let mut literal_index = 0;
        while literal_index < literals.len() {
            if literal_index + 2 < literals.len() && literals[literal_index + 1] == '-' {
                let start = literals[literal_index];
                let end = literals[literal_index + 2];
                if !valid_character_class_range(start, end) {
                    return Err(
                        "character class ranges must be ascending within `a-z`, `A-Z`, or `0-9`",
                    );
                }
                members.push(ClassMember::Range(start, end));
                literal_index += 3;
            } else {
                let literal = literals[literal_index];
                if !literal.is_ascii_alphanumeric() {
                    return Err("character classes may list only ASCII alphanumeric characters");
                }
                members.push(ClassMember::Literal(literal));
                literal_index += 1;
            }
        }
        Ok((Self { members }, index))
    }

    fn matches(&self, candidate: char) -> bool {
        self.members.iter().any(|member| member.matches(candidate))
    }
}

fn valid_character_class_range(start: char, end: char) -> bool {
    start <= end
        && ((start.is_ascii_digit() && end.is_ascii_digit())
            || (start.is_ascii_lowercase() && end.is_ascii_lowercase())
            || (start.is_ascii_uppercase() && end.is_ascii_uppercase()))
}

#[derive(Clone, Copy, Debug)]
enum ClassMember {
    Literal(char),
    Range(char, char),
}

impl ClassMember {
    fn matches(self, candidate: char) -> bool {
        match self {
            Self::Literal(expected) => expected == candidate,
            Self::Range(start, end) => (start..=end).contains(&candidate),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::GithubGlob;

    fn matches(pattern: &str, candidate: &str) -> bool {
        GithubGlob::parse(pattern)
            .expect("valid test pattern")
            .matches(candidate)
    }

    #[test]
    fn github_documented_branch_patterns_match_whole_names() {
        assert!(matches("feature/*", "feature/my-branch"));
        assert!(!matches("feature/*", "feature/beta/my-branch"));
        assert!(matches("feature/**", "feature/beta/my-branch"));
        assert!(matches("v[12].[0-9]+.[0-9]+", "v2.10.1"));
        assert!(!matches("v[12].[0-9]+.[0-9]+", "v3.10.1"));
        assert!(matches("releases/**-alpha", "releases/beta/3-alpha"));
    }

    #[test]
    fn github_quantifiers_and_escaping_are_deterministic() {
        assert!(matches("page.jsx?", "page.js"));
        assert!(matches("page.jsx?", "page.jsx"));
        assert!(!matches("page.jsx?", "page.jsxx"));
        assert!(matches(r"release/\!candidate", "release/!candidate"));
        assert!(matches("release/!candidate", "release/!candidate"));
        assert!(GithubGlob::parse("+").is_err());
        assert!(GithubGlob::parse("unterminated[").is_err());
        assert!(GithubGlob::parse("[a-9]").is_err());
        assert!(GithubGlob::parse("[!a]").is_err());
    }
}
