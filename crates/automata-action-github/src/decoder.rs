use std::{fmt, str};

use automata_action::{ActionDefinitionDocument, ActionDefinitionKind};

use crate::{
    ActionExecution, ActionInput, ActionOutput, CompositeAction, CompositeRunStep, CompositeStep,
    CompositeUsesStep, DockerAction, GithubActionMetadata, GithubActionMetadataLimits,
    JavascriptAction, JavascriptRuntime, MetadataDecodeError, MetadataDecodeErrorKind,
    MetadataKeyValue, MetadataScalar,
    model::{CompositeStepMetadata, DockerLifecycle},
    parser::{YamlMappingEntry, YamlNode, key_eq, parse_yaml},
    path::{docker_image, entry_path, scalar_string},
};

/// Object-safe adapter port from immutable definition bytes to GitHub action metadata.
pub trait ActionMetadataDecoder: fmt::Debug + Send + Sync {
    /// Decodes one selected metadata definition without evaluating expressions.
    ///
    /// # Errors
    ///
    /// Fails closed on an unsupported definition, invalid YAML, exhausted limits,
    /// schema mismatch, unsupported runtime, plugin action, or unsafe entry path.
    fn decode(
        &self,
        document: &ActionDefinitionDocument,
    ) -> Result<GithubActionMetadata, MetadataDecodeError>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GithubActionMetadataDecoder {
    limits: GithubActionMetadataLimits,
}

impl GithubActionMetadataDecoder {
    #[must_use]
    pub const fn new(limits: GithubActionMetadataLimits) -> Self {
        Self { limits }
    }

    #[must_use]
    pub const fn limits(self) -> GithubActionMetadataLimits {
        self.limits
    }
}

impl ActionMetadataDecoder for GithubActionMetadataDecoder {
    fn decode(
        &self,
        document: &ActionDefinitionDocument,
    ) -> Result<GithubActionMetadata, MetadataDecodeError> {
        if document.kind() != ActionDefinitionKind::MetadataYaml {
            return Err(MetadataDecodeError::new(
                MetadataDecodeErrorKind::UnsupportedDefinition,
                "definition.kind",
                None,
            ));
        }
        if document.bytes().len() > self.limits.maximum_source_bytes() {
            return Err(MetadataDecodeError::new(
                MetadataDecodeErrorKind::ResourceLimit,
                "yaml.source",
                None,
            ));
        }
        let source = str::from_utf8(document.bytes()).map_err(|_| {
            MetadataDecodeError::new(MetadataDecodeErrorKind::InvalidUtf8, "yaml.source", None)
        })?;
        decode_root(parse_yaml(source, self.limits)?)
    }
}

fn decode_root(root: YamlNode) -> Result<GithubActionMetadata, MetadataDecodeError> {
    let entries = expect_mapping(root, "action")?;
    let mut name = None;
    let mut description = None;
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();
    let mut execution = None;
    let mut ignored = Vec::new();

    for entry in entries {
        require_nonempty_key(&entry, "action.key")?;
        let key = entry.key().to_owned();
        let exact = key.as_str();
        let value = entry.into_value();
        if key_eq(exact, "name") {
            let decoded = scalar_string(&expect_scalar(value, "name")?);
            if exact == "name" {
                name = Some(decoded);
            } else {
                ignored.push(key);
            }
        } else if key_eq(exact, "description") {
            let decoded = scalar_string(&expect_scalar(value, "description")?);
            if exact == "description" {
                description = Some(decoded);
            } else {
                ignored.push(key);
            }
        } else if key_eq(exact, "inputs") {
            let decoded = decode_inputs(value)?;
            if exact == "inputs" {
                inputs = decoded;
            } else {
                ignored.push(key);
            }
        } else if key_eq(exact, "outputs") {
            let decoded = decode_outputs(value)?;
            if exact == "outputs" {
                outputs = decoded;
            } else {
                ignored.push(key);
            }
        } else if key_eq(exact, "runs") {
            let decoded = decode_runs(value)?;
            if exact == "runs" {
                execution = Some(decoded);
            } else {
                ignored.push(key);
            }
        } else {
            // action-root is intentionally loose in runner v2.336.0.
            ignored.push(key);
        }
    }

    let execution = execution.ok_or_else(|| {
        MetadataDecodeError::new(MetadataDecodeErrorKind::MissingRequiredField, "runs", None)
    })?;
    Ok(GithubActionMetadata::new(
        name,
        description,
        inputs,
        outputs,
        execution,
        ignored,
    ))
}

fn decode_inputs(node: YamlNode) -> Result<Vec<ActionInput>, MetadataDecodeError> {
    let entries = expect_mapping(node, "inputs")?;
    let mut decoded = Vec::with_capacity(entries.len());
    for entry in entries {
        require_nonempty_key(&entry, "inputs.name")?;
        let name = entry.key().to_owned();
        let metadata = expect_mapping(entry.into_value(), "inputs.entry")?;
        let mut description = None;
        let mut required = None;
        let mut default = None;
        let mut deprecation_message = None;
        for property in metadata {
            require_nonempty_key(&property, "inputs.property")?;
            let key = property.key().to_owned();
            let value = property.into_value();
            if key_eq(&key, "default") {
                default = Some(expect_scalar(value, "inputs.default")?);
            } else if key_eq(&key, "deprecationMessage") {
                deprecation_message = Some(expect_scalar(value, "inputs.deprecationMessage")?);
            } else if key_eq(&key, "description") {
                // These two properties are loose `any` values in the reviewed runner
                // schema. Preserve common scalar forms, but accept complex legacy data.
                description = value.into_scalar();
            } else if key_eq(&key, "required") {
                required = value.into_scalar();
            }
        }
        decoded.push(ActionInput::new(
            name,
            description,
            required,
            default,
            deprecation_message,
        ));
    }
    Ok(decoded)
}

fn decode_outputs(node: YamlNode) -> Result<Vec<ActionOutput>, MetadataDecodeError> {
    let entries = expect_mapping(node, "outputs")?;
    let mut decoded = Vec::with_capacity(entries.len());
    for entry in entries {
        require_nonempty_key(&entry, "outputs.name")?;
        let name = entry.key().to_owned();
        let mut fields = Fields::new(expect_mapping(entry.into_value(), "outputs.entry")?);
        fields.validate_allowed(&["description", "value"], "outputs.property")?;
        let description = fields
            .take_insensitive("description")
            .map(|node| expect_scalar(node, "outputs.description"))
            .transpose()?;
        let value = fields
            .take_insensitive("value")
            .map(|node| expect_scalar(node, "outputs.value"))
            .transpose()?;
        decoded.push(ActionOutput::new(name, description, value));
    }
    Ok(decoded)
}

fn decode_runs(node: YamlNode) -> Result<ActionExecution, MetadataDecodeError> {
    let mut fields = Fields::new(expect_mapping(node, "runs")?);
    fields.validate_allowed(
        &[
            "using",
            "image",
            "entrypoint",
            "args",
            "env",
            "pre-entrypoint",
            "pre-if",
            "post-entrypoint",
            "post-if",
            "main",
            "pre",
            "post",
            "steps",
            "plugin",
        ],
        "runs.property",
    )?;

    if fields.has_exact("plugin") {
        return Err(MetadataDecodeError::new(
            MetadataDecodeErrorKind::UnsupportedPlugin,
            "runs.plugin",
            fields.location_exact("plugin"),
        ));
    }
    let using = required_exact_scalar(&mut fields, "using", "runs.using")?;
    let runtime = scalar_string(&using);
    if runtime.eq_ignore_ascii_case("docker") {
        decode_docker(fields).map(ActionExecution::Docker)
    } else if runtime.eq_ignore_ascii_case("node12") {
        decode_javascript(fields, JavascriptRuntime::Node12).map(ActionExecution::Javascript)
    } else if runtime.eq_ignore_ascii_case("node16") {
        decode_javascript(fields, JavascriptRuntime::Node16).map(ActionExecution::Javascript)
    } else if runtime.eq_ignore_ascii_case("node20") {
        decode_javascript(fields, JavascriptRuntime::Node20).map(ActionExecution::Javascript)
    } else if runtime.eq_ignore_ascii_case("node24") {
        decode_javascript(fields, JavascriptRuntime::Node24).map(ActionExecution::Javascript)
    } else if runtime.eq_ignore_ascii_case("composite") {
        decode_composite(fields).map(ActionExecution::Composite)
    } else {
        Err(MetadataDecodeError::new(
            MetadataDecodeErrorKind::UnsupportedRuntime,
            "runs.using",
            using.location(),
        ))
    }
}

fn decode_javascript(
    mut fields: Fields,
    runtime: JavascriptRuntime,
) -> Result<JavascriptAction, MetadataDecodeError> {
    fields.validate_allowed(
        &["using", "main", "pre", "pre-if", "post", "post-if"],
        "runs.property",
    )?;
    let main_scalar = required_exact_scalar(&mut fields, "main", "runs.main")?;
    let main = entry_path(&main_scalar, "runs.main")?;
    let pre = optional_exact_scalar(&mut fields, "pre", "runs.pre")?
        .map(|value| entry_path(&value, "runs.pre"))
        .transpose()?;
    let post = optional_exact_scalar(&mut fields, "post", "runs.post")?
        .map(|value| entry_path(&value, "runs.post"))
        .transpose()?;
    let pre_condition = condition_or_always(&mut fields, "pre-if", "runs.pre-if")?;
    let post_condition = condition_or_always(&mut fields, "post-if", "runs.post-if")?;
    Ok(JavascriptAction::new(
        runtime,
        main,
        pre,
        pre_condition,
        post,
        post_condition,
    ))
}

fn decode_docker(mut fields: Fields) -> Result<DockerAction, MetadataDecodeError> {
    fields.validate_allowed(
        &[
            "using",
            "image",
            "entrypoint",
            "args",
            "env",
            "pre-entrypoint",
            "pre-if",
            "post-entrypoint",
            "post-if",
        ],
        "runs.property",
    )?;
    let image_scalar = required_exact_scalar(&mut fields, "image", "runs.image")?;
    let image = docker_image(&image_scalar)?;
    let entrypoint = optional_exact_scalar(&mut fields, "entrypoint", "runs.entrypoint")?;
    let arguments = fields
        .take_exact("args")
        .map(|node| decode_scalar_sequence(node, "runs.args"))
        .transpose()?
        .unwrap_or_default();
    let environment = fields
        .take_exact("env")
        .map(|node| decode_scalar_map(node, "runs.env"))
        .transpose()?
        .unwrap_or_default();
    let pre_entrypoint =
        optional_exact_scalar(&mut fields, "pre-entrypoint", "runs.pre-entrypoint")?;
    let post_entrypoint =
        optional_exact_scalar(&mut fields, "post-entrypoint", "runs.post-entrypoint")?;
    let pre_condition = condition_or_always(&mut fields, "pre-if", "runs.pre-if")?;
    let post_condition = condition_or_always(&mut fields, "post-if", "runs.post-if")?;
    Ok(DockerAction::new(
        image,
        entrypoint,
        arguments,
        environment,
        DockerLifecycle::new(
            pre_entrypoint,
            pre_condition,
            post_entrypoint,
            post_condition,
        ),
    ))
}

fn decode_composite(mut fields: Fields) -> Result<CompositeAction, MetadataDecodeError> {
    fields.validate_allowed(&["using", "steps"], "runs.property")?;
    let steps_node = fields.take_exact("steps").ok_or_else(|| {
        MetadataDecodeError::new(
            MetadataDecodeErrorKind::MissingRequiredField,
            "runs.steps",
            None,
        )
    })?;
    let items = expect_sequence(steps_node, "runs.steps")?;
    let mut steps = Vec::with_capacity(items.len());
    for (index, item) in items.into_iter().enumerate() {
        steps.push(decode_composite_step(item, index)?);
    }
    Ok(CompositeAction::new(steps))
}

fn decode_composite_step(
    node: YamlNode,
    index: usize,
) -> Result<CompositeStep, MetadataDecodeError> {
    let fields = Fields::new(expect_mapping(node, "runs.steps[]")?);
    fields.validate_allowed(
        &[
            "name",
            "id",
            "if",
            "run",
            "env",
            "continue-on-error",
            "working-directory",
            "shell",
            "uses",
            "with",
        ],
        "runs.steps[].property",
    )?;
    let has_run = fields.has_exact("run");
    let has_uses = fields.has_exact("uses");
    match (has_run, has_uses) {
        (true, false) => decode_composite_run_step(fields).map(CompositeStep::Run),
        (false, true) => decode_composite_uses_step(fields).map(CompositeStep::Uses),
        (true, true) | (false, false) => Err(MetadataDecodeError::new(
            MetadataDecodeErrorKind::InvalidStructure,
            format!("runs.steps[{index}]"),
            None,
        )),
    }
}

fn decode_composite_run_step(mut fields: Fields) -> Result<CompositeRunStep, MetadataDecodeError> {
    fields.validate_allowed(
        &[
            "name",
            "id",
            "if",
            "run",
            "env",
            "continue-on-error",
            "working-directory",
            "shell",
        ],
        "runs.steps[].property",
    )?;
    let name = optional_exact_scalar(&mut fields, "name", "runs.steps[].name")?;
    let id = optional_exact_scalar(&mut fields, "id", "runs.steps[].id")?;
    let condition = optional_exact_scalar(&mut fields, "if", "runs.steps[].if")?;
    let run = required_exact_scalar(&mut fields, "run", "runs.steps[].run")?;
    let shell = required_exact_scalar(&mut fields, "shell", "runs.steps[].shell")?;
    let environment = fields
        .take_exact("env")
        .map(|node| decode_scalar_map(node, "runs.steps[].env"))
        .transpose()?
        .unwrap_or_default();
    let continue_on_error = optional_exact_scalar(
        &mut fields,
        "continue-on-error",
        "runs.steps[].continue-on-error",
    )?;
    if let Some(value) = &continue_on_error {
        validate_boolean_or_expression(value, "runs.steps[].continue-on-error")?;
    }
    let working_directory = optional_exact_scalar(
        &mut fields,
        "working-directory",
        "runs.steps[].working-directory",
    )?;
    Ok(CompositeRunStep::new(
        CompositeStepMetadata::new(name, id, condition, continue_on_error),
        run,
        shell,
        environment,
        working_directory,
    ))
}

fn decode_composite_uses_step(
    mut fields: Fields,
) -> Result<CompositeUsesStep, MetadataDecodeError> {
    fields.validate_allowed(
        &[
            "name",
            "id",
            "if",
            "uses",
            "continue-on-error",
            "with",
            "env",
        ],
        "runs.steps[].property",
    )?;
    let name = optional_exact_scalar(&mut fields, "name", "runs.steps[].name")?;
    let id = optional_exact_scalar(&mut fields, "id", "runs.steps[].id")?;
    let condition = optional_exact_scalar(&mut fields, "if", "runs.steps[].if")?;
    let uses = required_exact_scalar(&mut fields, "uses", "runs.steps[].uses")?;
    let with = fields
        .take_exact("with")
        .map(|node| decode_scalar_map(node, "runs.steps[].with"))
        .transpose()?
        .unwrap_or_default();
    let environment = fields
        .take_exact("env")
        .map(|node| decode_scalar_map(node, "runs.steps[].env"))
        .transpose()?
        .unwrap_or_default();
    let continue_on_error = optional_exact_scalar(
        &mut fields,
        "continue-on-error",
        "runs.steps[].continue-on-error",
    )?;
    if let Some(value) = &continue_on_error {
        validate_boolean_or_expression(value, "runs.steps[].continue-on-error")?;
    }
    Ok(CompositeUsesStep::new(
        CompositeStepMetadata::new(name, id, condition, continue_on_error),
        uses,
        with,
        environment,
    ))
}

fn decode_scalar_sequence(
    node: YamlNode,
    field: &'static str,
) -> Result<Vec<MetadataScalar>, MetadataDecodeError> {
    expect_sequence(node, field)?
        .into_iter()
        .map(|item| expect_scalar(item, field))
        .collect()
}

fn decode_scalar_map(
    node: YamlNode,
    field: &'static str,
) -> Result<Vec<MetadataKeyValue>, MetadataDecodeError> {
    expect_mapping(node, field)?
        .into_iter()
        .map(|entry| {
            require_nonempty_key(&entry, field)?;
            let key = entry.key().to_owned();
            let value = expect_scalar(entry.into_value(), field)?;
            Ok(MetadataKeyValue::new(key, value))
        })
        .collect()
}

fn condition_or_always(
    fields: &mut Fields,
    key: &'static str,
    field: &'static str,
) -> Result<MetadataScalar, MetadataDecodeError> {
    optional_exact_scalar(fields, key, field)
        .map(|condition| condition.unwrap_or_else(|| MetadataScalar::synthetic("always()")))
}

fn required_exact_scalar(
    fields: &mut Fields,
    key: &'static str,
    field: &'static str,
) -> Result<MetadataScalar, MetadataDecodeError> {
    let value = fields.take_exact(key).ok_or_else(|| {
        MetadataDecodeError::new(MetadataDecodeErrorKind::MissingRequiredField, field, None)
    })?;
    let value = expect_scalar(value, field)?;
    if scalar_string(&value).is_empty() {
        return Err(MetadataDecodeError::new(
            MetadataDecodeErrorKind::MissingRequiredField,
            field,
            value.location(),
        ));
    }
    Ok(value)
}

fn optional_exact_scalar(
    fields: &mut Fields,
    key: &'static str,
    field: &'static str,
) -> Result<Option<MetadataScalar>, MetadataDecodeError> {
    fields
        .take_exact(key)
        .map(|node| {
            let value = expect_scalar(node, field)?;
            if scalar_string(&value).is_empty() {
                return Err(MetadataDecodeError::new(
                    MetadataDecodeErrorKind::InvalidStructure,
                    field,
                    value.location(),
                ));
            }
            Ok(value)
        })
        .transpose()
}

fn validate_boolean_or_expression(
    value: &MetadataScalar,
    field: &'static str,
) -> Result<(), MetadataDecodeError> {
    if value.kind() == crate::MetadataScalarKind::Boolean || value.text().contains("${{") {
        return Ok(());
    }
    Err(MetadataDecodeError::new(
        MetadataDecodeErrorKind::InvalidStructure,
        field,
        value.location(),
    ))
}

fn expect_scalar(
    node: YamlNode,
    field: impl Into<String>,
) -> Result<MetadataScalar, MetadataDecodeError> {
    let location = node.location();
    node.into_scalar().ok_or_else(|| {
        MetadataDecodeError::new(
            MetadataDecodeErrorKind::InvalidStructure,
            field,
            Some(location),
        )
    })
}

fn expect_mapping(
    node: YamlNode,
    field: impl Into<String>,
) -> Result<Vec<YamlMappingEntry>, MetadataDecodeError> {
    let location = node.location();
    node.into_mapping().ok_or_else(|| {
        MetadataDecodeError::new(
            MetadataDecodeErrorKind::InvalidStructure,
            field,
            Some(location),
        )
    })
}

fn expect_sequence(
    node: YamlNode,
    field: impl Into<String>,
) -> Result<Vec<YamlNode>, MetadataDecodeError> {
    let location = node.location();
    node.into_sequence().ok_or_else(|| {
        MetadataDecodeError::new(
            MetadataDecodeErrorKind::InvalidStructure,
            field,
            Some(location),
        )
    })
}

fn require_nonempty_key(
    entry: &YamlMappingEntry,
    field: &'static str,
) -> Result<(), MetadataDecodeError> {
    if !scalar_string(entry.key_scalar()).is_empty() {
        return Ok(());
    }
    Err(MetadataDecodeError::new(
        MetadataDecodeErrorKind::InvalidStructure,
        field,
        entry.key_scalar().location(),
    ))
}

#[derive(Debug)]
struct Fields {
    entries: Vec<YamlMappingEntry>,
}

impl Fields {
    const fn new(entries: Vec<YamlMappingEntry>) -> Self {
        Self { entries }
    }

    fn validate_allowed(
        &self,
        allowed: &[&str],
        field: &'static str,
    ) -> Result<(), MetadataDecodeError> {
        for entry in &self.entries {
            require_nonempty_key(entry, field)?;
            if !allowed.iter().any(|known| key_eq(entry.key(), known)) {
                return Err(MetadataDecodeError::new(
                    MetadataDecodeErrorKind::InvalidStructure,
                    field,
                    entry.key_scalar().location(),
                ));
            }
        }
        Ok(())
    }

    fn has_exact(&self, key: &str) -> bool {
        self.entries.iter().any(|entry| entry.key() == key)
    }

    fn location_exact(&self, key: &str) -> Option<crate::MetadataLocation> {
        self.entries
            .iter()
            .find(|entry| entry.key() == key)
            .and_then(|entry| entry.key_scalar().location())
    }

    fn take_exact(&mut self, key: &str) -> Option<YamlNode> {
        self.entries
            .iter()
            .position(|entry| entry.key() == key)
            .map(|index| self.entries.remove(index).into_value())
    }

    fn take_insensitive(&mut self, key: &str) -> Option<YamlNode> {
        self.entries
            .iter()
            .position(|entry| key_eq(entry.key(), key))
            .map(|index| self.entries.remove(index).into_value())
    }
}
