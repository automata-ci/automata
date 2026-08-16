use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_action::{
    ActionBundleLimits, ActionDefinitionDocument, ActionResolveErrorKind, ActionResolver,
    ActionSubpath, RepositoryActionRequest, inspect_archive_bytes,
};
use automata_ci_action_github::{
    ActionMetadataDecoder, CompositeRunStep, CompositeStep, CompositeUsesStep,
    GithubActionMetadata, MetadataDecodeErrorKind, MetadataKeyValue, MetadataScalar,
    MetadataScalarKind,
};
use automata_ci_core::{ActionReference, StepId};
use automata_ci_execution::{TargetPath, TargetPlatform};
use automata_ci_scm::{RepositoryId, RevisionSpec};
use automata_ci_workflow_github::{GithubConditionCompiler, GithubConditionPhase};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};

use crate::{
    ActionPreparationError, ActionPreparationPort, ActionPreparationRequest,
    PlannedActionPreparationRequest, PreparedAction, PreparedActionDefinition,
    PreparedActionExecution, PreparedBoolean, PreparedCompositeAction, PreparedCompositeRunStep,
    PreparedCompositeStep, PreparedCompositeStepMetadata, PreparedCompositeUsesStep, PreparedInput,
    PreparedJavascriptAction, PreparedKeyValue, PreparedLocalAction, PreparedOutput, PreparedValue,
    PreparedValueSegment, RepositoryCredentialPort,
    error::{ActionPreparationErrorKind, PortErrorKind},
};

/// Bounded metadata candidates copied from one checked-out local-action directory.
///
/// Callers should read exactly these two candidate filenames through the sandbox
/// endpoint's bounded copy API. `action.yml` has GitHub-compatible precedence
/// over `action.yaml` when both exist.
#[derive(Clone, Copy)]
pub struct LocalActionPreparationRequest<'a> {
    reference: &'a ActionReference,
    action_yml: Option<&'a [u8]>,
    action_yaml: Option<&'a [u8]>,
}

/// Exact checked-out metadata candidate paths for one local action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalActionDefinitionPaths {
    action_yml: TargetPath,
    action_yaml: TargetPath,
}

impl LocalActionDefinitionPaths {
    /// Returns the preferred `action.yml` candidate.
    #[must_use]
    pub const fn action_yml(&self) -> &TargetPath {
        &self.action_yml
    }

    /// Returns the fallback `action.yaml` candidate.
    #[must_use]
    pub const fn action_yaml(&self) -> &TargetPath {
        &self.action_yaml
    }
}

impl fmt::Debug for LocalActionPreparationRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalActionPreparationRequest")
            .field("reference", &self.reference)
            .field("action_yml_bytes", &self.action_yml.map(<[u8]>::len))
            .field("action_yaml_bytes", &self.action_yaml.map(<[u8]>::len))
            .finish()
    }
}

impl<'a> LocalActionPreparationRequest<'a> {
    /// Creates a local-action metadata request from bounded candidate bytes.
    #[must_use]
    pub const fn new(
        reference: &'a ActionReference,
        preferred_definition: Option<&'a [u8]>,
        fallback_definition: Option<&'a [u8]>,
    ) -> Self {
        Self {
            reference,
            action_yml: preferred_definition,
            action_yaml: fallback_definition,
        }
    }

    /// Returns the exact local action reference retained in `JobIR`.
    #[must_use]
    pub const fn reference(self) -> &'a ActionReference {
        self.reference
    }

    /// Returns the bounded `action.yml` bytes, when the candidate existed.
    #[must_use]
    pub const fn action_yml(self) -> Option<&'a [u8]> {
        self.action_yml
    }

    /// Returns the bounded `action.yaml` bytes, when the candidate existed.
    #[must_use]
    pub const fn action_yaml(self) -> Option<&'a [u8]> {
        self.action_yaml
    }
}

/// Pure compiler for metadata read from a checked-out local action.
///
/// This type deliberately does not access the host filesystem. The job
/// executor remains responsible for containing candidate paths below its
/// sandbox workspace and passing only bounded bytes here.
pub struct CheckedOutLocalActionPreparer {
    decoder: Arc<dyn ActionMetadataDecoder>,
    conditions: GithubConditionCompiler,
}

impl Clone for CheckedOutLocalActionPreparer {
    fn clone(&self) -> Self {
        Self {
            decoder: Arc::clone(&self.decoder),
            conditions: self.conditions,
        }
    }
}

impl CheckedOutLocalActionPreparer {
    /// Creates a checked-out action metadata compiler.
    #[must_use]
    pub fn new(
        decoder: Arc<dyn ActionMetadataDecoder>,
        conditions: GithubConditionCompiler,
    ) -> Self {
        Self {
            decoder,
            conditions,
        }
    }

    /// Resolves the only two metadata candidates below the checked-out workspace.
    ///
    /// # Errors
    ///
    /// Rejects a non-local reference, traversal, a platform mismatch, or a
    /// target path that exceeds the execution boundary.
    pub fn definition_paths(
        workspace: &TargetPath,
        reference: &ActionReference,
    ) -> Result<LocalActionDefinitionPaths, ActionPreparationError> {
        let ActionReference::Local { path } = reference else {
            return Err(ActionPreparationError::new(
                ActionPreparationErrorKind::UnsupportedReference,
            ));
        };
        validate_local_reference(path).map_err(|()| metadata_error())?;
        let relative = path.trim_start_matches("./");
        let (preferred_path, fallback_path) = match workspace.platform() {
            TargetPlatform::Posix => (
                format!(
                    "{}/{relative}/action.yml",
                    workspace.as_str().trim_end_matches('/')
                ),
                format!(
                    "{}/{relative}/action.yaml",
                    workspace.as_str().trim_end_matches('/')
                ),
            ),
            TargetPlatform::Windows => {
                let relative = relative.replace('/', "\\");
                (
                    format!(
                        "{}\\{relative}\\action.yml",
                        workspace.as_str().trim_end_matches('\\')
                    ),
                    format!(
                        "{}\\{relative}\\action.yaml",
                        workspace.as_str().trim_end_matches('\\')
                    ),
                )
            }
        };
        let construct = match workspace.platform() {
            TargetPlatform::Posix => TargetPath::posix,
            TargetPlatform::Windows => TargetPath::windows,
        };
        Ok(LocalActionDefinitionPaths {
            action_yml: construct(preferred_path).map_err(|_| metadata_error())?,
            action_yaml: construct(fallback_path).map_err(|_| metadata_error())?,
        })
    }

    /// Applies filename precedence, decodes, and compiles one local action.
    ///
    /// # Errors
    ///
    /// Fails closed for non-local or unsafe references, missing definitions,
    /// malformed metadata, unsupported Docker execution, and expression errors.
    pub fn prepare(
        &self,
        request: LocalActionPreparationRequest<'_>,
    ) -> Result<PreparedLocalAction, ActionPreparationError> {
        let ActionReference::Local { path } = request.reference() else {
            return Err(ActionPreparationError::new(
                ActionPreparationErrorKind::UnsupportedReference,
            ));
        };
        validate_local_reference(path).map_err(|()| metadata_error())?;
        let (filename, bytes) = request
            .action_yml()
            .map(|bytes| ("action.yml", bytes))
            .or_else(|| request.action_yaml().map(|bytes| ("action.yaml", bytes)))
            .ok_or_else(metadata_error)?;
        if bytes.len() > automata_ci_execution::MAX_COPY_BYTES {
            return Err(ActionPreparationError::new(
                ActionPreparationErrorKind::ResourceExhausted,
            ));
        }
        let definition_path = format!("{}/{filename}", path.trim_end_matches('/'));
        let document =
            ActionDefinitionDocument::metadata_yaml(definition_path, Bytes::copy_from_slice(bytes));
        let metadata = self
            .decoder
            .decode(&document)
            .map_err(|error| map_metadata_error(&error))?;
        let definition = prepare_definition(&metadata, &self.conditions, None)?;
        PreparedLocalAction::new(path.clone(), definition).map_err(|_| metadata_error())
    }
}

impl fmt::Debug for CheckedOutLocalActionPreparer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CheckedOutLocalActionPreparer")
            .field("decoder", &self.decoder)
            .field("conditions", &self.conditions)
            .finish()
    }
}

/// Concrete composition of immutable action resolution, credential lookup,
/// GitHub metadata decoding, and condition compilation.
pub struct ResolvedBundleActionPreparer {
    resolver: Arc<dyn ActionResolver>,
    credentials: Arc<dyn RepositoryCredentialPort>,
    decoder: Arc<dyn ActionMetadataDecoder>,
    conditions: GithubConditionCompiler,
    bundle_limits: ActionBundleLimits,
    maximum_archive_bytes: u64,
}

impl ResolvedBundleActionPreparer {
    /// Creates a repository-action preparation adapter.
    ///
    /// `maximum_archive_bytes` is the materialization ceiling and must not
    /// exceed the provider-neutral endpoint copy limit. The resolver's
    /// compressed-input ceiling must fit within it.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero or excessive archive read bound, or when
    /// the resolver's compressed-input ceiling exceeds that read bound.
    pub fn new(
        resolver: Arc<dyn ActionResolver>,
        credentials: Arc<dyn RepositoryCredentialPort>,
        decoder: Arc<dyn ActionMetadataDecoder>,
        conditions: GithubConditionCompiler,
        bundle_limits: ActionBundleLimits,
        maximum_archive_bytes: u64,
    ) -> Result<Self, ActionPreparationError> {
        if maximum_archive_bytes == 0
            || maximum_archive_bytes > automata_ci_execution::MAX_COPY_BYTES as u64
            || bundle_limits.compressed().maximum_bytes() > maximum_archive_bytes
        {
            return Err(ActionPreparationError::new(
                ActionPreparationErrorKind::ResourceExhausted,
            ));
        }
        Ok(Self {
            resolver,
            credentials,
            decoder,
            conditions,
            bundle_limits,
            maximum_archive_bytes,
        })
    }
}

impl fmt::Debug for ResolvedBundleActionPreparer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedBundleActionPreparer")
            .field("resolver", &self.resolver)
            .field("credentials", &self.credentials)
            .field("decoder", &self.decoder)
            .field("conditions", &self.conditions)
            .field("bundle_limits", &self.bundle_limits)
            .field("maximum_archive_bytes", &self.maximum_archive_bytes)
            .finish()
    }
}

#[async_trait]
impl ActionPreparationPort for ResolvedBundleActionPreparer {
    async fn prepare(
        &self,
        request: ActionPreparationRequest<'_>,
    ) -> Result<PreparedAction, ActionPreparationError> {
        let ActionReference::Repository {
            repository: repository_name,
            revision: revision_name,
            subpath,
        } = request.reference()
        else {
            return Err(ActionPreparationError::new(
                ActionPreparationErrorKind::UnsupportedReference,
            ));
        };
        let repository = RepositoryId::new(repository_name.clone()).map_err(|_| internal())?;
        let revision = RevisionSpec::new(revision_name.clone()).map_err(|_| internal())?;
        let subpath = match subpath {
            Some(value) => ActionSubpath::new(value.clone()).map_err(|_| internal())?,
            None => ActionSubpath::root(),
        };
        let credential = self.credentials.credential(&repository).map_err(|error| {
            let kind = match error.kind() {
                PortErrorKind::PermissionDenied => ActionPreparationErrorKind::PermissionDenied,
                PortErrorKind::ResourceExhausted => ActionPreparationErrorKind::ResourceExhausted,
                PortErrorKind::NotFound
                | PortErrorKind::Unavailable
                | PortErrorKind::InvalidData
                | PortErrorKind::Unsupported
                | PortErrorKind::Internal => ActionPreparationErrorKind::Resolution,
            };
            ActionPreparationError::new(kind)
        })?;
        let action_request = credential.as_ref().map_or_else(
            || {
                RepositoryActionRequest::public(
                    &repository,
                    &revision,
                    &subpath,
                    self.bundle_limits,
                )
            },
            |credential| {
                RepositoryActionRequest::authenticated(
                    &repository,
                    &revision,
                    &subpath,
                    credential,
                    self.bundle_limits,
                )
            },
        );
        let bundle =
            self.resolver
                .resolve(action_request)
                .await
                .map_err(|error| {
                    let kind = match error.kind() {
                        ActionResolveErrorKind::Scm => ActionPreparationErrorKind::Resolution,
                        ActionResolveErrorKind::Archive | ActionResolveErrorKind::BlobStore => {
                            ActionPreparationErrorKind::Content
                        }
                        ActionResolveErrorKind::ReferenceCache
                        | ActionResolveErrorKind::Internal => ActionPreparationErrorKind::Internal,
                    };
                    ActionPreparationError::new(kind)
                })?;
        let metadata = self
            .decoder
            .decode(bundle.definition())
            .map_err(|_| ActionPreparationError::new(ActionPreparationErrorKind::Metadata))?;
        prepare_metadata(
            &metadata,
            bundle.archive().digest(),
            bundle.archive_bytes().clone(),
            bundle.subpath().as_str(),
            &self.conditions,
            Some(RepositoryActionSource {
                repository: bundle.repository().as_str(),
                revision: bundle.resolved_revision().as_str(),
            }),
        )
    }

    async fn prepare_planned(
        &self,
        request: PlannedActionPreparationRequest<'_>,
    ) -> Result<PreparedAction, ActionPreparationError> {
        let ActionReference::Repository {
            repository,
            revision,
            subpath,
        } = request.reference()
        else {
            return Err(ActionPreparationError::new(
                ActionPreparationErrorKind::UnsupportedReference,
            ));
        };
        if revision.len() != 40
            || !revision
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(ActionPreparationError::new(
                ActionPreparationErrorKind::UnsupportedReference,
            ));
        }
        let expected_subpath = subpath.as_deref().unwrap_or_default();
        if expected_subpath != request.subpath()
            || automata_ci_core::Sha256Digest::from_bytes(Sha256::digest(request.archive()).into())
                != request.archive_sha256()
        {
            return Err(ActionPreparationError::new(
                ActionPreparationErrorKind::Content,
            ));
        }
        let action_subpath = if expected_subpath.is_empty() {
            ActionSubpath::root()
        } else {
            ActionSubpath::new(expected_subpath.to_owned())
                .map_err(|_| ActionPreparationError::new(ActionPreparationErrorKind::Content))?
        };
        let definition =
            inspect_archive_bytes(request.archive(), &action_subpath, self.bundle_limits)
                .map_err(|_| ActionPreparationError::new(ActionPreparationErrorKind::Content))?;
        let metadata = self
            .decoder
            .decode(&definition)
            .map_err(|_| ActionPreparationError::new(ActionPreparationErrorKind::Metadata))?;
        prepare_metadata(
            &metadata,
            request.archive_sha256(),
            request.archive().clone(),
            expected_subpath,
            &self.conditions,
            Some(RepositoryActionSource {
                repository,
                revision,
            }),
        )
    }
}

#[derive(Clone, Copy)]
struct RepositoryActionSource<'a> {
    repository: &'a str,
    revision: &'a str,
}

fn prepare_metadata(
    metadata: &GithubActionMetadata,
    archive_digest: automata_ci_core::Sha256Digest,
    archive: bytes::Bytes,
    subpath: &str,
    conditions: &GithubConditionCompiler,
    source: Option<RepositoryActionSource<'_>>,
) -> Result<PreparedAction, ActionPreparationError> {
    let definition = prepare_definition(metadata, conditions, source)?;
    PreparedAction::with_definition(archive_digest, archive, subpath, definition)
        .map_err(|_| internal())
}

fn prepare_definition(
    metadata: &GithubActionMetadata,
    conditions: &GithubConditionCompiler,
    source: Option<RepositoryActionSource<'_>>,
) -> Result<PreparedActionDefinition, ActionPreparationError> {
    let execution = if let Some(javascript) = metadata.javascript() {
        PreparedActionExecution::Javascript(Box::new(prepare_javascript(javascript, conditions)?))
    } else if let Some(composite) = metadata.composite() {
        PreparedActionExecution::Composite(prepare_composite(
            composite.steps(),
            conditions,
            source,
        )?)
    } else {
        return Err(ActionPreparationError::new(
            ActionPreparationErrorKind::UnsupportedExecution,
        ));
    };
    let inputs = metadata
        .inputs()
        .iter()
        .map(|input| {
            let default = input
                .default()
                .map(|value| prepare_value(value, conditions))
                .transpose()?;
            PreparedInput::with_metadata(
                input.name(),
                default,
                input.required().map(|value| value.text().to_owned()),
                input.deprecation_message().map(MetadataScalar::text),
            )
            .map_err(|_| metadata_error())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let outputs = metadata
        .outputs()
        .iter()
        .map(|output| {
            let value = output
                .value()
                .map(|value| prepare_value(value, conditions))
                .transpose()?;
            PreparedOutput::new(output.name(), value).map_err(|_| metadata_error())
        })
        .collect::<Result<Vec<_>, _>>()?;
    PreparedActionDefinition::new(inputs, outputs, execution).map_err(|_| metadata_error())
}

fn prepare_javascript(
    javascript: &automata_ci_action_github::JavascriptAction,
    conditions: &GithubConditionCompiler,
) -> Result<PreparedJavascriptAction, ActionPreparationError> {
    let pre_condition = conditions
        .compile_condition(
            Some(javascript.pre_condition().text()),
            GithubConditionPhase::Step,
        )
        .map_err(|_| ActionPreparationError::new(ActionPreparationErrorKind::Metadata))?;
    let post_condition = conditions
        .compile_condition(
            Some(javascript.post_condition().text()),
            GithubConditionPhase::Step,
        )
        .map_err(|_| ActionPreparationError::new(ActionPreparationErrorKind::Metadata))?;
    let javascript = PreparedJavascriptAction::new(
        javascript.runtime(),
        javascript.main().as_str(),
        javascript.pre().map(|path| path.as_str().to_owned()),
        pre_condition,
        javascript.post().map(|path| path.as_str().to_owned()),
        post_condition,
    )
    .map_err(|_| metadata_error())?;
    Ok(javascript)
}

fn prepare_composite(
    steps: &[CompositeStep],
    conditions: &GithubConditionCompiler,
    source: Option<RepositoryActionSource<'_>>,
) -> Result<PreparedCompositeAction, ActionPreparationError> {
    let steps = steps
        .iter()
        .map(|step| match step {
            CompositeStep::Run(step) => {
                prepare_composite_run(step, conditions).map(PreparedCompositeStep::Run)
            }
            CompositeStep::Uses(step) => {
                prepare_composite_uses(step, conditions, source).map(PreparedCompositeStep::Uses)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    PreparedCompositeAction::new(steps).map_err(|_| metadata_error())
}

fn prepare_composite_run(
    step: &CompositeRunStep,
    conditions: &GithubConditionCompiler,
) -> Result<PreparedCompositeRunStep, ActionPreparationError> {
    PreparedCompositeRunStep::new(
        prepare_composite_step_metadata(
            step.name(),
            step.id(),
            step.condition(),
            step.continue_on_error(),
            conditions,
        )?,
        prepare_value(step.run(), conditions)?,
        prepare_value(step.shell(), conditions)?,
        prepare_key_values(step.environment(), conditions)?,
        step.working_directory()
            .map(|value| prepare_value(value, conditions))
            .transpose()?,
    )
    .map_err(|_| metadata_error())
}

fn prepare_composite_uses(
    step: &CompositeUsesStep,
    conditions: &GithubConditionCompiler,
    source: Option<RepositoryActionSource<'_>>,
) -> Result<PreparedCompositeUsesStep, ActionPreparationError> {
    let reference =
        bind_repository_local_reference(prepare_nested_reference(step.uses().text())?, source)?;
    PreparedCompositeUsesStep::new(
        prepare_composite_step_metadata(
            step.name(),
            step.id(),
            step.condition(),
            step.continue_on_error(),
            conditions,
        )?,
        reference,
        prepare_key_values(step.with(), conditions)?,
        prepare_key_values(step.environment(), conditions)?,
    )
    .map_err(|_| metadata_error())
}

fn bind_repository_local_reference(
    reference: ActionReference,
    source: Option<RepositoryActionSource<'_>>,
) -> Result<ActionReference, ActionPreparationError> {
    let (ActionReference::Local { path }, Some(source)) = (&reference, source) else {
        return Ok(reference);
    };
    let relative = path.strip_prefix("./").ok_or_else(metadata_error)?;
    ActionSubpath::new(relative.to_owned()).map_err(|_| metadata_error())?;
    Ok(ActionReference::Repository {
        repository: source.repository.to_owned(),
        revision: source.revision.to_owned(),
        subpath: Some(relative.to_owned()),
    })
}

fn prepare_composite_step_metadata(
    name: Option<&MetadataScalar>,
    id: Option<&MetadataScalar>,
    condition: Option<&MetadataScalar>,
    continue_on_error: Option<&MetadataScalar>,
    conditions: &GithubConditionCompiler,
) -> Result<PreparedCompositeStepMetadata, ActionPreparationError> {
    let name = name
        .map(|value| prepare_value(value, conditions))
        .transpose()?;
    let id = id
        .map(|value| {
            if value.text().contains("${{") {
                return Err(metadata_error());
            }
            StepId::new(value.text()).map_err(|_| metadata_error())
        })
        .transpose()?;
    let condition = conditions
        .compile_condition(
            condition.map(MetadataScalar::text),
            GithubConditionPhase::Step,
        )
        .map_err(|_| metadata_error())?;
    let continue_on_error = match continue_on_error {
        None => PreparedBoolean::Literal(false),
        Some(value) if value.kind() == MetadataScalarKind::Boolean => {
            PreparedBoolean::Literal(value.text().eq_ignore_ascii_case("true"))
        }
        Some(value) => {
            let source = value.text().trim();
            if !source.starts_with("${{") || !source.ends_with("}}") {
                return Err(metadata_error());
            }
            PreparedBoolean::Expression(
                conditions
                    .compile_value_expression(source, GithubConditionPhase::Step)
                    .map_err(|_| metadata_error())?,
            )
        }
    };
    Ok(PreparedCompositeStepMetadata::new(
        name,
        id,
        condition,
        continue_on_error,
    ))
}

fn prepare_key_values(
    values: &[MetadataKeyValue],
    conditions: &GithubConditionCompiler,
) -> Result<Vec<PreparedKeyValue>, ActionPreparationError> {
    values
        .iter()
        .map(|value| {
            PreparedKeyValue::new(value.key(), prepare_value(value.value(), conditions)?)
                .map_err(|_| metadata_error())
        })
        .collect()
}

fn prepare_value(
    value: &MetadataScalar,
    conditions: &GithubConditionCompiler,
) -> Result<PreparedValue, ActionPreparationError> {
    if value.kind() == MetadataScalarKind::Null {
        return Ok(PreparedValue::Literal(String::new()));
    }
    let source = value.text();
    if !source.contains("${{") {
        return Ok(PreparedValue::Literal(source.to_owned()));
    }
    let segments = prepare_template_segments(source, conditions)?;
    if let [PreparedValueSegment::Expression(expression)] = segments.as_slice() {
        return Ok(PreparedValue::Expression(expression.clone()));
    }
    Ok(PreparedValue::Template(segments))
}

fn prepare_template_segments(
    source: &str,
    conditions: &GithubConditionCompiler,
) -> Result<Vec<PreparedValueSegment>, ActionPreparationError> {
    let mut segments = Vec::new();
    let mut cursor = 0;
    while let Some(relative_start) = source[cursor..].find("${{") {
        let start = cursor + relative_start;
        if start > cursor {
            segments.push(PreparedValueSegment::Literal(
                source[cursor..start].to_owned(),
            ));
        }
        let end = find_expression_end(source, start + 3).ok_or_else(metadata_error)?;
        let expression = conditions
            .compile_value_expression(&source[start..end], GithubConditionPhase::Step)
            .map_err(|_| metadata_error())?;
        segments.push(PreparedValueSegment::Expression(expression));
        cursor = end;
    }
    if cursor < source.len() {
        segments.push(PreparedValueSegment::Literal(source[cursor..].to_owned()));
    }
    (!segments.is_empty())
        .then_some(segments)
        .ok_or_else(metadata_error)
}

fn find_expression_end(source: &str, mut cursor: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut quoted = false;
    while cursor < bytes.len() {
        if bytes[cursor] == b'\'' {
            if quoted && bytes.get(cursor + 1) == Some(&b'\'') {
                cursor += 2;
                continue;
            }
            quoted = !quoted;
            cursor += 1;
            continue;
        }
        if !quoted && bytes[cursor..].starts_with(b"${{") {
            return None;
        }
        if !quoted && bytes[cursor..].starts_with(b"}}") {
            return Some(cursor + 2);
        }
        cursor += 1;
    }
    None
}

fn prepare_nested_reference(source: &str) -> Result<ActionReference, ActionPreparationError> {
    if source.contains("${{") {
        return Err(metadata_error());
    }
    if source.starts_with("./") {
        validate_local_reference(source).map_err(|()| metadata_error())?;
        return Ok(ActionReference::Local {
            path: source.to_owned(),
        });
    }
    if source.starts_with("docker://") {
        if source.len() == "docker://".len()
            || source.chars().any(char::is_control)
            || source.chars().any(char::is_whitespace)
        {
            return Err(metadata_error());
        }
        return Ok(ActionReference::Container {
            image: source.to_owned(),
        });
    }
    let (path, revision) = source.split_once('@').ok_or_else(metadata_error)?;
    if source.matches('@').count() != 1 || !valid_action_revision(revision) {
        return Err(metadata_error());
    }
    let components = path.split('/').collect::<Vec<_>>();
    if components.len() < 2
        || !valid_repository_component(components[0])
        || !valid_repository_component(components[1])
        || components[2..]
            .iter()
            .any(|component| !valid_action_component(component))
    {
        return Err(metadata_error());
    }
    Ok(ActionReference::Repository {
        repository: format!("{}/{}", components[0], components[1]),
        revision: revision.to_owned(),
        subpath: (components.len() > 2).then(|| components[2..].join("/")),
    })
}

fn validate_local_reference(source: &str) -> Result<(), ()> {
    let relative = source.strip_prefix("./").ok_or(())?;
    if relative.is_empty()
        || source.len() > 4_096
        || source.ends_with('/')
        || source.contains('\\')
        || source.chars().any(char::is_control)
        || relative
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(());
    }
    Ok(())
}

fn valid_action_component(value: &str) -> bool {
    !value.is_empty()
        && !matches!(value, "." | "..")
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
        && !value.chars().any(char::is_whitespace)
}

fn valid_repository_component(value: &str) -> bool {
    !value.is_empty()
        && !matches!(value, "." | "..")
        && value.len() <= 100
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_action_revision(value: &str) -> bool {
    !value.is_empty()
        && value != "@"
        && value.trim() == value
        && !value.starts_with(['/', '.', '-'])
        && !value.ends_with(['/', '.'])
        && !value.contains("//")
        && !value.contains("..")
        && !value.contains("@{")
        && value.split('/').all(|component| {
            !component.is_empty()
                && !component.starts_with('.')
                && !component.ends_with('.')
                && !component.as_bytes().ends_with(b".lock")
        })
        && !value.chars().any(|character| {
            character.is_control() || character.is_whitespace() || "\\~^:?*[]".contains(character)
        })
}

fn map_metadata_error(
    error: &automata_ci_action_github::MetadataDecodeError,
) -> ActionPreparationError {
    let kind = if error.kind() == MetadataDecodeErrorKind::ResourceLimit {
        ActionPreparationErrorKind::ResourceExhausted
    } else {
        ActionPreparationErrorKind::Metadata
    };
    ActionPreparationError::new(kind)
}

const fn metadata_error() -> ActionPreparationError {
    ActionPreparationError::new(ActionPreparationErrorKind::Metadata)
}

const fn internal() -> ActionPreparationError {
    ActionPreparationError::new(ActionPreparationErrorKind::Internal)
}

#[cfg(test)]
mod tests {
    use automata_ci_action_github::GithubActionMetadataDecoder;

    use super::*;

    #[test]
    fn repository_composite_local_children_bind_to_the_same_immutable_source() {
        let document = ActionDefinitionDocument::metadata_yaml(
            "action.yml",
            Bytes::from_static(
                b"runs:\n  using: composite\n  steps:\n    - uses: ./nested/action\n",
            ),
        );
        let metadata = GithubActionMetadataDecoder::default()
            .decode(&document)
            .expect("metadata");
        let definition = prepare_definition(
            &metadata,
            &GithubConditionCompiler::default(),
            Some(RepositoryActionSource {
                repository: "owner/action",
                revision: "0123456789abcdef0123456789abcdef01234567",
            }),
        )
        .expect("prepared definition");
        let [PreparedCompositeStep::Uses(step)] =
            definition.composite().expect("composite").steps()
        else {
            panic!("one nested action expected")
        };
        assert_eq!(
            step.reference(),
            &ActionReference::Repository {
                repository: "owner/action".to_owned(),
                revision: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                subpath: Some("nested/action".to_owned()),
            }
        );
    }

    #[test]
    fn checked_out_composite_local_children_remain_workspace_references() {
        let document = ActionDefinitionDocument::metadata_yaml(
            "action.yml",
            Bytes::from_static(
                b"runs:\n  using: composite\n  steps:\n    - uses: ./nested/action\n",
            ),
        );
        let metadata = GithubActionMetadataDecoder::default()
            .decode(&document)
            .expect("metadata");
        let definition = prepare_definition(&metadata, &GithubConditionCompiler::default(), None)
            .expect("prepared definition");
        let [PreparedCompositeStep::Uses(step)] =
            definition.composite().expect("composite").steps()
        else {
            panic!("one nested action expected")
        };
        assert_eq!(
            step.reference(),
            &ActionReference::Local {
                path: "./nested/action".to_owned(),
            }
        );
    }
}
