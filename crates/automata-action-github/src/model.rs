use crate::MetadataLocation;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MetadataScalarStyle {
    Plain,
    SingleQuoted,
    DoubleQuoted,
    Literal,
    Folded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MetadataScalarKind {
    String,
    Null,
    Boolean,
    Integer,
    Float,
}

/// Decoded YAML scalar with its original YAML classification retained.
///
/// Keeping plain `null`, booleans, numbers, quoting style, and expression text
/// distinct lets the later compatibility compiler apply GitHub's context-specific
/// coercion rules without reparsing YAML.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataScalar {
    text: String,
    style: MetadataScalarStyle,
    kind: MetadataScalarKind,
    location: Option<MetadataLocation>,
}

impl MetadataScalar {
    pub(crate) const fn new(
        text: String,
        style: MetadataScalarStyle,
        kind: MetadataScalarKind,
        location: MetadataLocation,
    ) -> Self {
        Self {
            text,
            style,
            kind,
            location: Some(location),
        }
    }

    pub(crate) fn synthetic(value: &str) -> Self {
        Self {
            text: value.to_owned(),
            style: MetadataScalarStyle::Plain,
            kind: MetadataScalarKind::String,
            location: None,
        }
    }

    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    #[must_use]
    pub const fn style(&self) -> MetadataScalarStyle {
        self.style
    }

    #[must_use]
    pub const fn kind(&self) -> MetadataScalarKind {
        self.kind
    }

    #[must_use]
    pub const fn location(&self) -> Option<MetadataLocation> {
        self.location
    }
}

/// Validated action-bundle-relative executable path.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MetadataEntryPath {
    declared: String,
    canonical: String,
}

impl MetadataEntryPath {
    pub(crate) const fn from_validated(declared: String, canonical: String) -> Self {
        Self {
            declared,
            canonical,
        }
    }

    #[must_use]
    pub fn declared(&self) -> &str {
        &self.declared
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.canonical
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataKeyValue {
    key: String,
    value: MetadataScalar,
}

impl MetadataKeyValue {
    pub(crate) const fn new(key: String, value: MetadataScalar) -> Self {
        Self { key, value }
    }

    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    #[must_use]
    pub const fn value(&self) -> &MetadataScalar {
        &self.value
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionInput {
    name: String,
    description: Option<MetadataScalar>,
    required: Option<MetadataScalar>,
    default: Option<MetadataScalar>,
    deprecation_message: Option<MetadataScalar>,
}

impl ActionInput {
    pub(crate) const fn new(
        name: String,
        description: Option<MetadataScalar>,
        required: Option<MetadataScalar>,
        default: Option<MetadataScalar>,
        deprecation_message: Option<MetadataScalar>,
    ) -> Self {
        Self {
            name,
            description,
            required,
            default,
            deprecation_message,
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn description(&self) -> Option<&MetadataScalar> {
        self.description.as_ref()
    }

    #[must_use]
    pub const fn required(&self) -> Option<&MetadataScalar> {
        self.required.as_ref()
    }

    #[must_use]
    pub const fn default(&self) -> Option<&MetadataScalar> {
        self.default.as_ref()
    }

    #[must_use]
    pub const fn deprecation_message(&self) -> Option<&MetadataScalar> {
        self.deprecation_message.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionOutput {
    name: String,
    description: Option<MetadataScalar>,
    value: Option<MetadataScalar>,
}

impl ActionOutput {
    pub(crate) const fn new(
        name: String,
        description: Option<MetadataScalar>,
        value: Option<MetadataScalar>,
    ) -> Self {
        Self {
            name,
            description,
            value,
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn description(&self) -> Option<&MetadataScalar> {
        self.description.as_ref()
    }

    #[must_use]
    pub const fn value(&self) -> Option<&MetadataScalar> {
        self.value.as_ref()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JavascriptRuntime {
    Node12,
    Node16,
    Node20,
    Node24,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JavascriptAction {
    runtime: JavascriptRuntime,
    main: MetadataEntryPath,
    pre: Option<MetadataEntryPath>,
    pre_condition: MetadataScalar,
    post: Option<MetadataEntryPath>,
    post_condition: MetadataScalar,
}

impl JavascriptAction {
    pub(crate) const fn new(
        runtime: JavascriptRuntime,
        main: MetadataEntryPath,
        pre: Option<MetadataEntryPath>,
        pre_condition: MetadataScalar,
        post: Option<MetadataEntryPath>,
        post_condition: MetadataScalar,
    ) -> Self {
        Self {
            runtime,
            main,
            pre,
            pre_condition,
            post,
            post_condition,
        }
    }

    #[must_use]
    pub const fn runtime(&self) -> JavascriptRuntime {
        self.runtime
    }

    #[must_use]
    pub const fn main(&self) -> &MetadataEntryPath {
        &self.main
    }

    #[must_use]
    pub const fn pre(&self) -> Option<&MetadataEntryPath> {
        self.pre.as_ref()
    }

    #[must_use]
    pub const fn pre_condition(&self) -> &MetadataScalar {
        &self.pre_condition
    }

    #[must_use]
    pub const fn post(&self) -> Option<&MetadataEntryPath> {
        self.post.as_ref()
    }

    #[must_use]
    pub const fn post_condition(&self) -> &MetadataScalar {
        &self.post_condition
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DockerImageKind {
    Local,
    Registry,
}

/// Validated local Dockerfile path or `docker://` image reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerImage {
    kind: DockerImageKind,
    value: String,
    local_path: Option<MetadataEntryPath>,
}

impl DockerImage {
    pub(crate) const fn local(value: String, path: MetadataEntryPath) -> Self {
        Self {
            kind: DockerImageKind::Local,
            value,
            local_path: Some(path),
        }
    }

    pub(crate) const fn registry(value: String) -> Self {
        Self {
            kind: DockerImageKind::Registry,
            value,
            local_path: None,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> DockerImageKind {
        self.kind
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    #[must_use]
    pub const fn local_path(&self) -> Option<&MetadataEntryPath> {
        self.local_path.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerAction {
    image: DockerImage,
    entrypoint: Option<MetadataScalar>,
    arguments: Vec<MetadataScalar>,
    environment: Vec<MetadataKeyValue>,
    pre_entrypoint: Option<MetadataScalar>,
    pre_condition: MetadataScalar,
    post_entrypoint: Option<MetadataScalar>,
    post_condition: MetadataScalar,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DockerLifecycle {
    pre_entrypoint: Option<MetadataScalar>,
    pre_condition: MetadataScalar,
    post_entrypoint: Option<MetadataScalar>,
    post_condition: MetadataScalar,
}

impl DockerLifecycle {
    pub(crate) fn new(
        pre_entrypoint: Option<MetadataScalar>,
        pre_condition: MetadataScalar,
        post_entrypoint: Option<MetadataScalar>,
        post_condition: MetadataScalar,
    ) -> Self {
        Self {
            pre_entrypoint,
            pre_condition,
            post_entrypoint,
            post_condition,
        }
    }
}

impl DockerAction {
    pub(crate) fn new(
        image: DockerImage,
        entrypoint: Option<MetadataScalar>,
        arguments: Vec<MetadataScalar>,
        environment: Vec<MetadataKeyValue>,
        lifecycle: DockerLifecycle,
    ) -> Self {
        let DockerLifecycle {
            pre_entrypoint,
            pre_condition,
            post_entrypoint,
            post_condition,
        } = lifecycle;
        Self {
            image,
            entrypoint,
            arguments,
            environment,
            pre_entrypoint,
            pre_condition,
            post_entrypoint,
            post_condition,
        }
    }

    #[must_use]
    pub const fn image(&self) -> &DockerImage {
        &self.image
    }

    #[must_use]
    pub const fn entrypoint(&self) -> Option<&MetadataScalar> {
        self.entrypoint.as_ref()
    }

    #[must_use]
    pub fn arguments(&self) -> &[MetadataScalar] {
        &self.arguments
    }

    #[must_use]
    pub fn environment(&self) -> &[MetadataKeyValue] {
        &self.environment
    }

    #[must_use]
    pub const fn pre_entrypoint(&self) -> Option<&MetadataScalar> {
        self.pre_entrypoint.as_ref()
    }

    #[must_use]
    pub const fn pre_condition(&self) -> &MetadataScalar {
        &self.pre_condition
    }

    #[must_use]
    pub const fn post_entrypoint(&self) -> Option<&MetadataScalar> {
        self.post_entrypoint.as_ref()
    }

    #[must_use]
    pub const fn post_condition(&self) -> &MetadataScalar {
        &self.post_condition
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositeRunStep {
    name: Option<MetadataScalar>,
    id: Option<MetadataScalar>,
    condition: Option<MetadataScalar>,
    run: MetadataScalar,
    shell: MetadataScalar,
    environment: Vec<MetadataKeyValue>,
    continue_on_error: Option<MetadataScalar>,
    working_directory: Option<MetadataScalar>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompositeStepMetadata {
    name: Option<MetadataScalar>,
    id: Option<MetadataScalar>,
    condition: Option<MetadataScalar>,
    continue_on_error: Option<MetadataScalar>,
}

impl CompositeStepMetadata {
    pub(crate) fn new(
        name: Option<MetadataScalar>,
        id: Option<MetadataScalar>,
        condition: Option<MetadataScalar>,
        continue_on_error: Option<MetadataScalar>,
    ) -> Self {
        Self {
            name,
            id,
            condition,
            continue_on_error,
        }
    }
}

impl CompositeRunStep {
    pub(crate) fn new(
        metadata: CompositeStepMetadata,
        run: MetadataScalar,
        shell: MetadataScalar,
        environment: Vec<MetadataKeyValue>,
        working_directory: Option<MetadataScalar>,
    ) -> Self {
        let CompositeStepMetadata {
            name,
            id,
            condition,
            continue_on_error,
        } = metadata;
        Self {
            name,
            id,
            condition,
            run,
            shell,
            environment,
            continue_on_error,
            working_directory,
        }
    }

    #[must_use]
    pub const fn name(&self) -> Option<&MetadataScalar> {
        self.name.as_ref()
    }

    #[must_use]
    pub const fn id(&self) -> Option<&MetadataScalar> {
        self.id.as_ref()
    }

    #[must_use]
    pub const fn condition(&self) -> Option<&MetadataScalar> {
        self.condition.as_ref()
    }

    #[must_use]
    pub const fn run(&self) -> &MetadataScalar {
        &self.run
    }

    #[must_use]
    pub const fn shell(&self) -> &MetadataScalar {
        &self.shell
    }

    #[must_use]
    pub fn environment(&self) -> &[MetadataKeyValue] {
        &self.environment
    }

    #[must_use]
    pub const fn continue_on_error(&self) -> Option<&MetadataScalar> {
        self.continue_on_error.as_ref()
    }

    #[must_use]
    pub const fn working_directory(&self) -> Option<&MetadataScalar> {
        self.working_directory.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositeUsesStep {
    name: Option<MetadataScalar>,
    id: Option<MetadataScalar>,
    condition: Option<MetadataScalar>,
    uses: MetadataScalar,
    with: Vec<MetadataKeyValue>,
    environment: Vec<MetadataKeyValue>,
    continue_on_error: Option<MetadataScalar>,
}

impl CompositeUsesStep {
    pub(crate) fn new(
        metadata: CompositeStepMetadata,
        uses: MetadataScalar,
        with: Vec<MetadataKeyValue>,
        environment: Vec<MetadataKeyValue>,
    ) -> Self {
        let CompositeStepMetadata {
            name,
            id,
            condition,
            continue_on_error,
        } = metadata;
        Self {
            name,
            id,
            condition,
            uses,
            with,
            environment,
            continue_on_error,
        }
    }

    #[must_use]
    pub const fn name(&self) -> Option<&MetadataScalar> {
        self.name.as_ref()
    }

    #[must_use]
    pub const fn id(&self) -> Option<&MetadataScalar> {
        self.id.as_ref()
    }

    #[must_use]
    pub const fn condition(&self) -> Option<&MetadataScalar> {
        self.condition.as_ref()
    }

    #[must_use]
    pub const fn uses(&self) -> &MetadataScalar {
        &self.uses
    }

    #[must_use]
    pub fn with(&self) -> &[MetadataKeyValue] {
        &self.with
    }

    #[must_use]
    pub fn environment(&self) -> &[MetadataKeyValue] {
        &self.environment
    }

    #[must_use]
    pub const fn continue_on_error(&self) -> Option<&MetadataScalar> {
        self.continue_on_error.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompositeStep {
    Run(CompositeRunStep),
    Uses(CompositeUsesStep),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositeAction {
    steps: Vec<CompositeStep>,
}

impl CompositeAction {
    pub(crate) const fn new(steps: Vec<CompositeStep>) -> Self {
        Self { steps }
    }

    #[must_use]
    pub fn steps(&self) -> &[CompositeStep] {
        &self.steps
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionExecution {
    Javascript(JavascriptAction),
    Docker(DockerAction),
    Composite(CompositeAction),
}

/// Semantically decoded action definition, retaining source order for all user maps.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubActionMetadata {
    name: Option<String>,
    description: Option<String>,
    inputs: Vec<ActionInput>,
    outputs: Vec<ActionOutput>,
    execution: ActionExecution,
    ignored_top_level_keys: Vec<String>,
}

impl GithubActionMetadata {
    pub(crate) const fn new(
        name: Option<String>,
        description: Option<String>,
        inputs: Vec<ActionInput>,
        outputs: Vec<ActionOutput>,
        execution: ActionExecution,
        ignored_top_level_keys: Vec<String>,
    ) -> Self {
        Self {
            name,
            description,
            inputs,
            outputs,
            execution,
            ignored_top_level_keys,
        }
    }

    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    #[must_use]
    pub fn inputs(&self) -> &[ActionInput] {
        &self.inputs
    }

    #[must_use]
    pub fn outputs(&self) -> &[ActionOutput] {
        &self.outputs
    }

    #[must_use]
    pub const fn execution(&self) -> &ActionExecution {
        &self.execution
    }

    #[must_use]
    pub fn ignored_top_level_keys(&self) -> &[String] {
        &self.ignored_top_level_keys
    }

    #[must_use]
    pub const fn javascript(&self) -> Option<&JavascriptAction> {
        match &self.execution {
            ActionExecution::Javascript(action) => Some(action),
            ActionExecution::Docker(_) | ActionExecution::Composite(_) => None,
        }
    }

    #[must_use]
    pub const fn docker(&self) -> Option<&DockerAction> {
        match &self.execution {
            ActionExecution::Docker(action) => Some(action),
            ActionExecution::Javascript(_) | ActionExecution::Composite(_) => None,
        }
    }

    #[must_use]
    pub const fn composite(&self) -> Option<&CompositeAction> {
        match &self.execution {
            ActionExecution::Composite(action) => Some(action),
            ActionExecution::Javascript(_) | ActionExecution::Docker(_) => None,
        }
    }
}
