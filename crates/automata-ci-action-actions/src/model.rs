use crate::MetadataLocation;

/// YAML presentation style retained for a decoded scalar.
///
/// Style is preserved because quoting and block syntax affect GitHub-compatible scalar coercion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MetadataScalarStyle {
    /// An unquoted plain scalar.
    Plain,
    /// A scalar delimited by single quotes.
    SingleQuoted,
    /// A scalar delimited by double quotes.
    DoubleQuoted,
    /// A literal block scalar introduced by `|`.
    Literal,
    /// A folded block scalar introduced by `>`.
    Folded,
}

/// YAML scalar classification retained without converting the source text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MetadataScalarKind {
    /// Text that has string semantics, including every quoted scalar.
    String,
    /// A plain YAML null spelling, including an empty scalar.
    Null,
    /// A plain YAML boolean spelling.
    Boolean,
    /// A plain YAML integer spelling.
    Integer,
    /// A plain YAML floating-point spelling.
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
    /// Returns the decoded scalar text without runtime coercion or expression evaluation.
    pub fn text(&self) -> &str {
        &self.text
    }

    #[must_use]
    /// Returns the scalar's original YAML presentation style.
    pub const fn style(&self) -> MetadataScalarStyle {
        self.style
    }

    #[must_use]
    /// Returns the scalar's YAML-compatible semantic classification.
    pub const fn kind(&self) -> MetadataScalarKind {
        self.kind
    }

    #[must_use]
    /// Returns the scalar's one-based source position.
    ///
    /// Decoder-supplied defaults such as `always()` are synthetic and therefore have no source
    /// location.
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
    /// Returns the path exactly as declared in metadata.
    ///
    /// This may retain harmless `.` components that were removed from the canonical form.
    pub fn declared(&self) -> &str {
        &self.declared
    }

    #[must_use]
    /// Returns the canonical bundle-relative path used for safe lookup.
    pub fn as_str(&self) -> &str {
        &self.canonical
    }
}

/// One ordered metadata mapping entry whose value remains an uncoerced scalar.
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
    /// Returns the mapping key exactly as decoded.
    pub fn key(&self) -> &str {
        &self.key
    }

    #[must_use]
    /// Returns the unevaluated mapping value.
    pub const fn value(&self) -> &MetadataScalar {
        &self.value
    }
}

/// One declared action input and its optional metadata.
///
/// Input names and declaration order are preserved without case normalization. Values remain
/// YAML scalars for the later compatibility compiler; this decoder does not coerce defaults,
/// bind caller inputs, or evaluate expressions.
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
    /// Returns the declared input name.
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    /// Returns the scalar description when the loose upstream field used a scalar value.
    pub const fn description(&self) -> Option<&MetadataScalar> {
        self.description.as_ref()
    }

    #[must_use]
    /// Returns the scalar required marker when the loose upstream field used a scalar value.
    pub const fn required(&self) -> Option<&MetadataScalar> {
        self.required.as_ref()
    }

    #[must_use]
    /// Returns the declared default without coercion or expression evaluation.
    pub const fn default(&self) -> Option<&MetadataScalar> {
        self.default.as_ref()
    }

    #[must_use]
    /// Returns the deprecation message associated with the input, when declared.
    pub const fn deprecation_message(&self) -> Option<&MetadataScalar> {
        self.deprecation_message.as_ref()
    }
}

/// One declared action output and its deferred value expression.
///
/// Output names and declaration order are preserved without case normalization. Values are not
/// resolved against step outputs by this metadata layer.
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
    /// Returns the declared output name.
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    /// Returns the optional output description without coercion.
    pub const fn description(&self) -> Option<&MetadataScalar> {
        self.description.as_ref()
    }

    #[must_use]
    /// Returns the optional output value without evaluating expressions.
    pub const fn value(&self) -> Option<&MetadataScalar> {
        self.value.as_ref()
    }
}

/// JavaScript runtime selected by the action's `runs.using` value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JavascriptRuntime {
    /// The legacy Node.js 12 runner runtime.
    Node12,
    /// The legacy Node.js 16 runner runtime.
    Node16,
    /// The Node.js 20 runner runtime.
    Node20,
    /// The Node.js 24 runner runtime.
    Node24,
}

/// A decoded JavaScript action lifecycle.
///
/// Executable paths are canonical, bundle-relative paths. Lifecycle conditions remain deferred
/// scalars and default to a synthetic `always()` value when omitted.
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
    /// Returns the selected Node.js runtime generation.
    pub const fn runtime(&self) -> JavascriptRuntime {
        self.runtime
    }

    #[must_use]
    /// Returns the required main-script path within the immutable action bundle.
    pub const fn main(&self) -> &MetadataEntryPath {
        &self.main
    }

    #[must_use]
    /// Returns the optional pre-script path within the immutable action bundle.
    pub const fn pre(&self) -> Option<&MetadataEntryPath> {
        self.pre.as_ref()
    }

    #[must_use]
    /// Returns the unevaluated pre-script condition.
    ///
    /// An omitted `pre-if` is represented by a synthetic `always()` scalar.
    pub const fn pre_condition(&self) -> &MetadataScalar {
        &self.pre_condition
    }

    #[must_use]
    /// Returns the optional post-script path within the immutable action bundle.
    pub const fn post(&self) -> Option<&MetadataEntryPath> {
        self.post.as_ref()
    }

    #[must_use]
    /// Returns the unevaluated post-script condition.
    ///
    /// An omitted `post-if` is represented by a synthetic `always()` scalar.
    pub const fn post_condition(&self) -> &MetadataScalar {
        &self.post_condition
    }
}

/// Addressing form used by a Docker action image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DockerImageKind {
    /// A validated Dockerfile path relative to the immutable action bundle.
    Local,
    /// A deferred `docker://` registry reference.
    Registry,
}

/// Validated local Dockerfile path or `docker://` image reference.
///
/// Registry values are bounded and reject whitespace, control characters, and expressions, but
/// this metadata layer does not require a digest. An admission or execution layer must apply any
/// immutable-container-image policy before pulling the image.
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
    /// Returns whether the image names a local Dockerfile or a registry reference.
    pub const fn kind(&self) -> DockerImageKind {
        self.kind
    }

    #[must_use]
    /// Returns the image value as declared in metadata.
    ///
    /// For a registry image this retains the `docker://` prefix and its original ASCII casing.
    pub fn as_str(&self) -> &str {
        &self.value
    }

    #[must_use]
    /// Returns the canonical bundle-relative Dockerfile path for a local image.
    ///
    /// Registry images have no local path.
    pub const fn local_path(&self) -> Option<&MetadataEntryPath> {
        self.local_path.as_ref()
    }
}

/// A decoded Docker action lifecycle and its deferred runtime values.
///
/// Arguments, environment values, entrypoints, and conditions retain source order and scalar
/// classification. They are not expression-evaluated or interpreted as host paths here.
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
    /// Returns the validated local Dockerfile or deferred registry image reference.
    pub const fn image(&self) -> &DockerImage {
        &self.image
    }

    #[must_use]
    /// Returns the optional main container entrypoint without evaluating it.
    pub const fn entrypoint(&self) -> Option<&MetadataScalar> {
        self.entrypoint.as_ref()
    }

    #[must_use]
    /// Returns container arguments in declaration order.
    pub fn arguments(&self) -> &[MetadataScalar] {
        &self.arguments
    }

    #[must_use]
    /// Returns container environment entries in declaration order.
    pub fn environment(&self) -> &[MetadataKeyValue] {
        &self.environment
    }

    #[must_use]
    /// Returns the optional pre-container entrypoint without evaluating it.
    pub const fn pre_entrypoint(&self) -> Option<&MetadataScalar> {
        self.pre_entrypoint.as_ref()
    }

    #[must_use]
    /// Returns the unevaluated pre-container condition.
    ///
    /// An omitted `pre-if` is represented by a synthetic `always()` scalar.
    pub const fn pre_condition(&self) -> &MetadataScalar {
        &self.pre_condition
    }

    #[must_use]
    /// Returns the optional post-container entrypoint without evaluating it.
    pub const fn post_entrypoint(&self) -> Option<&MetadataScalar> {
        self.post_entrypoint.as_ref()
    }

    #[must_use]
    /// Returns the unevaluated post-container condition.
    ///
    /// An omitted `post-if` is represented by a synthetic `always()` scalar.
    pub const fn post_condition(&self) -> &MetadataScalar {
        &self.post_condition
    }
}

/// One shell-command step in a composite action.
///
/// All command, shell, environment, condition, and directory values remain deferred metadata
/// scalars. This type describes the action; it does not execute the command.
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
    /// Returns the optional human-readable step name.
    pub const fn name(&self) -> Option<&MetadataScalar> {
        self.name.as_ref()
    }

    #[must_use]
    /// Returns the optional step identifier.
    pub const fn id(&self) -> Option<&MetadataScalar> {
        self.id.as_ref()
    }

    #[must_use]
    /// Returns the optional unevaluated `if` condition.
    pub const fn condition(&self) -> Option<&MetadataScalar> {
        self.condition.as_ref()
    }

    #[must_use]
    /// Returns the shell command text without evaluating expressions.
    pub const fn run(&self) -> &MetadataScalar {
        &self.run
    }

    #[must_use]
    /// Returns the required shell declaration without runtime interpretation.
    pub const fn shell(&self) -> &MetadataScalar {
        &self.shell
    }

    #[must_use]
    /// Returns step environment entries in declaration order.
    pub fn environment(&self) -> &[MetadataKeyValue] {
        &self.environment
    }

    #[must_use]
    /// Returns the optional continue-on-error boolean or deferred expression.
    pub const fn continue_on_error(&self) -> Option<&MetadataScalar> {
        self.continue_on_error.as_ref()
    }

    #[must_use]
    /// Returns the optional deferred working-directory value.
    ///
    /// Unlike executable entry paths, this runtime value is not resolved against the bundle by
    /// the metadata decoder.
    pub const fn working_directory(&self) -> Option<&MetadataScalar> {
        self.working_directory.as_ref()
    }
}

/// One nested-action invocation step in a composite action.
///
/// The `uses` value is preserved but is not resolved here. Before execution, callers must resolve
/// repository references to immutable revisions and apply policy to local or Docker references.
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
    /// Returns the optional human-readable step name.
    pub const fn name(&self) -> Option<&MetadataScalar> {
        self.name.as_ref()
    }

    #[must_use]
    /// Returns the optional step identifier.
    pub const fn id(&self) -> Option<&MetadataScalar> {
        self.id.as_ref()
    }

    #[must_use]
    /// Returns the optional unevaluated `if` condition.
    pub const fn condition(&self) -> Option<&MetadataScalar> {
        self.condition.as_ref()
    }

    #[must_use]
    /// Returns the unresolved nested-action reference exactly as a decoded scalar.
    pub const fn uses(&self) -> &MetadataScalar {
        &self.uses
    }

    #[must_use]
    /// Returns nested-action inputs in declaration order.
    pub fn with(&self) -> &[MetadataKeyValue] {
        &self.with
    }

    #[must_use]
    /// Returns step environment entries in declaration order.
    pub fn environment(&self) -> &[MetadataKeyValue] {
        &self.environment
    }

    #[must_use]
    /// Returns the optional continue-on-error boolean or deferred expression.
    pub const fn continue_on_error(&self) -> Option<&MetadataScalar> {
        self.continue_on_error.as_ref()
    }
}

/// Classified composite-action step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompositeStep {
    /// A shell-command step.
    Run(CompositeRunStep),
    /// A nested-action invocation step.
    Uses(CompositeUsesStep),
}

/// A composite action containing ordered, classified steps.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositeAction {
    steps: Vec<CompositeStep>,
}

impl CompositeAction {
    pub(crate) const fn new(steps: Vec<CompositeStep>) -> Self {
        Self { steps }
    }

    #[must_use]
    /// Returns composite steps in source order.
    pub fn steps(&self) -> &[CompositeStep] {
        &self.steps
    }
}

/// Execution implementation selected by the action's `runs.using` value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionExecution {
    /// A Node.js-backed action.
    Javascript(JavascriptAction),
    /// A container-backed action.
    Docker(DockerAction),
    /// An ordered sequence of run and nested-action steps.
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
    /// Returns the top-level action name when declared under the exact canonical `name` key.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    #[must_use]
    /// Returns the description when declared under the exact canonical `description` key.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    #[must_use]
    /// Returns input declarations in source order.
    pub fn inputs(&self) -> &[ActionInput] {
        &self.inputs
    }

    #[must_use]
    /// Returns output declarations in source order.
    pub fn outputs(&self) -> &[ActionOutput] {
        &self.outputs
    }

    #[must_use]
    /// Returns the classified action execution definition.
    pub const fn execution(&self) -> &ActionExecution {
        &self.execution
    }

    #[must_use]
    /// Returns accepted but semantically ignored top-level keys in source order.
    ///
    /// The reviewed GitHub runner treats the action root as loose. This list also records known
    /// keys that used non-canonical casing and were therefore validated but not projected into
    /// the canonical field.
    pub fn ignored_top_level_keys(&self) -> &[String] {
        &self.ignored_top_level_keys
    }

    #[must_use]
    /// Returns the JavaScript definition when [`Self::execution`] is JavaScript.
    pub const fn javascript(&self) -> Option<&JavascriptAction> {
        match &self.execution {
            ActionExecution::Javascript(action) => Some(action),
            ActionExecution::Docker(_) | ActionExecution::Composite(_) => None,
        }
    }

    #[must_use]
    /// Returns the Docker definition when [`Self::execution`] is Docker.
    pub const fn docker(&self) -> Option<&DockerAction> {
        match &self.execution {
            ActionExecution::Docker(action) => Some(action),
            ActionExecution::Javascript(_) | ActionExecution::Composite(_) => None,
        }
    }

    #[must_use]
    /// Returns the composite definition when [`Self::execution`] is composite.
    pub const fn composite(&self) -> Option<&CompositeAction> {
        match &self.execution {
            ActionExecution::Composite(action) => Some(action),
            ActionExecution::Javascript(_) | ActionExecution::Docker(_) => None,
        }
    }
}
