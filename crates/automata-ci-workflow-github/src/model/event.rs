use crate::{PreservedField, SourceSpan, Spanned, YamlNode};

/// GitHub workflow event name as retained by the source dialect.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EventName {
    /// A Git reference push.
    Push,
    /// A pull-request activity event.
    PullRequest,
    /// A manually dispatched workflow invocation.
    WorkflowDispatch,
    /// A scheduled cron invocation.
    Schedule,
    /// A reusable-workflow invocation.
    WorkflowCall,
    /// An event name preserved for diagnostics but unsupported by current compilation.
    Other(String),
}

/// Source-preserving branch, tag, path, and activity filters for push or pull requests.
///
/// Each `*_configured` method distinguishes an absent key from an explicitly
/// empty list, which is significant during exact trigger selection.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct PushPullRequestFilter {
    pub(crate) branches: Option<Vec<Spanned<String>>>,
    pub(crate) branches_ignore: Option<Vec<Spanned<String>>>,
    pub(crate) tags: Option<Vec<Spanned<String>>>,
    pub(crate) tags_ignore: Option<Vec<Spanned<String>>>,
    pub(crate) paths: Option<Vec<Spanned<String>>>,
    pub(crate) paths_ignore: Option<Vec<Spanned<String>>>,
    pub(crate) types: Option<Vec<Spanned<String>>>,
    pub(crate) extensions: Vec<PreservedField>,
}

impl PushPullRequestFilter {
    pub(crate) const fn empty() -> Self {
        Self {
            branches: None,
            branches_ignore: None,
            tags: None,
            tags_ignore: None,
            paths: None,
            paths_ignore: None,
            types: None,
            extensions: Vec::new(),
        }
    }

    /// Returns configured branch inclusion patterns in source order.
    pub fn branches(&self) -> &[Spanned<String>] {
        self.branches.as_deref().unwrap_or_default()
    }

    /// Returns whether the `branches` key appeared, including an empty list.
    pub const fn branches_configured(&self) -> bool {
        self.branches.is_some()
    }

    /// Returns configured branch exclusion patterns in source order.
    pub fn branches_ignore(&self) -> &[Spanned<String>] {
        self.branches_ignore.as_deref().unwrap_or_default()
    }

    /// Returns whether the `branches-ignore` key appeared.
    pub const fn branches_ignore_configured(&self) -> bool {
        self.branches_ignore.is_some()
    }

    /// Returns configured tag inclusion patterns in source order.
    pub fn tags(&self) -> &[Spanned<String>] {
        self.tags.as_deref().unwrap_or_default()
    }

    /// Returns whether the `tags` key appeared.
    pub const fn tags_configured(&self) -> bool {
        self.tags.is_some()
    }

    /// Returns configured tag exclusion patterns in source order.
    pub fn tags_ignore(&self) -> &[Spanned<String>] {
        self.tags_ignore.as_deref().unwrap_or_default()
    }

    /// Returns whether the `tags-ignore` key appeared.
    pub const fn tags_ignore_configured(&self) -> bool {
        self.tags_ignore.is_some()
    }

    /// Returns configured changed-path inclusion patterns in source order.
    pub fn paths(&self) -> &[Spanned<String>] {
        self.paths.as_deref().unwrap_or_default()
    }

    /// Returns whether the `paths` key appeared.
    pub const fn paths_configured(&self) -> bool {
        self.paths.is_some()
    }

    /// Returns configured changed-path exclusion patterns in source order.
    pub fn paths_ignore(&self) -> &[Spanned<String>] {
        self.paths_ignore.as_deref().unwrap_or_default()
    }

    /// Returns whether the `paths-ignore` key appeared.
    pub const fn paths_ignore_configured(&self) -> bool {
        self.paths_ignore.is_some()
    }

    /// Returns configured pull-request activity types in source order.
    pub fn types(&self) -> &[Spanned<String>] {
        self.types.as_deref().unwrap_or_default()
    }

    /// Returns whether the `types` key appeared.
    pub const fn types_configured(&self) -> bool {
        self.types.is_some()
    }

    /// Returns fields retained from source but unsupported by current selection.
    pub fn extensions(&self) -> &[PreservedField] {
        &self.extensions
    }
}

/// Source form of one event's trigger configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TriggerConfiguration {
    /// The event name was configured without a mapping.
    Empty,
    /// Push selection filters.
    Push(PushPullRequestFilter),
    /// Pull-request selection filters.
    PullRequest(PushPullRequestFilter),
    /// Optional manual-dispatch configuration retained as YAML.
    WorkflowDispatch(Option<YamlNode>),
    /// Schedule configuration retained for bounded cron selection.
    Schedule(YamlNode),
    /// Reusable-workflow call configuration retained for decoding.
    WorkflowCall(YamlNode),
    /// An otherwise valid configuration unsupported by the current compiler.
    Preserved(YamlNode),
}

/// One source-bound event entry from a workflow's `on` configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct EventTrigger {
    pub(crate) name: Spanned<EventName>,
    pub(crate) configuration: TriggerConfiguration,
    pub(crate) span: SourceSpan,
}

impl EventTrigger {
    /// Returns the normalized event name and its exact source span.
    pub fn name(&self) -> &Spanned<EventName> {
        &self.name
    }

    /// Returns the source-preserving trigger configuration.
    pub fn configuration(&self) -> &TriggerConfiguration {
        &self.configuration
    }

    /// Returns the exact source span covering this trigger entry.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

/// Source-ordered set of configured workflow events.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct TriggerSet {
    pub(crate) events: Vec<EventTrigger>,
    pub(crate) span: SourceSpan,
}

impl TriggerSet {
    /// Returns configured events in source order.
    pub fn events(&self) -> &[EventTrigger] {
        &self.events
    }

    /// Returns the exact source span covering the trigger set.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

/// Workflow-facing name for a [`TriggerSet`].
pub type WorkflowTriggers = TriggerSet;
