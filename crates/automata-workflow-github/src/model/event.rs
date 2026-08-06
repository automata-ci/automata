use crate::{PreservedField, SourceSpan, Spanned, YamlNode};

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EventName {
    Push,
    PullRequest,
    WorkflowDispatch,
    Schedule,
    WorkflowCall,
    Other(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct PushPullRequestFilter {
    pub(crate) branches: Vec<Spanned<String>>,
    pub(crate) branches_ignore: Vec<Spanned<String>>,
    pub(crate) tags: Vec<Spanned<String>>,
    pub(crate) tags_ignore: Vec<Spanned<String>>,
    pub(crate) paths: Vec<Spanned<String>>,
    pub(crate) paths_ignore: Vec<Spanned<String>>,
    pub(crate) types: Vec<Spanned<String>>,
    pub(crate) extensions: Vec<PreservedField>,
}

impl PushPullRequestFilter {
    pub(crate) const fn empty() -> Self {
        Self {
            branches: Vec::new(),
            branches_ignore: Vec::new(),
            tags: Vec::new(),
            tags_ignore: Vec::new(),
            paths: Vec::new(),
            paths_ignore: Vec::new(),
            types: Vec::new(),
            extensions: Vec::new(),
        }
    }

    pub fn branches(&self) -> &[Spanned<String>] {
        &self.branches
    }

    pub fn branches_ignore(&self) -> &[Spanned<String>] {
        &self.branches_ignore
    }

    pub fn tags(&self) -> &[Spanned<String>] {
        &self.tags
    }

    pub fn tags_ignore(&self) -> &[Spanned<String>] {
        &self.tags_ignore
    }

    pub fn paths(&self) -> &[Spanned<String>] {
        &self.paths
    }

    pub fn paths_ignore(&self) -> &[Spanned<String>] {
        &self.paths_ignore
    }

    pub fn types(&self) -> &[Spanned<String>] {
        &self.types
    }

    pub fn extensions(&self) -> &[PreservedField] {
        &self.extensions
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TriggerConfiguration {
    Empty,
    Push(PushPullRequestFilter),
    PullRequest(PushPullRequestFilter),
    WorkflowDispatch(Option<YamlNode>),
    Schedule(YamlNode),
    WorkflowCall(YamlNode),
    Preserved(YamlNode),
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct EventTrigger {
    pub(crate) name: Spanned<EventName>,
    pub(crate) configuration: TriggerConfiguration,
    pub(crate) span: SourceSpan,
}

impl EventTrigger {
    pub fn name(&self) -> &Spanned<EventName> {
        &self.name
    }

    pub fn configuration(&self) -> &TriggerConfiguration {
        &self.configuration
    }

    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct TriggerSet {
    pub(crate) events: Vec<EventTrigger>,
    pub(crate) span: SourceSpan,
}

impl TriggerSet {
    pub fn events(&self) -> &[EventTrigger] {
        &self.events
    }

    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

pub type WorkflowTriggers = TriggerSet;
