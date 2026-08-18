//! Compilation from the loss-aware GitHub source model into the neutral workflow DAG.

mod expression;
mod logical;
mod lowering;
mod safety;
mod trigger;

use automata_ci_core::{
    ContextValue, Located, PlanSourceLocation, PlanSourceOrigin, PlanSourceSpan, Sha256Digest,
    WorkflowEventProvenance, WorkflowPlan, WorkflowSourceProvenance,
};

use crate::{
    Diagnostic, DiagnosticKind, DiagnosticSeverity, EventName, EventTrigger,
    GithubWorkflowDispatchContract, GithubWorkflowSourcePlan, PreservedField,
    ProviderEventMetadata, SourceOrigin, SourceSpan, TriggerConfiguration,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LocalWorkflowSourceEvidence {
    snapshot_digest: Sha256Digest,
}

impl LocalWorkflowSourceEvidence {
    pub(crate) const fn new(snapshot_digest: Sha256Digest) -> Self {
        Self { snapshot_digest }
    }

    const fn snapshot_digest(self) -> Sha256Digest {
        self.snapshot_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LocalWorkflowDispatchEvidence {
    source: LocalWorkflowSourceEvidence,
    inputs: crate::GithubWorkflowDispatchInputs,
}

impl LocalWorkflowDispatchEvidence {
    pub(crate) const fn new(
        source: LocalWorkflowSourceEvidence,
        inputs: crate::GithubWorkflowDispatchInputs,
    ) -> Self {
        Self { source, inputs }
    }
}

/// Borrowed request to select and compile one GitHub event invocation.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct CompileWorkflowRequest<'plan> {
    source_plan: &'plan GithubWorkflowSourcePlan,
    event: WorkflowEventProvenance,
    selection: EventSelection,
}

#[derive(Clone, Debug)]
enum EventSelection {
    Unverified,
    Metadata(ProviderEventMetadata),
    Preselected(Option<ProviderEventMetadata>),
    LocalWorkflowDispatch(LocalWorkflowDispatchEvidence),
    LocalWorkflowCall(LocalWorkflowSourceEvidence),
}

impl EventSelection {
    const fn source_provider(&self) -> &'static str {
        match self {
            Self::Unverified | Self::Metadata(_) | Self::Preselected(_) => "github",
            Self::LocalWorkflowDispatch(_) | Self::LocalWorkflowCall(_) => "local",
        }
    }
}

impl<'plan> CompileWorkflowRequest<'plan> {
    /// Creates an initial-admission request whose event evidence still requires
    /// GitHub trigger selection.
    ///
    /// Attach verified provider metadata with
    /// [`Self::with_event_metadata`] when the configured trigger requires it.
    #[must_use]
    pub const fn new(
        source_plan: &'plan GithubWorkflowSourcePlan,
        event: WorkflowEventProvenance,
    ) -> Self {
        Self {
            source_plan,
            event,
            selection: EventSelection::Unverified,
        }
    }

    /// Attaches verified GitHub provider fields used for trigger selection.
    #[must_use]
    pub fn with_event_metadata(mut self, metadata: ProviderEventMetadata) -> Self {
        self.selection = EventSelection::Metadata(metadata);
        self
    }

    /// Recompiles an event that was already selected into an immutable plan.
    ///
    /// This mode validates that the plan's configured trigger span still names
    /// the exact trigger in this exact source. It deliberately does not replay
    /// provider filtering because provider-specific webhook fields are not part
    /// of the durable workflow plan. Callers must use it only for a plan
    /// previously emitted by this compiler, never for initial webhook
    /// admission.
    #[must_use]
    pub fn for_preselected_event(
        source_plan: &'plan GithubWorkflowSourcePlan,
        event: WorkflowEventProvenance,
    ) -> Self {
        Self {
            source_plan,
            event,
            selection: EventSelection::Preselected(None),
        }
    }

    /// Recompiles an already-selected event with its durable provider
    /// selection evidence.
    ///
    /// This is the replay boundary for selector values that are intentionally
    /// absent from the provider-neutral workflow plan. The caller must load
    /// the metadata from immutable evidence already bound to admission, never
    /// reconstruct it from an unauthenticated request.
    #[must_use]
    pub fn for_preselected_event_with_metadata(
        source_plan: &'plan GithubWorkflowSourcePlan,
        event: WorkflowEventProvenance,
        metadata: ProviderEventMetadata,
    ) -> Self {
        Self {
            source_plan,
            event,
            selection: EventSelection::Preselected(Some(metadata)),
        }
    }

    /// Selects an explicit local `workflow_dispatch` invocation.
    ///
    /// This is the only initial local-event constructor. It emits `local`
    /// source/event provenance and verifies the source repository revision is
    /// the exact evidence digest. It never accepts GitHub delivery metadata.
    #[must_use]
    pub(crate) fn for_local_workflow_dispatch(
        source_plan: &'plan GithubWorkflowSourcePlan,
        evidence: LocalWorkflowDispatchEvidence,
    ) -> Self {
        Self {
            source_plan,
            event: WorkflowEventProvenance::new("local", "workflow_dispatch"),
            selection: EventSelection::LocalWorkflowDispatch(evidence),
        }
    }

    /// Compiles one same-snapshot reusable workflow for `workflow_call`.
    ///
    /// The request remains local source authority even though the parsed
    /// syntax and expression dialect are GitHub Actions compatible.
    #[must_use]
    pub(crate) fn for_local_workflow_call(
        source_plan: &'plan GithubWorkflowSourcePlan,
        evidence: LocalWorkflowSourceEvidence,
    ) -> Self {
        Self {
            source_plan,
            event: WorkflowEventProvenance::new("local", "workflow_call"),
            selection: EventSelection::LocalWorkflowCall(evidence),
        }
    }

    /// Returns the exact parsed source plan to compile.
    #[must_use]
    pub const fn source_plan(&self) -> &'plan GithubWorkflowSourcePlan {
        self.source_plan
    }

    /// Returns the immutable event provenance being selected.
    #[must_use]
    pub const fn event(&self) -> &WorkflowEventProvenance {
        &self.event
    }
}

/// Closed reason that a valid workflow did not select the current event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WorkflowNotSelectedReason {
    /// The workflow does not configure the current event.
    EventNotConfigured,
    /// GitHub does not start workflow runs for a deleted push ref.
    DeletedPush,
    /// The event did not match valid branch, tag, activity, or path filters.
    EventFiltersNotMatched,
    /// The firing cron is not configured by this workflow.
    ScheduleNotConfigured,
}

/// Machine-readable result of selecting and compiling one workflow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CompilationDisposition {
    /// The event selected the workflow and a scheduler plan is available.
    Accepted,
    /// Selection reached a path filter that requires provider-verified diff evidence.
    RequiresChangedFiles,
    /// The workflow is valid but does not select this event.
    NotSelected(WorkflowNotSelectedReason),
    /// Invalid source, event evidence, or provider metadata rejected compilation.
    Rejected,
}

/// Compilation output. Any error diagnostic suppresses the scheduler plan.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct CompilationReport {
    plan: Option<WorkflowPlan>,
    diagnostics: Vec<Diagnostic>,
    disposition: CompilationDisposition,
    workflow_dispatch_contract: Option<GithubWorkflowDispatchContract>,
    workflow_dispatch_inputs: Option<ContextValue>,
}

impl CompilationReport {
    /// Returns the provider-neutral scheduler plan when compilation was accepted.
    #[must_use]
    pub const fn plan(&self) -> Option<&WorkflowPlan> {
        self.plan.as_ref()
    }

    /// Returns structured source diagnostics produced during selection and lowering.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Returns the machine-readable compilation disposition.
    #[must_use]
    pub const fn disposition(&self) -> CompilationDisposition {
        self.disposition
    }

    /// Returns the validated manual-dispatch source contract for an accepted invocation.
    #[must_use]
    pub const fn workflow_dispatch_contract(&self) -> Option<&GithubWorkflowDispatchContract> {
        self.workflow_dispatch_contract.as_ref()
    }

    /// Returns the canonical `inputs` object for an accepted manual-dispatch invocation.
    ///
    /// This value is suitable for later admission-context hydration. It is
    /// available only when the compiler validated bounded provider evidence
    /// against the exact selected source contract.
    #[must_use]
    pub const fn workflow_dispatch_inputs(&self) -> Option<&ContextValue> {
        self.workflow_dispatch_inputs.as_ref()
    }

    /// Returns whether event selection and provider-neutral compilation succeeded.
    #[must_use]
    pub fn is_accepted(&self) -> bool {
        self.disposition == CompilationDisposition::Accepted
    }

    /// Reports that selection can continue only with provider-verified changed files.
    #[must_use]
    pub const fn requires_changed_files(&self) -> bool {
        matches!(
            self.disposition,
            CompilationDisposition::RequiresChangedFiles
        )
    }

    /// Consumes the report into its optional plan and sanitized diagnostics.
    ///
    /// Use [`Self::disposition`] before consuming the report when a caller must
    /// distinguish valid non-selection from rejection or missing diff evidence.
    #[must_use]
    pub fn into_parts(self) -> (Option<WorkflowPlan>, Vec<Diagnostic>) {
        (self.plan, self.diagnostics)
    }
}

/// GitHub Actions workflow compiler. It performs no action fetching or execution.
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct GithubWorkflowCompiler;

impl GithubWorkflowCompiler {
    /// Creates a stateless GitHub source-plan compiler.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Selects the request event and lowers the exact source plan into workflow IR.
    ///
    /// The compiler performs no provider I/O, action fetching, or execution. It
    /// reports provider changed-file demand as a typed disposition.
    #[must_use]
    pub fn compile(&self, request: CompileWorkflowRequest<'_>) -> CompilationReport {
        logical::compile(request)
    }
}

#[derive(Debug)]
pub(super) struct CompileContext<'plan> {
    source: &'plan GithubWorkflowSourcePlan,
    diagnostics: Vec<Diagnostic>,
}

#[derive(Debug)]
pub(super) enum CompiledEvent {
    Selected {
        event: Box<WorkflowEventProvenance>,
        workflow_dispatch: Option<Box<CompiledWorkflowDispatch>>,
    },
    RequiresChangedFiles,
    NotSelected(WorkflowNotSelectedReason),
    Rejected,
}

#[derive(Debug)]
pub(super) struct CompiledWorkflowDispatch {
    pub(super) contract: GithubWorkflowDispatchContract,
    pub(super) inputs: ContextValue,
}

impl CompileContext<'_> {
    pub(super) fn unsupported(&mut self, code: &str, message: impl Into<String>, span: SourceSpan) {
        self.diagnostics.push(Diagnostic::error(
            DiagnosticKind::Unsupported,
            code,
            message,
            span,
        ));
    }

    pub(super) fn semantic(&mut self, code: &str, message: impl Into<String>, span: SourceSpan) {
        self.diagnostics.push(Diagnostic::error(
            DiagnosticKind::Semantic,
            code,
            message,
            span,
        ));
    }

    fn span(&mut self, span: &SourceSpan) -> Option<PlanSourceSpan> {
        let start = self.location(span.start(), span)?;
        let end = self.location(span.end(), span)?;
        match PlanSourceSpan::new(span.source_id().as_str(), start, end) {
            Ok(converted) => Some(converted),
            Err(error) => {
                self.semantic(
                    "github.compile.invalid_source_span",
                    error.to_string(),
                    span.clone(),
                );
                None
            }
        }
    }

    fn location(
        &mut self,
        location: crate::SourceLocation,
        span: &SourceSpan,
    ) -> Option<PlanSourceLocation> {
        let Ok(byte_offset) = u64::try_from(location.byte_offset()) else {
            self.semantic(
                "github.compile.source_coordinate_overflow",
                "source byte offset exceeds the workflow-plan representation",
                span.clone(),
            );
            return None;
        };
        let (Ok(line), Ok(column)) = (
            u32::try_from(location.line()),
            u32::try_from(location.column()),
        ) else {
            self.semantic(
                "github.compile.source_coordinate_overflow",
                "source line or column exceeds the workflow-plan representation",
                span.clone(),
            );
            return None;
        };
        PlanSourceLocation::new(byte_offset, line, column)
            .map_err(|error| {
                self.semantic(
                    "github.compile.invalid_source_location",
                    error.to_string(),
                    span.clone(),
                );
            })
            .ok()
    }

    fn located<T>(&mut self, value: T, span: &SourceSpan) -> Option<Located<T>> {
        self.span(span)
            .map(|converted| Located::new(value, converted))
    }

    fn reject_extensions(&mut self, extensions: &[PreservedField]) {
        for extension in extensions {
            self.unsupported(
                "github.compile.unsupported_field",
                format!(
                    "`{}` has no workflow-plan representation and cannot be dropped",
                    extension.path()
                ),
                extension.entry().key().span().clone(),
            );
        }
    }
}

fn has_errors(diagnostics: &[Diagnostic]) -> bool {
    diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity() == DiagnosticSeverity::Error)
}

fn compile_source(
    context: &CompileContext<'_>,
    source_provider: &'static str,
) -> WorkflowSourceProvenance {
    let provenance = context.source.source().provenance();
    let origin = match provenance.origin() {
        SourceOrigin::Repository {
            repository,
            revision,
            path,
        } => PlanSourceOrigin::Repository {
            repository: repository.to_string(),
            revision: *revision,
            path: path.to_string(),
        },
        SourceOrigin::Archive {
            snapshot_digest,
            path,
        } => PlanSourceOrigin::Archive {
            snapshot_digest: *snapshot_digest,
            path: path.to_string(),
        },
        SourceOrigin::LocalPath { path } => PlanSourceOrigin::LocalPath {
            path: path.to_string(),
        },
        SourceOrigin::Memory { name } => PlanSourceOrigin::Memory {
            name: name.to_string(),
        },
    };
    WorkflowSourceProvenance::new(source_provider, provenance.id().as_str(), origin)
}

fn compile_event(
    event: WorkflowEventProvenance,
    selection: &EventSelection,
    context: &mut CompileContext<'_>,
) -> CompiledEvent {
    if !validate_event_authority(&event, selection, context) {
        return CompiledEvent::Rejected;
    }
    let Some(triggers) = context.source.workflow().triggers() else {
        context.semantic(
            "github.compile.missing_triggers",
            "workflow has no trigger set",
            context.source.workflow().span().clone(),
        );
        return CompiledEvent::Rejected;
    };

    let selected_index = triggers
        .events()
        .iter()
        .position(|trigger| event_name(trigger.name().value()) == event.name());
    let mut selected_dispatch_contract = None;
    for (index, trigger) in triggers.events().iter().enumerate() {
        if let EventName::Other(name) = trigger.name().value() {
            context.unsupported(
                "github.compile.provider_event_unavailable",
                format!(
                    "GitHub provider ingress does not normalize the `{name}` event; the workflow cannot be published"
                ),
                trigger.name().span().clone(),
            );
        }
        reject_unsupported_trigger(trigger.configuration(), context);
        let dispatch_contract = trigger::validate_configuration(
            trigger.name().value(),
            trigger.configuration(),
            trigger.span(),
            context,
        );
        if Some(index) == selected_index {
            selected_dispatch_contract = dispatch_contract;
        }
    }
    let Some(selected_index) = selected_index else {
        return CompiledEvent::NotSelected(WorkflowNotSelectedReason::EventNotConfigured);
    };
    let selected = &triggers.events()[selected_index];
    if matches!(selected.name().value(), EventName::Other(_)) {
        return CompiledEvent::Rejected;
    }
    let Some(span) = context.span(selected.span()) else {
        return CompiledEvent::Rejected;
    };
    compile_selected_event(
        event,
        selection,
        selected,
        selected_dispatch_contract,
        span,
        context,
    )
}

fn compile_selected_event(
    event: WorkflowEventProvenance,
    selection: &EventSelection,
    selected: &EventTrigger,
    selected_dispatch_contract: Option<GithubWorkflowDispatchContract>,
    span: PlanSourceSpan,
    context: &mut CompileContext<'_>,
) -> CompiledEvent {
    match selection {
        EventSelection::Preselected(metadata) => compile_preselected_event(
            event,
            matches!(selected.name().value(), EventName::WorkflowDispatch),
            selected_dispatch_contract,
            metadata.as_ref(),
            &span,
            selected.span(),
            context,
        ),
        EventSelection::Metadata(metadata) => {
            let event = match metadata.changed_files_evidence_digest() {
                Some(digest) => event.with_selection_digest(digest),
                None => event,
            };
            trigger::event_matches(
                &event,
                selected.configuration(),
                selected_dispatch_contract.as_ref(),
                Some(metadata),
                selected.span(),
                context,
            )
            .with_event(event, span)
        }
        EventSelection::Unverified => trigger::event_matches(
            &event,
            selected.configuration(),
            selected_dispatch_contract.as_ref(),
            None,
            selected.span(),
            context,
        )
        .with_event(event, span),
        EventSelection::LocalWorkflowDispatch(evidence) => {
            if !matches!(selected.name().value(), EventName::WorkflowDispatch) {
                context.semantic(
                    "github.compile.local_event_selection",
                    "local source checking selects only an explicit workflow_dispatch trigger",
                    selected.span().clone(),
                );
                return CompiledEvent::Rejected;
            }
            trigger::local_workflow_dispatch_matches(
                selected_dispatch_contract.as_ref(),
                &evidence.inputs,
                selected.span(),
                context,
            )
            .with_event(event, span)
        }
        EventSelection::LocalWorkflowCall(_) => {
            if !matches!(selected.name().value(), EventName::WorkflowCall) {
                context.semantic(
                    "github.compile.local_event_selection",
                    "local reusable-workflow compilation selects only workflow_call",
                    selected.span().clone(),
                );
                return CompiledEvent::Rejected;
            }
            trigger::event_matches(
                &event,
                selected.configuration(),
                selected_dispatch_contract.as_ref(),
                None,
                selected.span(),
                context,
            )
            .with_event(event, span)
        }
    }
}

fn validate_event_authority(
    event: &WorkflowEventProvenance,
    selection: &EventSelection,
    context: &mut CompileContext<'_>,
) -> bool {
    let expected_provider = selection.source_provider();
    if event.provider() != expected_provider {
        context.semantic(
            "github.compile.event_provider",
            format!(
                "workflow source authority `{expected_provider}` cannot accept `{}` event provenance",
                event.provider(),
            ),
            context.source.workflow().span().clone(),
        );
        return false;
    }
    if let Some(evidence) = match selection {
        EventSelection::LocalWorkflowDispatch(evidence) => Some(evidence.source),
        EventSelection::LocalWorkflowCall(evidence) => Some(*evidence),
        EventSelection::Unverified
        | EventSelection::Metadata(_)
        | EventSelection::Preselected(_) => None,
    } {
        let SourceOrigin::Archive {
            snapshot_digest, ..
        } = context.source.source().provenance().origin()
        else {
            context.semantic(
                "github.compile.local_source_origin",
                "local workflow compilation requires repository snapshot provenance",
                context.source.workflow().span().clone(),
            );
            return false;
        };
        if *snapshot_digest != evidence.snapshot_digest() {
            context.semantic(
                "github.compile.local_snapshot_mismatch",
                "local workflow source revision does not match its snapshot evidence",
                context.source.workflow().span().clone(),
            );
            return false;
        }
    }
    true
}

fn compile_preselected_event(
    event: WorkflowEventProvenance,
    workflow_dispatch: bool,
    dispatch_contract: Option<GithubWorkflowDispatchContract>,
    metadata: Option<&ProviderEventMetadata>,
    configured_span: &PlanSourceSpan,
    trigger_span: &SourceSpan,
    context: &mut CompileContext<'_>,
) -> CompiledEvent {
    match event.configured_trigger_span() {
        Some(configured) if configured == configured_span => {}
        Some(_) => {
            context.semantic(
                "github.compile.preselected_trigger_mismatch",
                "preselected event trigger span does not identify this source's configured event",
                trigger_span.clone(),
            );
            return CompiledEvent::Rejected;
        }
        None => {
            context.semantic(
                "github.compile.preselected_trigger_required",
                "preselected event recompilation requires a configured trigger span",
                trigger_span.clone(),
            );
            return CompiledEvent::Rejected;
        }
    }
    if !workflow_dispatch {
        if metadata.is_some() {
            context.semantic(
                "github.compile.preselected_event_metadata_mismatch",
                "durable preselected metadata is not supported for this event",
                trigger_span.clone(),
            );
            return CompiledEvent::Rejected;
        }
        return CompiledEvent::Selected {
            event: Box::new(event),
            workflow_dispatch: None,
        };
    }
    let Some(contract) = dispatch_contract else {
        return CompiledEvent::Rejected;
    };
    let Some(workflow_dispatch) =
        trigger::compile_preselected_workflow_dispatch(&contract, metadata, trigger_span, context)
    else {
        return CompiledEvent::Rejected;
    };
    CompiledEvent::Selected {
        event: Box::new(event),
        workflow_dispatch: Some(Box::new(workflow_dispatch)),
    }
}

fn event_name(event: &EventName) -> &str {
    match event {
        EventName::Push => "push",
        EventName::PullRequest => "pull_request",
        EventName::MergeGroup => "merge_group",
        EventName::RepositoryDispatch => "repository_dispatch",
        EventName::WorkflowDispatch => "workflow_dispatch",
        EventName::Schedule => "schedule",
        EventName::WorkflowCall => "workflow_call",
        EventName::Other(name) => name,
    }
}

fn reject_unsupported_trigger(
    configuration: &TriggerConfiguration,
    context: &mut CompileContext<'_>,
) {
    match configuration {
        TriggerConfiguration::Push(filter) | TriggerConfiguration::PullRequest(filter) => {
            context.reject_extensions(filter.extensions());
        }
        TriggerConfiguration::MergeGroup(filter) => {
            context.reject_extensions(filter.extensions());
        }
        TriggerConfiguration::RepositoryDispatch(filter) => {
            context.reject_extensions(filter.extensions());
        }
        TriggerConfiguration::Preserved(node) => context.unsupported(
            "github.compile.event_configuration",
            "event configuration has no durable workflow-plan representation",
            node.span().clone(),
        ),
        TriggerConfiguration::Empty
        | TriggerConfiguration::WorkflowDispatch(_)
        | TriggerConfiguration::Schedule(_)
        | TriggerConfiguration::WorkflowCall(_) => {}
    }
}
