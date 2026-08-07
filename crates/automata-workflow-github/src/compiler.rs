//! Compilation from the loss-aware GitHub source model into the neutral workflow DAG.

mod expression;
mod lowering;
mod safety;

use std::fmt::Debug;

use automata_core::{
    Located, PlanSourceLocation, PlanSourceOrigin, PlanSourceSpan, WorkflowEventProvenance,
    WorkflowPlan, WorkflowSourceProvenance,
};

use lowering::{
    compile_concurrency, compile_defaults, compile_job, compile_permissions, compile_value_map,
    located_spanned_value, located_text,
};
use safety::scan_lossy_yaml;

use crate::{
    Diagnostic, DiagnosticKind, DiagnosticSeverity, EventName, GithubWorkflowSourcePlan,
    PreservedField, SourceOrigin, SourceSpan, TriggerConfiguration,
};

/// Borrowed request to compile one already-selected GitHub event invocation.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct CompileWorkflowRequest<'plan> {
    source_plan: &'plan GithubWorkflowSourcePlan,
    event: WorkflowEventProvenance,
}

impl<'plan> CompileWorkflowRequest<'plan> {
    #[must_use]
    pub const fn new(
        source_plan: &'plan GithubWorkflowSourcePlan,
        event: WorkflowEventProvenance,
    ) -> Self {
        Self { source_plan, event }
    }

    #[must_use]
    pub const fn source_plan(&self) -> &'plan GithubWorkflowSourcePlan {
        self.source_plan
    }

    #[must_use]
    pub const fn event(&self) -> &WorkflowEventProvenance {
        &self.event
    }
}

/// Compilation output. Any error diagnostic suppresses the scheduler plan.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct CompilationReport {
    plan: Option<WorkflowPlan>,
    diagnostics: Vec<Diagnostic>,
}

impl CompilationReport {
    #[must_use]
    pub const fn plan(&self) -> Option<&WorkflowPlan> {
        self.plan.as_ref()
    }

    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    #[must_use]
    pub fn is_accepted(&self) -> bool {
        self.plan.is_some()
            && !self
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.severity() == DiagnosticSeverity::Error)
    }

    #[must_use]
    pub fn into_parts(self) -> (Option<WorkflowPlan>, Vec<Diagnostic>) {
        (self.plan, self.diagnostics)
    }
}

/// Provider frontend compiler boundary.
pub trait WorkflowCompiler: Debug + Send + Sync {
    type SourcePlan: Clone + Debug + Send + Sync + 'static;

    fn compile(
        &self,
        source_plan: &Self::SourcePlan,
        event: WorkflowEventProvenance,
    ) -> CompilationReport;
}

/// GitHub Actions workflow compiler. It performs no action fetching or execution.
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct GithubWorkflowCompiler;

impl GithubWorkflowCompiler {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn compile(&self, request: CompileWorkflowRequest<'_>) -> CompilationReport {
        compile_github_workflow(request)
    }
}

impl WorkflowCompiler for GithubWorkflowCompiler {
    type SourcePlan = GithubWorkflowSourcePlan;

    fn compile(
        &self,
        source_plan: &Self::SourcePlan,
        event: WorkflowEventProvenance,
    ) -> CompilationReport {
        self.compile(CompileWorkflowRequest::new(source_plan, event))
    }
}

#[derive(Debug)]
struct CompileContext<'plan> {
    source: &'plan GithubWorkflowSourcePlan,
    diagnostics: Vec<Diagnostic>,
}

impl CompileContext<'_> {
    fn unsupported(&mut self, code: &str, message: impl Into<String>, span: SourceSpan) {
        self.diagnostics.push(Diagnostic::error(
            DiagnosticKind::Unsupported,
            code,
            message,
            span,
        ));
    }

    fn semantic(&mut self, code: &str, message: impl Into<String>, span: SourceSpan) {
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

fn compile_github_workflow(request: CompileWorkflowRequest<'_>) -> CompilationReport {
    let mut context = CompileContext {
        source: request.source_plan,
        diagnostics: Vec::new(),
    };
    scan_lossy_yaml(request.source_plan.document().root(), &mut context);

    let workflow = request.source_plan.workflow();
    context.reject_extensions(workflow.extensions());
    let event = compile_event(request.event, &mut context);
    let source = compile_source(&context);
    let name = workflow
        .name()
        .and_then(|value| located_text(value, &mut context));
    let run_name = workflow
        .run_name()
        .and_then(|value| located_spanned_value(value, &mut context));
    let permissions = workflow
        .permissions()
        .and_then(|value| compile_permissions(value, &mut context));
    let environment = compile_value_map(workflow.environment(), &mut context);
    let run_defaults = compile_defaults(workflow.defaults(), &mut context);
    let concurrency = workflow
        .concurrency()
        .and_then(|value| compile_concurrency(value, &mut context));
    let jobs = workflow
        .jobs()
        .iter()
        .filter_map(|job| compile_job(job, &mut context))
        .collect::<Vec<_>>();
    let span = context.span(workflow.span());

    let plan = match (event, span) {
        (Some(event), Some(span)) if !has_errors(&context.diagnostics) => {
            match WorkflowPlan::builder(source, event, jobs, span)
                .name(name)
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
                        "github.compile.invalid_workflow_plan",
                        error.to_string(),
                        workflow.span().clone(),
                    );
                    None
                }
            }
        }
        _ => None,
    };
    CompilationReport {
        plan,
        diagnostics: context.diagnostics,
    }
}

fn has_errors(diagnostics: &[Diagnostic]) -> bool {
    diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity() == DiagnosticSeverity::Error)
}

fn compile_source(context: &CompileContext<'_>) -> WorkflowSourceProvenance {
    let provenance = context.source.source().provenance();
    let origin = match provenance.origin() {
        SourceOrigin::Repository {
            repository,
            revision,
            path,
        } => PlanSourceOrigin::Repository {
            repository: repository.to_string(),
            revision: revision.to_string(),
            path: path.to_string(),
        },
        SourceOrigin::LocalPath { path } => PlanSourceOrigin::LocalPath {
            path: path.to_string(),
        },
        SourceOrigin::Memory { name } => PlanSourceOrigin::Memory {
            name: name.to_string(),
        },
    };
    WorkflowSourceProvenance::new("github", provenance.id().as_str(), origin)
}

fn compile_event(
    event: WorkflowEventProvenance,
    context: &mut CompileContext<'_>,
) -> Option<WorkflowEventProvenance> {
    if event.provider() != "github" {
        context.semantic(
            "github.compile.event_provider",
            format!(
                "GitHub workflow compiler cannot accept `{}` event provenance",
                event.provider()
            ),
            context.source.workflow().span().clone(),
        );
        return None;
    }
    let Some(triggers) = context.source.workflow().triggers() else {
        context.semantic(
            "github.compile.missing_triggers",
            "workflow has no trigger set",
            context.source.workflow().span().clone(),
        );
        return None;
    };

    for trigger in triggers.events() {
        reject_unsupported_trigger(trigger.configuration(), context);
    }
    let selected = triggers
        .events()
        .iter()
        .find(|trigger| event_name(trigger.name().value()) == event.name());
    let Some(selected) = selected else {
        context.semantic(
            "github.compile.event_not_configured",
            format!(
                "event `{}` is not configured by this workflow",
                event.name()
            ),
            triggers.span().clone(),
        );
        return None;
    };
    let span = context.span(selected.span())?;
    Some(event.with_configured_trigger_span(span))
}

fn event_name(event: &EventName) -> &str {
    match event {
        EventName::Push => "push",
        EventName::PullRequest => "pull_request",
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
        TriggerConfiguration::WorkflowDispatch(Some(node)) => context.unsupported(
            "github.compile.workflow_dispatch_inputs",
            "configured workflow_dispatch inputs are not represented by workflow-plan v1",
            node.span().clone(),
        ),
        TriggerConfiguration::Schedule(node) => context.unsupported(
            "github.compile.schedule",
            "schedule configuration is not represented by workflow-plan v1",
            node.span().clone(),
        ),
        TriggerConfiguration::WorkflowCall(node) => context.unsupported(
            "github.compile.workflow_call",
            "reusable workflow configuration is not represented by workflow-plan v1",
            node.span().clone(),
        ),
        TriggerConfiguration::Preserved(node) => context.unsupported(
            "github.compile.event_configuration",
            "event configuration is not represented by workflow-plan v1",
            node.span().clone(),
        ),
        TriggerConfiguration::Empty | TriggerConfiguration::WorkflowDispatch(None) => {}
    }
}
