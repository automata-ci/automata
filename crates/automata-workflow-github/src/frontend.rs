use std::fmt::Debug;

use crate::{
    Diagnostic, DiagnosticKind, DiagnosticSeverity, GithubWorkflowSourcePlan, SourceFile,
    SourcePlanVersion, SourceProvenance,
    decode::decode_workflow,
    syntax::{ParseLimits, parse_yaml},
};

pub type WorkflowParseLimits = ParseLimits;

/// Borrowed parse request. Provenance is explicit so diagnostics remain useful after ingestion.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ParseWorkflowRequest<'source> {
    provenance: SourceProvenance,
    source: &'source str,
}

impl<'source> ParseWorkflowRequest<'source> {
    pub fn new(provenance: SourceProvenance, source: &'source str) -> Self {
        Self { provenance, source }
    }

    pub fn provenance(&self) -> &SourceProvenance {
        &self.provenance
    }

    pub const fn source(&self) -> &'source str {
        self.source
    }
}

/// A frontend report can retain a source-level plan even when diagnostics exist.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct FrontendReport<Plan> {
    source: SourceFile,
    plan: Option<Plan>,
    diagnostics: Vec<Diagnostic>,
}

impl<Plan> FrontendReport<Plan> {
    /// Creates a report from an immutable source, an optional dialect-owned
    /// plan, and structured diagnostics.
    #[must_use]
    pub fn new(source: SourceFile, plan: Option<Plan>, diagnostics: Vec<Diagnostic>) -> Self {
        Self {
            source,
            plan,
            diagnostics,
        }
    }

    pub fn is_accepted(&self) -> bool {
        self.plan.is_some()
            && !self
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
    }

    pub fn diagnostics_of_kind(&self, kind: DiagnosticKind) -> impl Iterator<Item = &Diagnostic> {
        self.diagnostics
            .iter()
            .filter(move |diagnostic| diagnostic.kind == kind)
    }

    pub fn source(&self) -> &SourceFile {
        &self.source
    }

    pub fn plan(&self) -> Option<&Plan> {
        self.plan.as_ref()
    }

    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Decomposes the immutable report without exposing mutable fields.
    #[must_use]
    pub fn into_parts(self) -> (SourceFile, Option<Plan>, Vec<Diagnostic>) {
        (self.source, self.plan, self.diagnostics)
    }
}

/// Source-frontend boundary whose plan type is owned by each dialect.
///
/// The associated type prevents a non-GitHub frontend from having to emit a
/// GitHub syntax tree. A heterogeneous registry erases frontends only after
/// they compile their source plan into the shared workflow-plan/JobIR layer.
pub trait WorkflowFrontend: Debug + Send + Sync {
    type Plan: Clone + Debug + Send + Sync + 'static;

    fn parse(&self, request: ParseWorkflowRequest<'_>) -> FrontendReport<Self::Plan>;
}

/// Report produced by [`GithubWorkflowFrontend`].
pub type GithubFrontendReport = FrontendReport<GithubWorkflowSourcePlan>;

#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct GithubWorkflowFrontend {
    limits: WorkflowParseLimits,
}

impl GithubWorkflowFrontend {
    pub fn new(limits: WorkflowParseLimits) -> Self {
        Self { limits }
    }

    pub fn limits(&self) -> WorkflowParseLimits {
        self.limits
    }
}

impl WorkflowFrontend for GithubWorkflowFrontend {
    type Plan = GithubWorkflowSourcePlan;

    fn parse(&self, request: ParseWorkflowRequest<'_>) -> GithubFrontendReport {
        let source = SourceFile::new(request.provenance, request.source);
        let syntax = parse_yaml(&source, self.limits);
        let mut diagnostics = syntax.diagnostics;
        if syntax.fatal {
            return FrontendReport {
                source,
                plan: None,
                diagnostics,
            };
        }

        if syntax.documents.len() != 1 {
            let span = syntax
                .documents
                .first()
                .map_or_else(|| source_span(&source), |document| document.span.clone());
            diagnostics.push(Diagnostic::error(
                DiagnosticKind::Semantic,
                "github.document_count",
                format!(
                    "GitHub workflow source must contain exactly one YAML document; found {}",
                    syntax.documents.len()
                ),
                span,
            ));
            return FrontendReport {
                source,
                plan: None,
                diagnostics,
            };
        }

        let document = syntax
            .documents
            .into_iter()
            .next()
            .expect("document count was checked");
        let workflow = decode_workflow(&document.root, &mut diagnostics);
        let plan = workflow.map(|workflow| GithubWorkflowSourcePlan {
            version: SourcePlanVersion::V1,
            source: source.clone(),
            document,
            workflow,
        });

        FrontendReport {
            source,
            plan,
            diagnostics,
        }
    }
}

fn source_span(source: &SourceFile) -> crate::SourceSpan {
    let start = crate::SourceLocation::new(0, 1, 1);
    crate::SourceSpan::new(source.provenance().id().clone(), start, start)
}
