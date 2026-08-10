use std::fmt::Debug;

use crate::{
    Diagnostic, DiagnosticKind, DiagnosticSeverity, GithubWorkflowSourcePlan, SourceFile,
    SourcePlanVersion, SourceProvenance, WorkflowParseLimits, decode::decode_workflow,
    syntax::parse_yaml,
};

/// Borrowed parse request. Provenance is explicit so diagnostics remain useful after ingestion.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ParseWorkflowRequest<'source> {
    provenance: SourceProvenance,
    source: &'source str,
}

impl<'source> ParseWorkflowRequest<'source> {
    /// Creates a request for exact source bytes and their immutable provenance.
    #[must_use]
    pub fn new(provenance: SourceProvenance, source: &'source str) -> Self {
        Self { provenance, source }
    }

    /// Returns the repository/path/revision evidence attached to the source.
    pub fn provenance(&self) -> &SourceProvenance {
        &self.provenance
    }

    /// Returns the borrowed GitHub workflow YAML text.
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

    /// Returns whether a plan exists and no error diagnostic was emitted.
    pub fn is_accepted(&self) -> bool {
        self.plan.is_some()
            && !self
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
    }

    /// Iterates over diagnostics from one frontend stage or limit category.
    pub fn diagnostics_of_kind(&self, kind: DiagnosticKind) -> impl Iterator<Item = &Diagnostic> {
        self.diagnostics
            .iter()
            .filter(move |diagnostic| diagnostic.kind == kind)
    }

    /// Returns the immutable source file retained with this report.
    pub fn source(&self) -> &SourceFile {
        &self.source
    }

    /// Returns the dialect-level plan, if syntax and semantic decoding produced one.
    ///
    /// Parsing does not compile the plan into provider-neutral workflow IR;
    /// callers pass this source plan to the compiler as a separate step.
    pub fn plan(&self) -> Option<&Plan> {
        self.plan.as_ref()
    }

    /// Returns all structured, source-bound diagnostics in emission order.
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
    /// Dialect-owned source plan produced before provider-neutral compilation.
    type Plan: Clone + Debug + Send + Sync + 'static;

    /// Parses and semantically decodes one exact source request.
    fn parse(&self, request: ParseWorkflowRequest<'_>) -> FrontendReport<Self::Plan>;
}

/// Report produced by [`GithubWorkflowFrontend`].
pub type GithubFrontendReport = FrontendReport<GithubWorkflowSourcePlan>;

/// GitHub Actions YAML frontend configured with explicit resource bounds.
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct GithubWorkflowFrontend {
    limits: WorkflowParseLimits,
}

impl GithubWorkflowFrontend {
    /// Creates a GitHub frontend with the supplied YAML parsing bounds.
    #[must_use]
    pub fn new(limits: WorkflowParseLimits) -> Self {
        Self { limits }
    }

    /// Returns the YAML parsing bounds enforced by this frontend.
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
