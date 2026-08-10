use std::sync::Arc;

use automata_ci_core::PlanSourceOrigin;
use automata_ci_workflow_github::{
    CompileWorkflowRequest, Diagnostic, GithubWorkflowCompiler, GithubWorkflowFrontend,
    ParseWorkflowRequest, SourceId, SourceOrigin, SourceProvenance, WorkflowFrontend as _,
};

use crate::{WorkflowAdmissionRequest, WorkflowPlanVerificationError, WorkflowPlanVerifier};

/// GitHub adapter that re-parses and recompiles exact admitted source.
#[derive(Clone, Copy, Debug, Default)]
pub struct GithubWorkflowPlanVerifier;

impl GithubWorkflowPlanVerifier {
    /// Creates a stateless verifier for GitHub workflow source.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl WorkflowPlanVerifier for GithubWorkflowPlanVerifier {
    fn verify(
        &self,
        admission: &WorkflowAdmissionRequest,
    ) -> Result<(), WorkflowPlanVerificationError> {
        if admission.repository().provider() != "github" {
            return Err(WorkflowPlanVerificationError::PlanMismatch);
        }
        let source = std::str::from_utf8(admission.source())
            .map_err(|_| WorkflowPlanVerificationError::InvalidSourceEncoding)?;
        let provenance = source_provenance(admission)?;
        let parsed =
            GithubWorkflowFrontend::default().parse(ParseWorkflowRequest::new(provenance, source));
        if !parsed.is_accepted() {
            return Err(WorkflowPlanVerificationError::FrontendRejected(
                diagnostic_codes(parsed.diagnostics()),
            ));
        }
        let compiled =
            GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::for_preselected_event(
                parsed.plan().ok_or_else(|| {
                    WorkflowPlanVerificationError::FrontendRejected("no plan".into())
                })?,
                admission.plan().event().clone(),
            ));
        if !compiled.is_accepted() {
            return Err(WorkflowPlanVerificationError::CompilationRejected(
                diagnostic_codes(compiled.diagnostics()),
            ));
        }
        if compiled.plan() != Some(admission.plan()) {
            return Err(WorkflowPlanVerificationError::PlanMismatch);
        }
        Ok(())
    }
}

fn source_provenance(
    admission: &WorkflowAdmissionRequest,
) -> Result<SourceProvenance, WorkflowPlanVerificationError> {
    let PlanSourceOrigin::Repository {
        repository,
        revision,
        path,
    } = admission.plan().source().origin()
    else {
        return Err(WorkflowPlanVerificationError::PlanMismatch);
    };
    Ok(SourceProvenance::new(
        SourceId::new(admission.workflow_path()),
        SourceOrigin::Repository {
            repository: Arc::from(repository.as_str()),
            revision: Arc::from(revision.as_str()),
            path: Arc::from(path.as_str()),
        },
    ))
}

fn diagnostic_codes(diagnostics: &[Diagnostic]) -> String {
    let mut codes = diagnostics.iter().map(Diagnostic::code).collect::<Vec<_>>();
    codes.sort_unstable();
    codes.dedup();
    if codes.is_empty() {
        "unspecified diagnostic".to_owned()
    } else {
        codes.join(",")
    }
}
