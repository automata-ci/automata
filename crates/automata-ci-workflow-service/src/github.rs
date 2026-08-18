use std::sync::Arc;

use automata_ci_core::PlanSourceOrigin;
use automata_ci_workflow_actions::{
    CompileWorkflowRequest, Diagnostic, GithubWorkflowCompiler, GithubWorkflowFrontend,
    ParseWorkflowRequest, SourceId, SourceOrigin, SourceProvenance, WorkflowFrontend as _,
};

use crate::{
    WorkflowAdmissionRequest, WorkflowPlanVerificationError, WorkflowPlanVerifier,
    github_dispatch::{
        AUTOMATA_WORKFLOW_DISPATCH_EVIDENCE_V1_MEDIA_TYPE, GithubWorkflowDispatchEvidence,
    },
    github_schedule::{AUTOMATA_GITHUB_SCHEDULE_EVIDENCE_V1_MEDIA_TYPE, GithubScheduleEvidence},
};

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
        let parsed_plan = parsed
            .plan()
            .ok_or_else(|| WorkflowPlanVerificationError::FrontendRejected("no plan".into()))?;
        let compile_request = if admission.plan().event().name() == "workflow_dispatch" {
            if admission.event_media_type() != AUTOMATA_WORKFLOW_DISPATCH_EVIDENCE_V1_MEDIA_TYPE {
                return Err(WorkflowPlanVerificationError::WorkflowDispatchEvidenceMismatch);
            }
            let evidence = GithubWorkflowDispatchEvidence::decode(admission.event())
                .map_err(|_| WorkflowPlanVerificationError::WorkflowDispatchEvidenceMismatch)?;
            if !evidence.matches_admission(admission) {
                return Err(WorkflowPlanVerificationError::WorkflowDispatchEvidenceMismatch);
            }
            CompileWorkflowRequest::for_preselected_event_with_metadata(
                parsed_plan,
                admission.plan().event().clone(),
                evidence.metadata(),
            )
        } else if admission.plan().event().name() == "schedule" {
            if admission.event_media_type() != AUTOMATA_GITHUB_SCHEDULE_EVIDENCE_V1_MEDIA_TYPE {
                return Err(WorkflowPlanVerificationError::ScheduleEvidenceMismatch);
            }
            let evidence = GithubScheduleEvidence::decode(admission.event())
                .map_err(|_| WorkflowPlanVerificationError::ScheduleEvidenceMismatch)?;
            CompileWorkflowRequest::for_preselected_event_with_metadata(
                parsed_plan,
                admission.plan().event().clone(),
                automata_ci_workflow_actions::ProviderEventMetadata::schedule(evidence.cron()),
            )
        } else {
            if admission.event_media_type() == AUTOMATA_WORKFLOW_DISPATCH_EVIDENCE_V1_MEDIA_TYPE {
                return Err(WorkflowPlanVerificationError::WorkflowDispatchEvidenceMismatch);
            }
            if admission.event_media_type() == AUTOMATA_GITHUB_SCHEDULE_EVIDENCE_V1_MEDIA_TYPE {
                return Err(WorkflowPlanVerificationError::ScheduleEvidenceMismatch);
            }
            CompileWorkflowRequest::for_preselected_event(
                parsed_plan,
                admission.plan().event().clone(),
            )
        };
        let compiled = GithubWorkflowCompiler::new().compile(compile_request);
        if !compiled.is_accepted() {
            return Err(WorkflowPlanVerificationError::CompilationRejected(
                diagnostic_codes(compiled.diagnostics()),
            ));
        }
        if compiled.plan() != Some(admission.plan()) {
            return Err(WorkflowPlanVerificationError::PlanMismatch);
        }
        if admission.plan().event().name() == "workflow_dispatch"
            && compiled.workflow_dispatch_inputs() != Some(admission.base_context().inputs())
        {
            return Err(WorkflowPlanVerificationError::WorkflowDispatchEvidenceMismatch);
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
            revision: *revision,
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
