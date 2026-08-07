use std::sync::Arc;

use automata_core::{
    Architecture, ContainerFeature, DeferredBoolean, EnvironmentProfile, EnvironmentProfileId,
    ExpressionSegment, OperatingSystem, PlanSourceOrigin, QueuePolicy, Sha256Digest,
};
use automata_store::WorkflowConcurrency;
use automata_workflow_github::{
    CompileWorkflowRequest, Diagnostic, EvaluateJobRequest, GithubJobContext, GithubJobEvaluator,
    GithubRunnerProfileCatalog, GithubRunnerProfileMapping, GithubTargetPathStyle,
    GithubWorkflowCompiler, GithubWorkflowFrontend, GithubWorkspacePath, ParseWorkflowRequest,
    SourceId, SourceOrigin, SourceProvenance, WorkflowFrontend as _,
};

use crate::{
    MaterializeWorkflowRequest, MaterializedWorkflow, MaterializedWorkflowJob,
    WorkflowMaterializationError, WorkflowMaterializer,
};

/// GitHub adapter that re-parses, recompiles, and evaluates exact source.
#[derive(Clone, Debug)]
pub struct GithubWorkflowMaterializer {
    profiles: GithubRunnerProfileCatalog,
}

impl GithubWorkflowMaterializer {
    /// Creates an adapter with a server-attested, deployer-supplied profile catalog.
    #[must_use]
    pub const fn new(profiles: GithubRunnerProfileCatalog) -> Self {
        Self { profiles }
    }

    #[must_use]
    pub const fn profiles(&self) -> &GithubRunnerProfileCatalog {
        &self.profiles
    }

    fn materialize_jobs(
        &self,
        request: &MaterializeWorkflowRequest<'_>,
        workspace: &GithubWorkspacePath,
    ) -> Result<Vec<MaterializedWorkflowJob>, WorkflowMaterializationError> {
        let admission = request.admission();
        let mut jobs = Vec::with_capacity(request.jobs().len());
        for planned in admission.plan().jobs() {
            let identity = request
                .jobs()
                .iter()
                .find(|identity| identity.key() == planned.key().value())
                .ok_or(WorkflowMaterializationError::IdentityMismatch)?;
            let context = GithubJobContext::builder(
                request.workflow_id(),
                request.run_id(),
                identity.job_id(),
            )
            .repository(admission.repository().slug())
            .commit_sha(admission.commit_sha())
            .git_ref(admission.git_ref())
            .workflow_name(admission.workflow_name())
            .workspace(workspace.clone())
            .event(request.event().clone());
            let context = if let Some(actor) = admission.actor() {
                context.actor(actor)
            } else {
                context
            };
            let context = if let Some(run_number) = admission.run_number() {
                context.run_number(run_number)
            } else {
                context
            };
            let context = if let Some(run_attempt) = admission.run_attempt() {
                context.run_attempt(run_attempt)
            } else {
                context
            }
            .build()
            .map_err(|error| WorkflowMaterializationError::EvaluationRejected(error.to_string()))?;
            let evaluation = GithubJobEvaluator::new().evaluate(&EvaluateJobRequest::new(
                admission.plan(),
                &context,
                &self.profiles,
                identity.key().clone(),
            ));
            if !evaluation.is_accepted() {
                return Err(WorkflowMaterializationError::EvaluationRejected(
                    diagnostic_codes(evaluation.diagnostics()),
                ));
            }
            let envelope = evaluation.into_parts().0.ok_or_else(|| {
                WorkflowMaterializationError::EvaluationRejected("no JobIR".into())
            })?;
            jobs.push(MaterializedWorkflowJob::new(
                identity.key().clone(),
                envelope,
            ));
        }
        Ok(jobs)
    }
}

impl WorkflowMaterializer for GithubWorkflowMaterializer {
    fn materialize(
        &self,
        request: &MaterializeWorkflowRequest<'_>,
    ) -> Result<MaterializedWorkflow, WorkflowMaterializationError> {
        let admission = request.admission();
        if admission.repository().provider() != "github" {
            return Err(WorkflowMaterializationError::PlanMismatch);
        }
        validate_compiled_plan(admission)?;
        validate_job_identities(request)?;

        let path_style = if admission.workspace().starts_with('/') {
            GithubTargetPathStyle::Unix
        } else {
            GithubTargetPathStyle::Windows
        };
        let workspace = GithubWorkspacePath::new(path_style, admission.workspace())
            .map_err(|error| WorkflowMaterializationError::EvaluationRejected(error.to_string()))?;
        let jobs = self.materialize_jobs(request, &workspace)?;
        let concurrency = resolve_concurrency(request)?;
        Ok(MaterializedWorkflow::new(jobs, concurrency))
    }
}

fn validate_compiled_plan(
    admission: &crate::WorkflowAdmissionRequest,
) -> Result<(), WorkflowMaterializationError> {
    let source = std::str::from_utf8(admission.source())
        .map_err(|_| WorkflowMaterializationError::InvalidSourceEncoding)?;
    let provenance = source_provenance(admission)?;
    let parsed =
        GithubWorkflowFrontend::default().parse(ParseWorkflowRequest::new(provenance, source));
    if !parsed.is_accepted() {
        return Err(WorkflowMaterializationError::FrontendRejected(
            diagnostic_codes(parsed.diagnostics()),
        ));
    }
    let compiled = GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::new(
        parsed
            .plan()
            .ok_or_else(|| WorkflowMaterializationError::FrontendRejected("no plan".into()))?,
        admission.plan().event().clone(),
    ));
    if !compiled.is_accepted() {
        return Err(WorkflowMaterializationError::CompilationRejected(
            diagnostic_codes(compiled.diagnostics()),
        ));
    }
    if compiled.plan() != Some(admission.plan()) {
        return Err(WorkflowMaterializationError::PlanMismatch);
    }
    Ok(())
}

fn validate_job_identities(
    request: &MaterializeWorkflowRequest<'_>,
) -> Result<(), WorkflowMaterializationError> {
    if request.jobs().len() != request.admission().plan().jobs().len()
        || request.admission().plan().jobs().iter().any(|job| {
            job.concurrency().is_some()
                || !request
                    .jobs()
                    .iter()
                    .any(|identity| identity.key() == job.key().value())
        })
    {
        return Err(WorkflowMaterializationError::IdentityMismatch);
    }
    Ok(())
}

/// Builds the exact checked local Ubuntu 24.04 dogfood profile mapping.
///
/// Production composition may supply any independently attested catalog to
/// [`GithubWorkflowMaterializer::new`].
///
/// # Errors
///
/// Returns an error only if the checked profile constants cease to be valid.
pub fn github_hosted_ubuntu_24_04_catalog()
-> Result<GithubRunnerProfileCatalog, automata_workflow_github::JobEvaluationInputError> {
    let digest = Sha256Digest::from_bytes([
        0xb0, 0xc2, 0xf5, 0xc0, 0xca, 0xd3, 0x41, 0xe3, 0x4c, 0x42, 0x2a, 0x1b, 0x69, 0xbc, 0xc7,
        0x0b, 0xb8, 0x22, 0x24, 0xf2, 0x4d, 0x85, 0x12, 0x02, 0x6c, 0xab, 0x93, 0x46, 0xdd, 0x1c,
        0x60, 0x87,
    ]);
    let profile = EnvironmentProfile::new(
        EnvironmentProfileId::new("automata.dev/github-hosted-ubuntu-24-04-x64-v1").map_err(
            |_| automata_workflow_github::JobEvaluationInputError::InvalidProfileSelector,
        )?,
        digest,
    );
    GithubRunnerProfileCatalog::new([GithubRunnerProfileMapping::new(
        "ubuntu-24.04",
        profile,
        OperatingSystem::Linux,
        Architecture::X86_64,
    )?
    .with_container_features([ContainerFeature::DOCKER_COMPATIBLE_API])])
}

fn source_provenance(
    admission: &crate::WorkflowAdmissionRequest,
) -> Result<SourceProvenance, WorkflowMaterializationError> {
    let PlanSourceOrigin::Repository {
        repository,
        revision,
        path,
    } = admission.plan().source().origin()
    else {
        return Err(WorkflowMaterializationError::PlanMismatch);
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

fn resolve_concurrency(
    request: &MaterializeWorkflowRequest<'_>,
) -> Result<Option<WorkflowConcurrency>, WorkflowMaterializationError> {
    let Some(concurrency) = request.admission().plan().concurrency() else {
        return Ok(None);
    };
    if concurrency.queue() != QueuePolicy::Single {
        return Err(WorkflowMaterializationError::UnsupportedConcurrency(
            "only GitHub's single pending slot is durable".into(),
        ));
    }
    let mut group = String::new();
    for segment in concurrency.group().value().segments() {
        match segment {
            ExpressionSegment::Literal(value) => group.push_str(value),
            ExpressionSegment::Evaluation(source) => {
                group.push_str(&resolve_early_github_value(source, request)?);
            }
        }
    }
    let cancel_in_progress = match concurrency
        .cancel_in_progress()
        .map(automata_core::Located::value)
    {
        None | Some(DeferredBoolean::Literal(false)) => false,
        Some(DeferredBoolean::Literal(true)) => true,
        Some(DeferredBoolean::Expression(_)) => {
            return Err(WorkflowMaterializationError::UnsupportedConcurrency(
                "expression-valued cancel-in-progress is not early-bound".into(),
            ));
        }
    };
    WorkflowConcurrency::new(group, cancel_in_progress)
        .map(Some)
        .map_err(|error| WorkflowMaterializationError::UnsupportedConcurrency(error.to_string()))
}

fn resolve_early_github_value(
    source: &str,
    request: &MaterializeWorkflowRequest<'_>,
) -> Result<String, WorkflowMaterializationError> {
    let expression = source
        .strip_prefix("${{")
        .and_then(|value| value.strip_suffix("}}"))
        .map(str::trim)
        .ok_or_else(|| {
            WorkflowMaterializationError::UnsupportedConcurrency(
                "invalid expression delimiter".into(),
            )
        })?;
    let admission = request.admission();
    match expression.to_ascii_lowercase().as_str() {
        "github.workflow" => Ok(admission.workflow_name().to_owned()),
        "github.ref" => Ok(admission.git_ref().to_owned()),
        "github.sha" => Ok(admission.commit_sha().to_owned()),
        "github.workspace" => Ok(admission.workspace().to_owned()),
        "github.repository" => Ok(admission.repository().slug()),
        _ => Err(WorkflowMaterializationError::UnsupportedConcurrency(
            format!("unsupported early expression `{expression}`"),
        )),
    }
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
