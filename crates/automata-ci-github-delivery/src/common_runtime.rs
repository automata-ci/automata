//! GitHub implementation of the common provider runtime boundary.

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_provider::{
    ClaimedProviderProcessing, ExternalSubjectKind, ProviderControlKind, ProviderDeliveryId,
    ProviderTypeId, VerifiedProviderControlDelivery, VerifiedProviderTriggerDelivery,
};
use automata_ci_provider_delivery::{
    ProviderControlHandlingError, ProviderProcessingLease, ProviderRuntimeAdapter,
    ProviderRuntimeContext, ProviderTriggerOutcome,
};
use automata_ci_provider_github::{
    GithubCheckControl, GithubCheckControlTarget, GithubCheckRunAction, GithubConnectionPolicy,
    GithubInstanceConfiguration,
};
use automata_ci_store::{
    GithubCheckAppId, GithubCheckRerunAction, GithubCheckRerunRepository, GithubCheckRerunRequest,
    GithubCheckRerunStoreError, GithubCheckRerunTarget, GithubCheckRunId, GithubCheckSuiteId,
    StoreError, TenantScope,
};
use automata_ci_workflow_service::{
    ProviderWorkflowResultService, ProviderWorkflowResultServiceError,
};

use crate::GithubTriggerHandler;

/// GitHub adapter for common trigger dispatch and native Check rerun controls.
pub struct GithubProviderRuntimeAdapter {
    provider_type: ProviderTypeId,
    triggers: Arc<dyn GithubTriggerHandler>,
    reruns: Arc<dyn GithubCheckRerunRepository>,
    results: ProviderWorkflowResultService,
}

impl GithubProviderRuntimeAdapter {
    /// Composes GitHub trigger processing and the durable native-rerun authority.
    ///
    /// # Panics
    ///
    /// Panics only if the built-in `github` provider identifier stops satisfying
    /// the common canonical identifier contract.
    #[must_use]
    pub fn new(
        triggers: Arc<dyn GithubTriggerHandler>,
        reruns: Arc<dyn GithubCheckRerunRepository>,
        results: ProviderWorkflowResultService,
    ) -> Self {
        Self {
            provider_type: ProviderTypeId::new("github")
                .expect("the built-in GitHub provider type is canonical"),
            triggers,
            reruns,
            results,
        }
    }
}

impl fmt::Debug for GithubProviderRuntimeAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubProviderRuntimeAdapter")
            .field("provider_type", &self.provider_type)
            .field("triggers", &self.triggers)
            .field("reruns", &self.reruns)
            .field("results", &self.results)
            .finish()
    }
}

#[async_trait]
impl ProviderRuntimeAdapter for GithubProviderRuntimeAdapter {
    fn provider_type(&self) -> &ProviderTypeId {
        &self.provider_type
    }

    async fn process_trigger(
        &self,
        context: &ProviderRuntimeContext,
        trigger: &VerifiedProviderTriggerDelivery,
        invocation: &ClaimedProviderProcessing,
        lease: &ProviderProcessingLease,
    ) -> ProviderTriggerOutcome {
        self.triggers
            .process_trigger(context, trigger, invocation, lease)
            .await
    }

    async fn handle_control(
        &self,
        context: &ProviderRuntimeContext,
        control: &VerifiedProviderControlDelivery,
        invocation: &ClaimedProviderProcessing,
        _lease: &ProviderProcessingLease,
    ) -> Result<Option<ProviderDeliveryId>, ProviderControlHandlingError> {
        let request =
            check_rerun_request(context.provider().manifest(), context.connection(), control)?;
        let receipts = self
            .reruns
            .rerun_github_check(request)
            .await
            .map_err(|error| rerun_error(&error))?;
        if receipts.is_empty() {
            return Err(ProviderControlHandlingError::Conflict);
        }
        for receipt in receipts {
            self.results
                .project_rerun(
                    context.connection(),
                    receipt,
                    invocation.receipt().created_at(),
                )
                .await
                .map_err(result_error)?;
        }
        Ok(None)
    }
}

fn check_rerun_request(
    provider: &automata_ci_provider::ProviderInstanceManifest,
    connection: &automata_ci_provider::ProviderConnectionManifest,
    delivery: &VerifiedProviderControlDelivery,
) -> Result<GithubCheckRerunRequest, ProviderControlHandlingError> {
    let evidence = delivery.evidence();
    let control = delivery.control();
    if provider.provider_type().as_str() != "github"
        || evidence.provider_type().as_str() != "github"
        || control.kind() != ProviderControlKind::Rerun
    {
        return Err(ProviderControlHandlingError::InvalidEvidence);
    }
    let native = GithubCheckControl::decode(control.document())
        .map_err(|_| ProviderControlHandlingError::InvalidEvidence)?;
    let instance = GithubInstanceConfiguration::decode(provider.configuration())
        .map_err(|_| ProviderControlHandlingError::InvalidEvidence)?;
    let policy = GithubConnectionPolicy::decode(connection.configuration().adapter_policy())
        .map_err(|_| ProviderControlHandlingError::InvalidEvidence)?;
    if policy.installation_id().get() != native.installation_id()
        || instance.app_id().get() != native.app_id()
    {
        return Err(ProviderControlHandlingError::InvalidEvidence);
    }
    let actor = control
        .actor()
        .filter(|actor| actor.kind() == ExternalSubjectKind::User)
        .ok_or(ProviderControlHandlingError::Unauthorized)?;
    let sender_id = parse_provider_id(actor.external_id().as_str())?;
    let repository_id = parse_provider_id(control.repository().external_id().as_str())?;
    let tenant = TenantScope::from_authenticated_tenant_id(
        connection.configuration().tenant_id().to_string(),
    )
    .map_err(|_| ProviderControlHandlingError::InvalidEvidence)?;
    let target = match native.target() {
        GithubCheckControlTarget::Run {
            run_id,
            suite_id,
            external_id,
            action,
        } => GithubCheckRerunTarget::Run {
            run_id: GithubCheckRunId::new(*run_id)
                .map_err(|_| ProviderControlHandlingError::InvalidEvidence)?,
            suite_id: GithubCheckSuiteId::new(*suite_id)
                .map_err(|_| ProviderControlHandlingError::InvalidEvidence)?,
            external_id: external_id.clone(),
            action: rerun_action(*action),
        },
        GithubCheckControlTarget::Suite { suite_id } => GithubCheckRerunTarget::Suite {
            suite_id: GithubCheckSuiteId::new(*suite_id)
                .map_err(|_| ProviderControlHandlingError::InvalidEvidence)?,
        },
    };
    GithubCheckRerunRequest::new(
        tenant,
        connection.connection_id(),
        native.installation_id(),
        repository_id,
        GithubCheckAppId::new(native.app_id())
            .map_err(|_| ProviderControlHandlingError::InvalidEvidence)?,
        control.object(),
        sender_id,
        evidence.external_delivery().external_id().as_str(),
        evidence.raw_body().digest(),
        target,
    )
    .map_err(|_| ProviderControlHandlingError::InvalidEvidence)
}

fn parse_provider_id(value: &str) -> Result<u64, ProviderControlHandlingError> {
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0 && i64::try_from(*value).is_ok())
        .ok_or(ProviderControlHandlingError::InvalidEvidence)
}

const fn rerun_action(action: GithubCheckRunAction) -> GithubCheckRerunAction {
    match action {
        GithubCheckRunAction::Rerequested => GithubCheckRerunAction::Rerequested,
        GithubCheckRunAction::RerunAll => GithubCheckRerunAction::RerunAll,
        GithubCheckRunAction::RerunFailed => GithubCheckRerunAction::RerunFailed,
        GithubCheckRunAction::RerunJob => GithubCheckRerunAction::RerunJob,
    }
}

fn rerun_error(error: &GithubCheckRerunStoreError) -> ProviderControlHandlingError {
    match error {
        GithubCheckRerunStoreError::Store(StoreError::Operation(_)) => {
            ProviderControlHandlingError::Unavailable
        }
        GithubCheckRerunStoreError::Store(_) => ProviderControlHandlingError::InvalidEvidence,
        GithubCheckRerunStoreError::AuthorityRejected => ProviderControlHandlingError::Unauthorized,
        GithubCheckRerunStoreError::Conflict => ProviderControlHandlingError::Conflict,
    }
}

const fn result_error(error: ProviderWorkflowResultServiceError) -> ProviderControlHandlingError {
    match error {
        ProviderWorkflowResultServiceError::Unavailable => {
            ProviderControlHandlingError::Unavailable
        }
        ProviderWorkflowResultServiceError::SubjectNotReady => {
            ProviderControlHandlingError::NotFound
        }
        ProviderWorkflowResultServiceError::InvalidConfiguration
        | ProviderWorkflowResultServiceError::InvalidEvidence => {
            ProviderControlHandlingError::InvalidEvidence
        }
        ProviderWorkflowResultServiceError::Inconsistent => ProviderControlHandlingError::Conflict,
    }
}

#[cfg(test)]
mod tests {
    use automata_ci_core::{GitObjectId, ManagedTenantId, Sha256Digest, UnixMillis};
    use automata_ci_provider::{
        ExternalDeliveryId, ExternalDeliveryIdentity, ExternalRepositoryId,
        ExternalRepositoryIdentity, ExternalSubjectId, ExternalSubjectIdentity,
        ProviderArchiveLimits, ProviderConfigurationRevision, ProviderConnectionConfiguration,
        ProviderConnectionId, ProviderConnectionManifest, ProviderConnectionRevision,
        ProviderControl, ProviderDefaultBranch, ProviderDeliveryEvidence, ProviderDeliveryId,
        ProviderDeliveryObservations, ProviderEventName, ProviderInstanceId,
        ProviderInstanceManifest, ProviderLifecycleState, ProviderOrigins, ProviderRepositoryPath,
        ProviderRunnerPolicyBinding, ProviderSchemaVersion, ProviderSecretBindings,
        ProviderSecretGeneration, ProviderSecretName, ProviderWebhookEndpointId,
        ProviderWebhookEndpointRevision, ProviderWebhookSecretReference,
        ProviderWebhookSignatureEvidence, ProviderWorkflowSource, RepositoryVisibility,
        VerifiedProviderControlDelivery, provider_capability_digest,
        provider_raw_webhook_descriptor,
    };
    use automata_ci_provider_github::{
        GithubInstanceConfiguration, GithubJwtIssuer, GithubProviderFactory,
    };
    use automata_ci_scm::RepositoryId;

    use super::*;

    #[derive(Clone, Copy)]
    enum Target {
        Run,
        Suite,
    }

    #[test]
    fn common_rerequest_controls_become_exact_durable_github_requests() {
        let (provider, connection, run) = fixture(Target::Run);
        let request = check_rerun_request(&provider, &connection, &run).expect("run request");
        assert_eq!(request.installation_id(), 71);
        assert_eq!(request.github_repository_id(), 42);
        assert_eq!(request.app_id().get(), 501);
        assert_eq!(request.sender_id(), 83);
        assert_eq!(request.delivery_id(), "delivery-rerequested");
        assert_eq!(
            request.tenant().as_str(),
            "11111111-1111-4111-8111-111111111111"
        );
        assert_eq!(
            request.target(),
            &GithubCheckRerunTarget::Run {
                run_id: GithubCheckRunId::new(601).expect("run ID"),
                suite_id: GithubCheckSuiteId::new(701).expect("suite ID"),
                external_id: "automata-result-subject".to_owned(),
                action: GithubCheckRerunAction::Rerequested,
            }
        );

        let (provider, connection, suite) = fixture(Target::Suite);
        let request = check_rerun_request(&provider, &connection, &suite).expect("suite request");
        assert_eq!(
            request.target(),
            &GithubCheckRerunTarget::Suite {
                suite_id: GithubCheckSuiteId::new(701).expect("suite ID"),
            }
        );
    }

    fn fixture(
        target: Target,
    ) -> (
        ProviderInstanceManifest,
        ProviderConnectionManifest,
        VerifiedProviderControlDelivery,
    ) {
        let instance_id = ProviderInstanceId::new();
        let revision = ProviderConfigurationRevision::new(1).expect("provider revision");
        let connection_id = ProviderConnectionId::new();
        let connection_revision = ProviderConnectionRevision::new(1).expect("connection revision");
        let (provider, connection, repository) =
            provider_connection(instance_id, revision, connection_id, connection_revision);
        let native = match target {
            Target::Run => GithubCheckControl::check_run(
                71,
                501,
                601,
                701,
                "automata-result-subject",
                GithubCheckRunAction::Rerequested,
            ),
            Target::Suite => GithubCheckControl::check_suite(71, 501, 701),
        }
        .expect("native control");
        let control = ProviderControl::new(
            ProviderControlKind::Rerun,
            repository,
            GitObjectId::from_provider_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .expect("head revision"),
            Some(ExternalSubjectIdentity::new(
                instance_id,
                ExternalSubjectKind::User,
                ExternalSubjectId::new("83").expect("sender ID"),
            )),
            native.document().expect("control document"),
        )
        .expect("control");
        let raw = provider_raw_webhook_descriptor(Sha256Digest::from_bytes([7; 32]), 1)
            .expect("raw descriptor");
        let evidence = ProviderDeliveryEvidence::rehydrate(
            ProviderDeliveryId::new(),
            ProviderWebhookEndpointId::new(),
            ProviderWebhookEndpointRevision::new(1).expect("endpoint revision"),
            ProviderTypeId::new("github").expect("provider type"),
            instance_id,
            revision,
            connection_id,
            connection_revision,
            ExternalDeliveryIdentity::new(
                instance_id,
                ExternalDeliveryId::new("delivery-rerequested").expect("delivery ID"),
            ),
            ProviderEventName::new(match target {
                Target::Run => "check_run",
                Target::Suite => "check_suite",
            })
            .expect("event name"),
            UnixMillis::new(900),
            raw,
            UnixMillis::new(10_000),
            ProviderWebhookSignatureEvidence::new(
                "github-hmac-sha256",
                ProviderWebhookSecretReference::new(
                    revision,
                    ProviderSecretName::new("webhook-secret").expect("secret name"),
                    ProviderSecretGeneration::new(1).expect("secret generation"),
                ),
            )
            .expect("signature"),
            ProviderDeliveryObservations::new(Vec::new()).expect("observations"),
        )
        .expect("delivery evidence");
        let delivery =
            VerifiedProviderControlDelivery::rehydrate(evidence, control).expect("delivery");
        (provider, connection, delivery)
    }

    fn provider_connection(
        instance_id: ProviderInstanceId,
        revision: ProviderConfigurationRevision,
        connection_id: ProviderConnectionId,
        connection_revision: ProviderConnectionRevision,
    ) -> (
        ProviderInstanceManifest,
        ProviderConnectionManifest,
        ExternalRepositoryIdentity,
    ) {
        let capabilities = GithubProviderFactory::capabilities().expect("capabilities");
        let provider = ProviderInstanceManifest::new(
            instance_id,
            ProviderTypeId::new("github").expect("provider type"),
            revision,
            ProviderLifecycleState::Active,
            ProviderOrigins::new("https://github.com/", "https://api.github.com/")
                .expect("origins"),
            GithubInstanceConfiguration::new(
                501,
                "Iv1.automata",
                GithubJwtIssuer::AppClientId,
                "https://codeload.github.com/"
                    .parse()
                    .expect("archive origin"),
            )
            .expect("GitHub configuration")
            .document()
            .expect("provider configuration"),
            ProviderSecretBindings::empty(),
            provider_capability_digest(&capabilities).expect("capability digest"),
            UnixMillis::new(100),
            Some(UnixMillis::new(100)),
            None,
        )
        .expect("provider manifest");
        let repository = ExternalRepositoryIdentity::new(
            instance_id,
            ExternalRepositoryId::new("42").expect("repository ID"),
        );
        let policy = GithubConnectionPolicy::new(
            71,
            RepositoryId::new("owner/repository").expect("repository route"),
        )
        .expect("GitHub policy")
        .document()
        .expect("GitHub policy document");
        let configuration = ProviderConnectionConfiguration::new(
            ManagedTenantId::parse("11111111-1111-4111-8111-111111111111").expect("tenant"),
            repository.clone(),
            revision,
            provider.configuration().digest(),
            provider.capability_digest(),
            RepositoryVisibility::Private,
            ProviderDefaultBranch::new("main").expect("default branch"),
            ProviderWorkflowSource::Directory(
                ProviderRepositoryPath::new(".ci/workflows").expect("workflow root"),
            ),
            ProviderRunnerPolicyBinding::new(
                ProviderSchemaVersion::new(1).expect("runner schema"),
                Sha256Digest::from_bytes([5; 32]),
            ),
            ProviderArchiveLimits::new(1_024, 8_192, 100, 1_024, 10, 1_024)
                .expect("archive limits"),
            policy,
        );
        let connection = ProviderConnectionManifest::new(
            connection_id,
            connection_revision,
            ProviderLifecycleState::Active,
            configuration,
            UnixMillis::new(100),
            Some(UnixMillis::new(100)),
            None,
        )
        .expect("connection manifest");
        (provider, connection, repository)
    }
}
