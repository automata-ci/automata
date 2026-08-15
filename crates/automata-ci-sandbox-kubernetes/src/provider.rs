use std::{future::Future, num::NonZeroU16, str::FromStr as _, sync::Arc, time::Instant};

use automata_ci_core::{EnvironmentProfile, EnvironmentProfileId, RunnerId, Sha256Digest};
use automata_ci_execution::{
    Cancellation, DestroyDisposition, DestroySandbox, OperationOutcome, ProviderCapabilities,
    ProviderError, ProviderErrorKind, ProviderId, ProviderStage, SandboxCapability, SandboxCustody,
    SandboxHandle, SandboxInspection, SandboxProvider, SandboxRecord, SandboxSpec, SandboxState,
};
use k8s_openapi::api::{core::v1::Pod, networking::v1::NetworkPolicy};
use kube::{
    Api, Client, Resource, ResourceExt,
    api::{DeleteParams, PostParams, Preconditions},
};
use tokio::time::{Duration, sleep, timeout};

use crate::{
    KUBERNETES_PROVIDER_ID, KubernetesConfigurationError, KubernetesSandboxConfig,
    endpoint::KubernetesExecutionEndpoint,
    invalid_configuration,
    objects::{
        CUSTODY_KIND_LABEL, CUSTODY_RUNNER_LABEL, CUSTODY_SLOT_LABEL, FINGERPRINT_ANNOTATION,
        GENERATION_ANNOTATION, MANAGED_LABEL, PROFILE_DIGEST_ANNOTATION, PROFILE_ID_ANNOTATION,
        SANDBOX_LABEL, SANDBOX_SCHEMA, SCHEMA_LABEL, build_objects, network_policy_name,
    },
};

/// Kubernetes adapter for one deny-by-default Pod per whole-job sandbox.
#[derive(Clone)]
pub struct KubernetesSandboxProvider {
    inner: Arc<KubernetesInner>,
}

struct KubernetesInner {
    client: Client,
    config: KubernetesSandboxConfig,
    provider_id: ProviderId,
    capabilities: ProviderCapabilities,
}

impl KubernetesSandboxProvider {
    /// Creates an adapter over an authenticated Kubernetes client.
    ///
    /// # Errors
    ///
    /// Returns a configuration error if fixed provider values cannot be built.
    pub fn new(
        client: Client,
        config: KubernetesSandboxConfig,
    ) -> Result<Self, KubernetesConfigurationError> {
        let provider_id = ProviderId::new(KUBERNETES_PROVIDER_ID)
            .map_err(|_| KubernetesConfigurationError::InvalidProviderIdentity)?;
        let mut declared_capabilities = vec![
            SandboxCapability::WholeJob,
            SandboxCapability::Attach,
            SandboxCapability::Inspect,
            SandboxCapability::Exec,
            SandboxCapability::CopyTo,
            SandboxCapability::CopyFrom,
            SandboxCapability::EnvironmentInjection,
            SandboxCapability::NetworkDisabled,
            SandboxCapability::ReadOnlyRootFilesystem,
            SandboxCapability::WritableRootFilesystem,
            SandboxCapability::ResourceLimits,
        ];
        if config.ephemeral_storage_enforced() {
            declared_capabilities.push(SandboxCapability::EphemeralStorageLimits);
        }
        if config.gpu_resource_name().is_some() {
            declared_capabilities.push(SandboxCapability::DeviceLimits);
        }
        if config.process_limit().is_some() {
            declared_capabilities.push(SandboxCapability::ProcessLimits);
        }
        let capabilities = ProviderCapabilities::new(declared_capabilities)
            .map_err(|_| KubernetesConfigurationError::InvalidProviderIdentity)?;
        Ok(Self {
            inner: Arc::new(KubernetesInner {
                client,
                config,
                provider_id,
                capabilities,
            }),
        })
    }
}

impl std::fmt::Debug for KubernetesSandboxProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KubernetesSandboxProvider")
            .field("provider_id", &self.inner.provider_id)
            .field("namespace", &self.inner.config.namespace())
            .field("capabilities", &self.inner.capabilities)
            .finish_non_exhaustive()
    }
}

impl SandboxProvider for KubernetesSandboxProvider {
    fn provider_id(&self) -> &ProviderId {
        &self.inner.provider_id
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        &self.inner.capabilities
    }

    fn create(
        &self,
        spec: &SandboxSpec,
        cancellation: &dyn Cancellation,
    ) -> Result<SandboxRecord, ProviderError> {
        ensure_not_cancelled(cancellation, ProviderStage::Validate)?;
        let name = sandbox_name(spec);
        let handle = SandboxHandle::new(self.inner.provider_id.clone(), name.clone())
            .map_err(|_| invalid_configuration(ProviderStage::Validate))?;
        let objects = build_objects(&name, spec, &self.inner.config)?;
        let pods: Api<Pod> =
            Api::namespaced(self.inner.client.clone(), self.inner.config.namespace());
        let policies: Api<NetworkPolicy> =
            Api::namespaced(self.inner.client.clone(), self.inner.config.namespace());
        let operation_timeout = self.inner.config.operation_timeout();
        let readiness_timeout = self.inner.config.readiness_timeout();
        let fingerprint = objects.fingerprint.clone();
        let created = block_on(async move {
            create_or_verify_policy(
                &policies,
                objects.network_policy,
                &fingerprint,
                operation_timeout,
            )
            .await?;
            if cancellation.is_cancelled() {
                return Err(ProviderErrorKind::Cancelled);
            }
            create_or_verify_pod(&pods, objects.pod, &fingerprint, operation_timeout).await?;
            wait_until_ready(
                &pods,
                &name,
                readiness_timeout,
                operation_timeout,
                cancellation,
            )
            .await
        })
        .map_err(|kind| {
            ProviderError::new(
                kind,
                ProviderStage::CreateSandbox,
                OperationOutcome::Uncertain,
                Some(handle.clone()),
            )
        })?;
        if cancellation.is_cancelled() {
            return Err(ProviderError::new(
                ProviderErrorKind::Cancelled,
                ProviderStage::Start,
                OperationOutcome::Uncertain,
                Some(handle),
            ));
        }
        Ok(SandboxRecord::new(
            handle,
            spec.generation(),
            spec.profile().attestation().clone(),
            created,
        ))
    }

    fn attach(
        &self,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<Box<dyn automata_ci_execution::ExecutionEndpoint>, ProviderError> {
        ensure_handle(&self.inner.provider_id, handle, ProviderStage::Attach)?;
        ensure_not_cancelled(cancellation, ProviderStage::Attach)?;
        let pods: Api<Pod> =
            Api::namespaced(self.inner.client.clone(), self.inner.config.namespace());
        let name = handle.opaque().to_owned();
        let timeout_duration = self.inner.config.operation_timeout();
        let pod = block_on(async move {
            timeout(timeout_duration, pods.get(&name))
                .await
                .map_err(|_| ProviderErrorKind::TimedOut)?
                .map_err(|error| map_kube_error(&error))
        })
        .map_err(|kind| provider_error(kind, ProviderStage::Attach))?;
        verify_managed(&pod, handle.opaque(), None)
            .map_err(|kind| provider_error(kind, ProviderStage::Attach))?;
        if pod_state(&pod) != SandboxState::Running {
            return Err(provider_error(
                ProviderErrorKind::InvalidState,
                ProviderStage::Attach,
            ));
        }
        let uid = pod.uid().ok_or_else(|| {
            provider_error(ProviderErrorKind::BackendRejected, ProviderStage::Attach)
        })?;
        Ok(Box::new(KubernetesExecutionEndpoint::new(
            self.inner.client.clone(),
            self.inner.config.namespace().into(),
            handle.clone(),
            uid,
            self.inner.config.operation_timeout(),
        )))
    }

    fn inspect(
        &self,
        handle: &SandboxHandle,
        cancellation: &dyn Cancellation,
    ) -> Result<SandboxInspection, ProviderError> {
        ensure_handle(&self.inner.provider_id, handle, ProviderStage::Inspect)?;
        ensure_not_cancelled(cancellation, ProviderStage::Inspect)?;
        let pods: Api<Pod> =
            Api::namespaced(self.inner.client.clone(), self.inner.config.namespace());
        let name = handle.opaque().to_owned();
        let timeout_duration = self.inner.config.operation_timeout();
        let pod = block_on(async move {
            timeout(timeout_duration, pods.get(&name))
                .await
                .map_err(|_| ProviderErrorKind::TimedOut)?
                .map_err(|error| map_kube_error(&error))
        })
        .map_err(|kind| provider_error(kind, ProviderStage::Inspect))?;
        verify_managed(&pod, handle.opaque(), None)
            .map_err(|kind| provider_error(kind, ProviderStage::Inspect))?;
        let (generation, custody, profile) =
            identity_from_pod(&pod).map_err(|kind| provider_error(kind, ProviderStage::Inspect))?;
        Ok(SandboxInspection::new(
            handle.clone(),
            generation,
            custody,
            profile,
            pod_state(&pod),
        ))
    }

    fn destroy(
        &self,
        request: &DestroySandbox,
        cancellation: &dyn Cancellation,
    ) -> Result<DestroyDisposition, ProviderError> {
        ensure_handle(
            &self.inner.provider_id,
            request.handle(),
            ProviderStage::DestroySandbox,
        )?;
        ensure_not_cancelled(cancellation, ProviderStage::DestroySandbox)?;
        let pods: Api<Pod> =
            Api::namespaced(self.inner.client.clone(), self.inner.config.namespace());
        let policies: Api<NetworkPolicy> =
            Api::namespaced(self.inner.client.clone(), self.inner.config.namespace());
        let name = request.handle().opaque().to_owned();
        let policy_name = network_policy_name(&name);
        let generation = request.generation().get();
        let timeout_duration = self.inner.config.operation_timeout();
        let result = block_on(async move {
            let pod_custody =
                delete_pod_and_wait(&pods, &name, generation, timeout_duration).await?;
            // Network isolation must outlive the exact Pod UID. Kubernetes Pod
            // deletion is asynchronous even after DELETE succeeds.
            let policy_existed = delete_policy_and_wait(
                &policies,
                &policy_name,
                &name,
                generation,
                pod_custody,
                timeout_duration,
            )
            .await?;
            let existed = pod_custody.is_some() || policy_existed;
            Ok::<_, ProviderErrorKind>(existed)
        })
        .map_err(|kind| {
            ProviderError::new(
                kind,
                ProviderStage::DestroySandbox,
                OperationOutcome::Uncertain,
                Some(request.handle().clone()),
            )
        })?;
        Ok(if result {
            DestroyDisposition::Destroyed
        } else {
            DestroyDisposition::AlreadyAbsent
        })
    }
}

async fn delete_pod_and_wait(
    pods: &Api<Pod>,
    name: &str,
    generation: u64,
    deadline: Duration,
) -> Result<Option<SandboxCustody>, ProviderErrorKind> {
    let started = Instant::now();
    let Some(pod) = timed_get_opt(pods, name, remaining(deadline, started)?).await? else {
        return Ok(None);
    };
    verify_managed(&pod, name, Some(generation))?;
    let custody = custody_from_object(&pod)?;
    let uid = pod.uid().ok_or(ProviderErrorKind::BackendRejected)?;
    let resource_version = pod
        .resource_version()
        .ok_or(ProviderErrorKind::BackendRejected)?;
    let deletion = timeout(
        remaining(deadline, started)?,
        pods.delete(
            name,
            &DeleteParams::default().preconditions(Preconditions {
                resource_version: Some(resource_version),
                uid: Some(uid.clone()),
            }),
        ),
    )
    .await
    .map_err(|_| ProviderErrorKind::TimedOut)?;
    if let Err(error) = deletion
        && api_error_code(&error) != Some(404)
    {
        return Err(map_kube_error(&error));
    }
    loop {
        let Some(observed) = timed_get_opt(pods, name, remaining(deadline, started)?).await? else {
            return Ok(Some(custody));
        };
        if observed.uid().as_deref() != Some(uid.as_str()) {
            return Err(ProviderErrorKind::OwnershipMismatch);
        }
        sleep(Duration::from_millis(100).min(remaining(deadline, started)?)).await;
    }
}

async fn delete_policy_and_wait(
    policies: &Api<NetworkPolicy>,
    policy_name: &str,
    sandbox_name: &str,
    generation: u64,
    expected_custody: Option<SandboxCustody>,
    deadline: Duration,
) -> Result<bool, ProviderErrorKind> {
    let started = Instant::now();
    let Some(policy) = timed_get_opt(policies, policy_name, remaining(deadline, started)?).await?
    else {
        return Ok(false);
    };
    verify_managed(&policy, sandbox_name, Some(generation))?;
    let custody = custody_from_object(&policy)?;
    if expected_custody.is_some_and(|expected| custody != expected) {
        return Err(ProviderErrorKind::OwnershipMismatch);
    }
    let uid = policy.uid().ok_or(ProviderErrorKind::BackendRejected)?;
    let resource_version = policy
        .resource_version()
        .ok_or(ProviderErrorKind::BackendRejected)?;
    let deletion = timeout(
        remaining(deadline, started)?,
        policies.delete(
            policy_name,
            &DeleteParams::default().preconditions(Preconditions {
                resource_version: Some(resource_version),
                uid: Some(uid.clone()),
            }),
        ),
    )
    .await
    .map_err(|_| ProviderErrorKind::TimedOut)?;
    if let Err(error) = deletion
        && api_error_code(&error) != Some(404)
    {
        return Err(map_kube_error(&error));
    }
    loop {
        let Some(observed) =
            timed_get_opt(policies, policy_name, remaining(deadline, started)?).await?
        else {
            return Ok(true);
        };
        if observed.uid().as_deref() != Some(uid.as_str()) {
            return Err(ProviderErrorKind::OwnershipMismatch);
        }
        sleep(Duration::from_millis(100).min(remaining(deadline, started)?)).await;
    }
}

async fn timed_get_opt<K>(
    api: &Api<K>,
    name: &str,
    deadline: Duration,
) -> Result<Option<K>, ProviderErrorKind>
where
    K: Clone + serde::de::DeserializeOwned + std::fmt::Debug,
{
    timeout(deadline, api.get_opt(name))
        .await
        .map_err(|_| ProviderErrorKind::TimedOut)?
        .map_err(|error| map_kube_error(&error))
}

fn remaining(deadline: Duration, started: Instant) -> Result<Duration, ProviderErrorKind> {
    let remaining = deadline.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        Err(ProviderErrorKind::TimedOut)
    } else {
        Ok(remaining)
    }
}

async fn create_or_verify_pod(
    api: &Api<Pod>,
    pod: Pod,
    fingerprint: &str,
    deadline: Duration,
) -> Result<(), ProviderErrorKind> {
    let name = pod.name_any();
    if let Some(existing) = timeout(deadline, api.get_opt(&name))
        .await
        .map_err(|_| ProviderErrorKind::TimedOut)?
        .map_err(|error| map_kube_error(&error))?
    {
        return verify_observed_pod(&existing, &pod, fingerprint);
    }
    match timeout(deadline, api.create(&PostParams::default(), &pod)).await {
        Ok(Ok(created)) => verify_observed_pod(&created, &pod, fingerprint),
        Ok(Err(error)) if api_error_code(&error) == Some(409) => {
            let existing = timeout(deadline, api.get(&name))
                .await
                .map_err(|_| ProviderErrorKind::TimedOut)?
                .map_err(|error| map_kube_error(&error))?;
            verify_observed_pod(&existing, &pod, fingerprint)
        }
        Ok(Err(error)) => Err(map_kube_error(&error)),
        Err(_) => Err(ProviderErrorKind::TimedOut),
    }
}

async fn create_or_verify_policy(
    api: &Api<NetworkPolicy>,
    policy: NetworkPolicy,
    fingerprint: &str,
    deadline: Duration,
) -> Result<(), ProviderErrorKind> {
    let name = policy.name_any();
    let sandbox = policy
        .labels()
        .get(SANDBOX_LABEL)
        .cloned()
        .ok_or(ProviderErrorKind::BackendRejected)?;
    if let Some(existing) = timeout(deadline, api.get_opt(&name))
        .await
        .map_err(|_| ProviderErrorKind::TimedOut)?
        .map_err(|error| map_kube_error(&error))?
    {
        return verify_observed_policy(&existing, &policy, &sandbox, fingerprint);
    }
    match timeout(deadline, api.create(&PostParams::default(), &policy)).await {
        Ok(Ok(created)) => verify_observed_policy(&created, &policy, &sandbox, fingerprint),
        Ok(Err(error)) if api_error_code(&error) == Some(409) => {
            let existing = timeout(deadline, api.get(&name))
                .await
                .map_err(|_| ProviderErrorKind::TimedOut)?
                .map_err(|error| map_kube_error(&error))?;
            verify_observed_policy(&existing, &policy, &sandbox, fingerprint)
        }
        Ok(Err(error)) => Err(map_kube_error(&error)),
        Err(_) => Err(ProviderErrorKind::TimedOut),
    }
}

fn verify_observed_pod(
    observed: &Pod,
    expected: &Pod,
    fingerprint: &str,
) -> Result<(), ProviderErrorKind> {
    let name = expected.name_any();
    verify_managed(observed, &name, None)?;
    verify_same_custody(observed, expected)?;
    verify_fingerprint(observed, fingerprint)?;
    let observed = observed.spec.as_ref().ok_or(ProviderErrorKind::Conflict)?;
    let expected = expected
        .spec
        .as_ref()
        .ok_or(ProviderErrorKind::BackendRejected)?;
    let exact = observed.containers == expected.containers
        && observed.init_containers == expected.init_containers
        && observed.volumes == expected.volumes
        && observed.automount_service_account_token == expected.automount_service_account_token
        && observed.dns_policy == expected.dns_policy
        && observed.enable_service_links == expected.enable_service_links
        && observed.host_ipc == expected.host_ipc
        && observed.host_network == expected.host_network
        && observed.host_pid == expected.host_pid
        && observed.restart_policy == expected.restart_policy
        && observed.security_context == expected.security_context
        && observed.share_process_namespace == expected.share_process_namespace
        && observed.termination_grace_period_seconds == expected.termination_grace_period_seconds
        && observed.node_selector == expected.node_selector
        && observed.affinity == expected.affinity
        && observed.tolerations == expected.tolerations
        && observed.runtime_class_name == expected.runtime_class_name
        && observed.ephemeral_containers == expected.ephemeral_containers;
    exact.then_some(()).ok_or(ProviderErrorKind::Conflict)
}

fn verify_observed_policy(
    observed: &NetworkPolicy,
    expected: &NetworkPolicy,
    sandbox: &str,
    fingerprint: &str,
) -> Result<(), ProviderErrorKind> {
    verify_managed(observed, sandbox, None)?;
    verify_same_custody(observed, expected)?;
    verify_fingerprint(observed, fingerprint)?;
    (observed.spec == expected.spec)
        .then_some(())
        .ok_or(ProviderErrorKind::Conflict)
}

fn verify_fingerprint<K>(object: &K, fingerprint: &str) -> Result<(), ProviderErrorKind>
where
    K: Resource,
{
    (ResourceExt::annotations(object)
        .get(FINGERPRINT_ANNOTATION)
        .map(String::as_str)
        == Some(fingerprint))
    .then_some(())
    .ok_or(ProviderErrorKind::Conflict)
}

async fn wait_until_ready(
    pods: &Api<Pod>,
    name: &str,
    deadline: Duration,
    operation_timeout: Duration,
    cancellation: &dyn Cancellation,
) -> Result<SandboxState, ProviderErrorKind> {
    let started = Instant::now();
    loop {
        if cancellation.is_cancelled() {
            return Err(ProviderErrorKind::Cancelled);
        }
        let remaining = deadline.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(ProviderErrorKind::TimedOut);
        }
        let pod = timeout(operation_timeout.min(remaining), pods.get(name))
            .await
            .map_err(|_| ProviderErrorKind::TimedOut)?
            .map_err(|error| map_kube_error(&error))?;
        match pod_state(&pod) {
            SandboxState::Running => return Ok(SandboxState::Running),
            SandboxState::Stopped | SandboxState::Degraded => {
                return Err(ProviderErrorKind::InvalidState);
            }
            SandboxState::Absent | SandboxState::Created => {}
        }
        sleep(Duration::from_millis(250).min(deadline.saturating_sub(started.elapsed()))).await;
    }
}

pub(crate) fn pod_state(pod: &Pod) -> SandboxState {
    let Some(status) = &pod.status else {
        return SandboxState::Created;
    };
    match status.phase.as_deref() {
        Some("Running") => {
            let ready = status
                .container_statuses
                .as_deref()
                .unwrap_or_default()
                .iter()
                .find(|container| container.name == crate::objects::MAIN_CONTAINER)
                .is_some_and(|container| container.ready);
            if ready {
                SandboxState::Running
            } else {
                SandboxState::Created
            }
        }
        Some("Succeeded" | "Failed") => SandboxState::Stopped,
        Some("Unknown") => SandboxState::Degraded,
        _ => SandboxState::Created,
    }
}

fn identity_from_pod(
    pod: &Pod,
) -> Result<
    (
        automata_ci_execution::SandboxGeneration,
        SandboxCustody,
        EnvironmentProfile,
    ),
    ProviderErrorKind,
> {
    let annotations = pod.annotations();
    let generation = annotations
        .get(GENERATION_ANNOTATION)
        .and_then(|value| value.parse().ok())
        .and_then(|value| automata_ci_execution::SandboxGeneration::new(value).ok())
        .ok_or(ProviderErrorKind::OwnershipMismatch)?;
    let profile_id = annotations
        .get(PROFILE_ID_ANNOTATION)
        .and_then(|value| EnvironmentProfileId::from_str(value).ok())
        .ok_or(ProviderErrorKind::OwnershipMismatch)?;
    let digest = annotations
        .get(PROFILE_DIGEST_ANNOTATION)
        .and_then(|value| Sha256Digest::from_str(value).ok())
        .ok_or(ProviderErrorKind::OwnershipMismatch)?;
    Ok((
        generation,
        custody_from_object(pod)?,
        EnvironmentProfile::new(profile_id, digest),
    ))
}

fn verify_same_custody<K>(observed: &K, expected: &K) -> Result<(), ProviderErrorKind>
where
    K: Resource,
{
    (custody_from_object(observed)? == custody_from_object(expected)?)
        .then_some(())
        .ok_or(ProviderErrorKind::Conflict)
}

fn custody_from_object<K>(object: &K) -> Result<SandboxCustody, ProviderErrorKind>
where
    K: Resource,
{
    let labels = ResourceExt::labels(object);
    let runner_id = labels
        .get(CUSTODY_RUNNER_LABEL)
        .and_then(|value| RunnerId::from_str(value).ok())
        .ok_or(ProviderErrorKind::OwnershipMismatch)?;
    let slot = labels
        .get(CUSTODY_SLOT_LABEL)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or(ProviderErrorKind::OwnershipMismatch)?;
    match labels.get(CUSTODY_KIND_LABEL).map(String::as_str) {
        Some("profile-admission") if slot == 0 => {
            Ok(SandboxCustody::ProfileAdmission { runner_id })
        }
        Some("job") => NonZeroU16::new(slot)
            .map(|slot_ordinal| SandboxCustody::Job {
                runner_id,
                slot_ordinal,
            })
            .ok_or(ProviderErrorKind::OwnershipMismatch),
        _ => Err(ProviderErrorKind::OwnershipMismatch),
    }
}

pub(crate) fn verify_managed<K>(
    object: &K,
    sandbox: &str,
    generation: Option<u64>,
) -> Result<(), ProviderErrorKind>
where
    K: Resource,
{
    if ResourceExt::labels(object)
        .get(MANAGED_LABEL)
        .map(String::as_str)
        != Some("true")
        || ResourceExt::labels(object)
            .get(SCHEMA_LABEL)
            .map(String::as_str)
            != Some(SANDBOX_SCHEMA)
        || ResourceExt::labels(object)
            .get(SANDBOX_LABEL)
            .map(String::as_str)
            != Some(sandbox)
        || generation.is_some_and(|expected| {
            ResourceExt::annotations(object)
                .get(GENERATION_ANNOTATION)
                .and_then(|value| value.parse::<u64>().ok())
                != Some(expected)
        })
    {
        return Err(ProviderErrorKind::OwnershipMismatch);
    }
    custody_from_object(object)?;
    Ok(())
}

fn sandbox_name(spec: &SandboxSpec) -> String {
    format!(
        "a-{}-{}",
        spec.operation_id().as_uuid().simple(),
        spec.generation().get()
    )
}

fn ensure_handle(
    provider: &ProviderId,
    handle: &SandboxHandle,
    stage: ProviderStage,
) -> Result<(), ProviderError> {
    if handle.provider() != provider || !handle.opaque().starts_with("a-") {
        return Err(provider_error(ProviderErrorKind::OwnershipMismatch, stage));
    }
    Ok(())
}

fn ensure_not_cancelled(
    cancellation: &dyn Cancellation,
    stage: ProviderStage,
) -> Result<(), ProviderError> {
    if cancellation.is_cancelled() {
        return Err(provider_error(ProviderErrorKind::Cancelled, stage));
    }
    Ok(())
}

fn provider_error(kind: ProviderErrorKind, stage: ProviderStage) -> ProviderError {
    ProviderError::new(kind, stage, OperationOutcome::KnownNoEffect, None)
}

pub(crate) fn map_kube_error(error: &kube::Error) -> ProviderErrorKind {
    match api_error_code(error) {
        Some(404) => ProviderErrorKind::NotFound,
        Some(409) => ProviderErrorKind::Conflict,
        Some(400 | 422) => ProviderErrorKind::BackendRejected,
        Some(401 | 403) => ProviderErrorKind::InvalidConfiguration,
        _ => ProviderErrorKind::AdapterUnavailable,
    }
}

fn api_error_code(error: &kube::Error) -> Option<u16> {
    match error {
        kube::Error::Api(response) => Some(response.code),
        _ => None,
    }
}

pub(crate) fn block_on<F, T>(future: F) -> Result<T, ProviderErrorKind>
where
    F: Future<Output = Result<T, ProviderErrorKind>> + Send,
    T: Send,
{
    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| ProviderErrorKind::AdapterUnavailable)?
                    .block_on(future)
            })
            .join()
            .map_err(|_| ProviderErrorKind::AdapterUnavailable)?
    })
}
