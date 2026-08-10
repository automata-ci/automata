use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use automata_ci_execution::{
    Cancellation, DestroyDisposition, DestroySandbox, EnvironmentProfile, NetworkPolicy,
    OperationId, OperationOutcome, ProviderError, ResourceLimits, RootFilesystemPolicy,
    SandboxEnvironment, SandboxGeneration, SandboxHandle, SandboxPrivilegePolicy, SandboxProvider,
    SandboxSpec, SandboxState,
};
use uuid::Uuid;

use crate::podman_probe::ProbeCancellation;

const ADMISSION_GENERATION: u64 = 1;
const OPERATION_DOMAIN: [u8; 16] = *b"automata-profile";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ProfileAdmissionPolicy {
    network: NetworkPolicy,
    root_filesystem: RootFilesystemPolicy,
    privilege: SandboxPrivilegePolicy,
    resources: ResourceLimits,
}

impl ProfileAdmissionPolicy {
    pub(super) const fn new(
        network: NetworkPolicy,
        root_filesystem: RootFilesystemPolicy,
        privilege: SandboxPrivilegePolicy,
        resources: ResourceLimits,
    ) -> Self {
        Self {
            network,
            root_filesystem,
            privilege,
            resources,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProfileAdmissionOutcome {
    Admitted,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProfileAdmissionErrorKind {
    InvalidCatalog,
    CreateFailed,
    InvalidCreateEvidence,
    InspectFailed,
    InvalidInspectionEvidence,
    DestroyFailed,
    InvalidDestroyEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProfileAdmissionCleanupStatus {
    NotRequired,
    Complete,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ProfileAdmissionError {
    kind: ProfileAdmissionErrorKind,
    cleanup: ProfileAdmissionCleanupStatus,
    provider_error: Option<ProviderError>,
    cleanup_error: Option<ProviderError>,
}

impl ProfileAdmissionError {
    const fn evidence(
        kind: ProfileAdmissionErrorKind,
        cleanup: ProfileAdmissionCleanupStatus,
        cleanup_error: Option<ProviderError>,
    ) -> Self {
        Self {
            kind,
            cleanup,
            provider_error: None,
            cleanup_error,
        }
    }

    const fn provider(
        kind: ProfileAdmissionErrorKind,
        provider_error: ProviderError,
        cleanup: ProfileAdmissionCleanupStatus,
        cleanup_error: Option<ProviderError>,
    ) -> Self {
        Self {
            kind,
            cleanup,
            provider_error: Some(provider_error),
            cleanup_error,
        }
    }

    pub(super) const fn kind(&self) -> ProfileAdmissionErrorKind {
        self.kind
    }

    pub(super) const fn cleanup_status(&self) -> ProfileAdmissionCleanupStatus {
        self.cleanup
    }

    pub(super) const fn provider_error(&self) -> Option<&ProviderError> {
        self.provider_error.as_ref()
    }

    pub(super) const fn cleanup_error(&self) -> Option<&ProviderError> {
        self.cleanup_error.as_ref()
    }

    fn is_clean_cancellation(&self, cancellation: &ProbeCancellation) -> bool {
        cancellation.is_cancelled()
            && self.cleanup != ProfileAdmissionCleanupStatus::Failed
            && self.provider_error.as_ref().is_some_and(|error| {
                error.kind() == automata_ci_execution::ProviderErrorKind::Cancelled
            })
    }
}

impl fmt::Display for ProfileAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("runner environment-profile admission failed")
    }
}

impl Error for ProfileAdmissionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.cleanup_error
            .as_ref()
            .or(self.provider_error.as_ref())
            .map(|error| error as &(dyn Error + 'static))
    }
}

pub(super) fn admit_environment_profiles(
    provider: &dyn SandboxProvider,
    environments: &BTreeMap<EnvironmentProfile, SandboxEnvironment>,
    policy: ProfileAdmissionPolicy,
    cancellation: &ProbeCancellation,
) -> Result<ProfileAdmissionOutcome, ProfileAdmissionError> {
    validate_catalog(environments)?;
    let generation = SandboxGeneration::new(ADMISSION_GENERATION).map_err(|_| {
        ProfileAdmissionError::evidence(
            ProfileAdmissionErrorKind::InvalidCatalog,
            ProfileAdmissionCleanupStatus::NotRequired,
            None,
        )
    })?;
    let context = ProfileAdmissionContext {
        provider,
        policy,
        generation,
        provisioning_cancellation: ProvisioningCancellation(cancellation),
        cleanup_cancellation: CleanupCancellation(cancellation),
    };

    for environment in environments.values() {
        if cancellation.is_cancelled() {
            return Ok(ProfileAdmissionOutcome::Cancelled);
        }
        if let Err(error) = context.admit(environment) {
            if error.is_clean_cancellation(cancellation) {
                return Ok(ProfileAdmissionOutcome::Cancelled);
            }
            return Err(error);
        }
    }

    Ok(if cancellation.is_cancelled() {
        ProfileAdmissionOutcome::Cancelled
    } else {
        ProfileAdmissionOutcome::Admitted
    })
}

struct ProfileAdmissionContext<'context> {
    provider: &'context dyn SandboxProvider,
    policy: ProfileAdmissionPolicy,
    generation: SandboxGeneration,
    provisioning_cancellation: ProvisioningCancellation<'context>,
    cleanup_cancellation: CleanupCancellation<'context>,
}

impl ProfileAdmissionContext<'_> {
    fn admit(&self, environment: &SandboxEnvironment) -> Result<(), ProfileAdmissionError> {
        let operation_ids = AdmissionOperationIds::for_profile(environment.attestation());
        let spec = SandboxSpec::new(
            operation_ids.create,
            self.generation,
            environment.clone(),
            environment.workspace().clone(),
            self.policy.network,
            self.policy.root_filesystem,
            self.policy.resources,
        )
        .with_privilege(self.policy.privilege);
        let record = self.create(environment, &spec, operation_ids.destroy)?;
        self.inspect(environment, &record, operation_ids.destroy)?;
        self.destroy(&record, operation_ids.destroy)
    }

    fn create(
        &self,
        environment: &SandboxEnvironment,
        spec: &SandboxSpec,
        destroy_operation_id: OperationId,
    ) -> Result<automata_ci_execution::SandboxRecord, ProfileAdmissionError> {
        let record = match self.provider.create(spec, &self.provisioning_cancellation) {
            Ok(record) => record,
            Err(error) => {
                let recovery_handle = error.recovery_handle().cloned();
                let (cleanup, cleanup_error) = cleanup_after_create_failure(
                    self.provider,
                    recovery_handle.as_ref(),
                    self.generation,
                    destroy_operation_id,
                    error.outcome(),
                    &self.cleanup_cancellation,
                );
                return Err(ProfileAdmissionError::provider(
                    ProfileAdmissionErrorKind::CreateFailed,
                    error,
                    cleanup,
                    cleanup_error,
                ));
            }
        };

        if record.handle().provider() != self.provider.provider_id()
            || record.generation() != self.generation
            || record.profile() != environment.attestation()
            || record.state() != SandboxState::Running
        {
            let (cleanup, cleanup_error) = cleanup_handle(
                self.provider,
                record.handle(),
                self.generation,
                destroy_operation_id,
                &self.cleanup_cancellation,
            );
            return Err(ProfileAdmissionError::evidence(
                ProfileAdmissionErrorKind::InvalidCreateEvidence,
                cleanup,
                cleanup_error,
            ));
        }
        Ok(record)
    }

    fn inspect(
        &self,
        environment: &SandboxEnvironment,
        record: &automata_ci_execution::SandboxRecord,
        destroy_operation_id: OperationId,
    ) -> Result<(), ProfileAdmissionError> {
        let inspection = match self
            .provider
            .inspect(record.handle(), &self.provisioning_cancellation)
        {
            Ok(inspection) => inspection,
            Err(error) => {
                let (cleanup, cleanup_error) = cleanup_handle(
                    self.provider,
                    record.handle(),
                    self.generation,
                    destroy_operation_id,
                    &self.cleanup_cancellation,
                );
                return Err(ProfileAdmissionError::provider(
                    ProfileAdmissionErrorKind::InspectFailed,
                    error,
                    cleanup,
                    cleanup_error,
                ));
            }
        };
        if inspection.handle() != record.handle()
            || inspection.handle().provider() != self.provider.provider_id()
            || inspection.generation() != self.generation
            || inspection.profile() != environment.attestation()
            || inspection.state() != SandboxState::Running
        {
            let (cleanup, cleanup_error) = cleanup_handle(
                self.provider,
                record.handle(),
                self.generation,
                destroy_operation_id,
                &self.cleanup_cancellation,
            );
            return Err(ProfileAdmissionError::evidence(
                ProfileAdmissionErrorKind::InvalidInspectionEvidence,
                cleanup,
                cleanup_error,
            ));
        }
        Ok(())
    }

    fn destroy(
        &self,
        record: &automata_ci_execution::SandboxRecord,
        operation_id: OperationId,
    ) -> Result<(), ProfileAdmissionError> {
        match destroy_with_reconciliation(
            self.provider,
            record.handle(),
            self.generation,
            operation_id,
            &self.cleanup_cancellation,
        ) {
            Ok(DestroyEvidence::Destroyed | DestroyEvidence::ReconciledAbsent) => Ok(()),
            Ok(DestroyEvidence::InitiallyAbsent) => Err(ProfileAdmissionError::evidence(
                ProfileAdmissionErrorKind::InvalidDestroyEvidence,
                ProfileAdmissionCleanupStatus::Complete,
                None,
            )),
            Err(error) => Err(ProfileAdmissionError::provider(
                ProfileAdmissionErrorKind::DestroyFailed,
                error.clone(),
                ProfileAdmissionCleanupStatus::Failed,
                Some(error),
            )),
        }
    }
}

fn validate_catalog(
    environments: &BTreeMap<EnvironmentProfile, SandboxEnvironment>,
) -> Result<(), ProfileAdmissionError> {
    let mut operation_ids = BTreeSet::new();
    if environments.is_empty()
        || environments.iter().any(|(profile, environment)| {
            profile != environment.attestation()
                || !AdmissionOperationIds::for_profile(profile)
                    .values()
                    .into_iter()
                    .all(|operation_id| operation_ids.insert(operation_id))
        })
    {
        return Err(ProfileAdmissionError::evidence(
            ProfileAdmissionErrorKind::InvalidCatalog,
            ProfileAdmissionCleanupStatus::NotRequired,
            None,
        ));
    }
    Ok(())
}

fn cleanup_after_create_failure(
    provider: &dyn SandboxProvider,
    recovery_handle: Option<&SandboxHandle>,
    generation: SandboxGeneration,
    operation_id: OperationId,
    outcome: OperationOutcome,
    cancellation: &dyn Cancellation,
) -> (ProfileAdmissionCleanupStatus, Option<ProviderError>) {
    match recovery_handle {
        Some(handle) => cleanup_handle(provider, handle, generation, operation_id, cancellation),
        None if outcome == OperationOutcome::KnownNoEffect => {
            (ProfileAdmissionCleanupStatus::NotRequired, None)
        }
        None => (ProfileAdmissionCleanupStatus::Failed, None),
    }
}

fn cleanup_handle(
    provider: &dyn SandboxProvider,
    handle: &SandboxHandle,
    generation: SandboxGeneration,
    operation_id: OperationId,
    cancellation: &dyn Cancellation,
) -> (ProfileAdmissionCleanupStatus, Option<ProviderError>) {
    match destroy_with_reconciliation(provider, handle, generation, operation_id, cancellation) {
        Ok(_) => (ProfileAdmissionCleanupStatus::Complete, None),
        Err(error) => (ProfileAdmissionCleanupStatus::Failed, Some(error)),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DestroyEvidence {
    Destroyed,
    ReconciledAbsent,
    InitiallyAbsent,
}

fn destroy_with_reconciliation(
    provider: &dyn SandboxProvider,
    handle: &SandboxHandle,
    generation: SandboxGeneration,
    operation_id: OperationId,
    cancellation: &dyn Cancellation,
) -> Result<DestroyEvidence, ProviderError> {
    let request = DestroySandbox::new(operation_id, handle.clone(), generation);
    match provider.destroy(&request, cancellation) {
        Ok(DestroyDisposition::Destroyed) => Ok(DestroyEvidence::Destroyed),
        Ok(DestroyDisposition::AlreadyAbsent) => Ok(DestroyEvidence::InitiallyAbsent),
        Err(error)
            if error.outcome() == OperationOutcome::Uncertain
                && error
                    .recovery_handle()
                    .is_none_or(|recovery_handle| recovery_handle == handle) =>
        {
            match provider.destroy(&request, cancellation)? {
                DestroyDisposition::Destroyed => Ok(DestroyEvidence::Destroyed),
                DestroyDisposition::AlreadyAbsent => Ok(DestroyEvidence::ReconciledAbsent),
            }
        }
        Err(error) => Err(error),
    }
}

#[derive(Clone, Copy)]
struct AdmissionOperationIds {
    create: OperationId,
    destroy: OperationId,
}

impl AdmissionOperationIds {
    fn for_profile(profile: &EnvironmentProfile) -> Self {
        Self {
            create: operation_id(profile, 0x43),
            destroy: operation_id(profile, 0x44),
        }
    }

    const fn values(self) -> [OperationId; 2] {
        [self.create, self.destroy]
    }
}

fn operation_id(profile: &EnvironmentProfile, purpose: u8) -> OperationId {
    let digest = profile.digest().into_bytes();
    let mut bytes = [0_u8; 16];
    for index in 0..bytes.len() {
        bytes[index] = digest[index] ^ digest[index + bytes.len()] ^ OPERATION_DOMAIN[index];
    }
    let mut ordinal = 0_u8;
    for (index, byte) in profile.id().as_str().bytes().enumerate() {
        let lane = index % bytes.len();
        bytes[lane] = bytes[lane].rotate_left(5) ^ byte ^ ordinal.wrapping_mul(0x9d);
        ordinal = ordinal.wrapping_add(1);
    }
    bytes[15] ^= purpose;
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    OperationId::from_uuid(Uuid::from_bytes(bytes))
}

struct ProvisioningCancellation<'cancellation>(&'cancellation ProbeCancellation);

impl Cancellation for ProvisioningCancellation<'_> {
    fn is_cancelled(&self) -> bool {
        self.0.is_cancelled()
    }
}

struct CleanupCancellation<'cancellation>(&'cancellation ProbeCancellation);

impl Cancellation for CleanupCancellation<'_> {
    fn is_cancelled(&self) -> bool {
        self.0.is_forced()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use automata_ci_execution::{
        ExecutionArgv, ExecutionEndpoint, ExecutionEnvironment, ImmutableImage,
        ProviderCapabilities, ProviderErrorKind, ProviderId, ProviderStage, SandboxCapability,
        SandboxInspection, SandboxRecord, TargetPath,
    };

    use super::*;

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    enum FakeBehavior {
        #[default]
        Happy,
        CreateFailureWithRecovery,
        CreateState(SandboxState),
        InspectState(SandboxState),
        DestroyInitiallyAbsent,
        DestroyUncertainOnce,
        CancelAfterCreate(u8),
        InspectAndDestroyFailure,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Call {
        Create(Box<SandboxSpec>),
        Inspect(SandboxHandle),
        Destroy(DestroySandbox, bool),
    }

    #[derive(Debug)]
    struct FakeState {
        calls: Vec<Call>,
        resources: BTreeMap<SandboxHandle, (SandboxGeneration, EnvironmentProfile)>,
    }

    #[derive(Debug)]
    struct FakeProvider {
        id: ProviderId,
        capabilities: ProviderCapabilities,
        behavior: FakeBehavior,
        signals: ProbeCancellation,
        state: Mutex<FakeState>,
    }

    impl FakeProvider {
        fn new(behavior: FakeBehavior, signals: ProbeCancellation) -> Self {
            Self {
                id: ProviderId::new("profile-admission-test").expect("provider id"),
                capabilities: ProviderCapabilities::new([SandboxCapability::WholeJob])
                    .expect("capabilities"),
                behavior,
                signals,
                state: Mutex::new(FakeState {
                    calls: Vec::new(),
                    resources: BTreeMap::new(),
                }),
            }
        }

        fn calls(&self) -> Vec<Call> {
            self.state.lock().expect("fake state").calls.clone()
        }

        fn resource_count(&self) -> usize {
            self.state.lock().expect("fake state").resources.len()
        }
    }

    impl SandboxProvider for FakeProvider {
        fn provider_id(&self) -> &ProviderId {
            &self.id
        }

        fn capabilities(&self) -> &ProviderCapabilities {
            &self.capabilities
        }

        fn create(
            &self,
            spec: &SandboxSpec,
            cancellation: &dyn Cancellation,
        ) -> Result<SandboxRecord, ProviderError> {
            if cancellation.is_cancelled() {
                return Err(cancelled(ProviderStage::CreateSandbox));
            }
            let handle =
                SandboxHandle::new(self.id.clone(), format!("profile-{}", spec.operation_id()))
                    .expect("handle");
            let mut state = self.state.lock().expect("fake state");
            state.calls.push(Call::Create(Box::new(spec.clone())));
            state.resources.insert(
                handle.clone(),
                (spec.generation(), spec.profile().attestation().clone()),
            );
            drop(state);
            let cancel_after_create = match self.behavior {
                FakeBehavior::CancelAfterCreate(count) => count,
                _ => 0,
            };
            for _ in 0..cancel_after_create {
                self.signals.cancel();
            }
            if self.behavior == FakeBehavior::CreateFailureWithRecovery {
                return Err(ProviderError::new(
                    ProviderErrorKind::AdapterUnavailable,
                    ProviderStage::Start,
                    OperationOutcome::Uncertain,
                    Some(handle),
                ));
            }
            Ok(SandboxRecord::new(
                handle,
                spec.generation(),
                spec.profile().attestation().clone(),
                match self.behavior {
                    FakeBehavior::CreateState(state) => state,
                    _ => SandboxState::Running,
                },
            ))
        }

        fn attach(
            &self,
            _handle: &SandboxHandle,
            _cancellation: &dyn Cancellation,
        ) -> Result<Box<dyn ExecutionEndpoint>, ProviderError> {
            Err(ProviderError::new(
                ProviderErrorKind::UnsupportedCapability,
                ProviderStage::Attach,
                OperationOutcome::KnownNoEffect,
                None,
            ))
        }

        fn inspect(
            &self,
            handle: &SandboxHandle,
            cancellation: &dyn Cancellation,
        ) -> Result<SandboxInspection, ProviderError> {
            self.state
                .lock()
                .expect("fake state")
                .calls
                .push(Call::Inspect(handle.clone()));
            if cancellation.is_cancelled() {
                return Err(cancelled(ProviderStage::Inspect));
            }
            if self.behavior == FakeBehavior::InspectAndDestroyFailure {
                return Err(ProviderError::new(
                    ProviderErrorKind::AdapterUnavailable,
                    ProviderStage::Inspect,
                    OperationOutcome::KnownNoEffect,
                    None,
                ));
            }
            let state = self.state.lock().expect("fake state");
            let (generation, profile) = state.resources.get(handle).expect("owned resource");
            Ok(SandboxInspection::new(
                handle.clone(),
                *generation,
                profile.clone(),
                match self.behavior {
                    FakeBehavior::InspectState(state) => state,
                    _ => SandboxState::Running,
                },
            ))
        }

        fn destroy(
            &self,
            request: &DestroySandbox,
            cancellation: &dyn Cancellation,
        ) -> Result<DestroyDisposition, ProviderError> {
            let cancelled = cancellation.is_cancelled();
            let mut state = self.state.lock().expect("fake state");
            let first_destroy = !state
                .calls
                .iter()
                .any(|call| matches!(call, Call::Destroy(_, _)));
            state.calls.push(Call::Destroy(request.clone(), cancelled));
            if cancelled {
                return Err(super::tests::cancelled(ProviderStage::DestroySandbox));
            }
            if self.behavior == FakeBehavior::InspectAndDestroyFailure {
                return Err(ProviderError::new(
                    ProviderErrorKind::BackendRejected,
                    ProviderStage::DestroySandbox,
                    OperationOutcome::KnownNoEffect,
                    None,
                ));
            }
            if self.behavior == FakeBehavior::DestroyInitiallyAbsent {
                state.resources.remove(request.handle());
                return Ok(DestroyDisposition::AlreadyAbsent);
            }
            if self.behavior == FakeBehavior::DestroyUncertainOnce && first_destroy {
                state.resources.remove(request.handle());
                return Err(ProviderError::new(
                    ProviderErrorKind::AdapterUnavailable,
                    ProviderStage::DestroySandbox,
                    OperationOutcome::Uncertain,
                    Some(request.handle().clone()),
                ));
            }
            Ok(if state.resources.remove(request.handle()).is_some() {
                DestroyDisposition::Destroyed
            } else {
                DestroyDisposition::AlreadyAbsent
            })
        }
    }

    fn cancelled(stage: ProviderStage) -> ProviderError {
        ProviderError::new(
            ProviderErrorKind::Cancelled,
            stage,
            OperationOutcome::KnownNoEffect,
            None,
        )
    }

    fn environment(
        id: &str,
        profile_digest: [u8; 32],
        image_digest_byte: u8,
    ) -> (EnvironmentProfile, SandboxEnvironment) {
        let profile_id = format!("test.local/{id}");
        let attestation = EnvironmentProfile::new(
            automata_ci_execution::EnvironmentProfileId::new(profile_id).expect("profile id"),
            automata_ci_execution::Sha256Digest::from_bytes(profile_digest),
        );
        let image_digest = format!("{image_digest_byte:02x}").repeat(32);
        let image = ImmutableImage::new(format!(
            "registry.example.test/automata/{id}@sha256:{image_digest}"
        ))
        .expect("immutable image");
        let keepalive = ExecutionArgv::new(
            TargetPath::posix("/bin/sleep").expect("keepalive path"),
            vec!["infinity".to_owned()],
        )
        .expect("keepalive");
        let environment = SandboxEnvironment::new(
            attestation.clone(),
            image,
            keepalive,
            TargetPath::posix(format!("/work/{id}")).expect("workspace"),
            ExecutionEnvironment::empty(),
        )
        .expect("environment");
        (attestation, environment)
    }

    fn policy() -> ProfileAdmissionPolicy {
        ProfileAdmissionPolicy::new(
            NetworkPolicy::Disabled,
            RootFilesystemPolicy::Writable,
            SandboxPrivilegePolicy::Administrator,
            ResourceLimits::new(256 * 1024 * 1024, 1_750, 321).expect("resources"),
        )
    }

    fn profile_digest(seed: u8) -> [u8; 32] {
        let mut value = seed;
        std::array::from_fn(|_| {
            let byte = value;
            value = value.wrapping_add(0x1d);
            byte
        })
    }

    #[test]
    fn every_profile_uses_exact_policy_and_full_lifecycle() {
        let signals = ProbeCancellation::default();
        let provider = FakeProvider::new(FakeBehavior::default(), signals.clone());
        let profiles = BTreeMap::from([
            environment("linux-b", profile_digest(0x22), 0xb2),
            environment("linux-a", profile_digest(0x11), 0xa1),
        ]);

        assert_eq!(
            admit_environment_profiles(&provider, &profiles, policy(), &signals),
            Ok(ProfileAdmissionOutcome::Admitted)
        );
        assert_eq!(provider.resource_count(), 0);
        let calls = provider.calls();
        assert_eq!(calls.len(), profiles.len() * 3);
        for (calls, environment) in calls.chunks_exact(3).zip(profiles.values()) {
            let Call::Create(spec) = &calls[0] else {
                panic!("profile must begin with create")
            };
            assert_eq!(spec.profile(), environment);
            assert_eq!(spec.workspace(), environment.workspace());
            assert_eq!(spec.network(), NetworkPolicy::Disabled);
            assert_eq!(spec.root_filesystem(), RootFilesystemPolicy::Writable);
            assert_eq!(spec.privilege(), SandboxPrivilegePolicy::Administrator);
            assert_eq!(spec.resources(), policy().resources);
            assert_eq!(spec.generation().get(), ADMISSION_GENERATION);
            let Call::Inspect(inspected) = &calls[1] else {
                panic!("profile create must be inspected")
            };
            let Call::Destroy(destroyed, cleanup_cancelled) = &calls[2] else {
                panic!("profile inspection must be destroyed")
            };
            assert!(!cleanup_cancelled);
            assert_eq!(inspected, destroyed.handle());
            assert_eq!(destroyed.generation(), spec.generation());
            assert_ne!(destroyed.operation_id(), spec.operation_id());
        }

        let first_ids: Vec<_> = calls
            .iter()
            .filter_map(|call| match call {
                Call::Create(spec) => Some(spec.operation_id()),
                Call::Destroy(request, _) => Some(request.operation_id()),
                Call::Inspect(_) => None,
            })
            .collect();
        assert_eq!(
            admit_environment_profiles(&provider, &profiles, policy(), &signals),
            Ok(ProfileAdmissionOutcome::Admitted)
        );
        let second_ids: Vec<_> = provider.calls()[calls.len()..]
            .iter()
            .filter_map(|call| match call {
                Call::Create(spec) => Some(spec.operation_id()),
                Call::Destroy(request, _) => Some(request.operation_id()),
                Call::Inspect(_) => None,
            })
            .collect();
        assert_eq!(first_ids, second_ids);
    }

    #[test]
    fn uncertain_create_recovery_handle_is_destroyed() {
        let signals = ProbeCancellation::default();
        let provider = FakeProvider::new(FakeBehavior::CreateFailureWithRecovery, signals.clone());
        let profiles = BTreeMap::from([environment("linux", profile_digest(0x31), 0x41)]);

        let error = admit_environment_profiles(&provider, &profiles, policy(), &signals)
            .expect_err("create failure cannot admit profile");
        assert_eq!(error.kind(), ProfileAdmissionErrorKind::CreateFailed);
        assert_eq!(
            error.cleanup_status(),
            ProfileAdmissionCleanupStatus::Complete
        );
        assert_eq!(provider.resource_count(), 0);
        assert!(matches!(
            provider.calls().as_slice(),
            [Call::Create(_), Call::Destroy(_, false)]
        ));
    }

    #[test]
    fn invalid_create_and_inspection_evidence_are_cleaned() {
        for behavior in [
            FakeBehavior::CreateState(SandboxState::Created),
            FakeBehavior::InspectState(SandboxState::Degraded),
        ] {
            let signals = ProbeCancellation::default();
            let provider = FakeProvider::new(behavior, signals.clone());
            let profiles = BTreeMap::from([environment("linux", profile_digest(0x51), 0x61)]);
            let error = admit_environment_profiles(&provider, &profiles, policy(), &signals)
                .expect_err("invalid lifecycle evidence cannot admit profile");
            assert!(matches!(
                error.kind(),
                ProfileAdmissionErrorKind::InvalidCreateEvidence
                    | ProfileAdmissionErrorKind::InvalidInspectionEvidence
            ));
            assert_eq!(
                error.cleanup_status(),
                ProfileAdmissionCleanupStatus::Complete
            );
            assert_eq!(provider.resource_count(), 0);
        }
    }

    #[test]
    fn first_shutdown_request_cancels_provisioning_but_not_cleanup() {
        let signals = ProbeCancellation::default();
        let provider = FakeProvider::new(FakeBehavior::CancelAfterCreate(1), signals.clone());
        let profiles = BTreeMap::from([environment("linux", profile_digest(0x71), 0x81)]);

        assert_eq!(
            admit_environment_profiles(&provider, &profiles, policy(), &signals),
            Ok(ProfileAdmissionOutcome::Cancelled)
        );
        assert_eq!(provider.resource_count(), 0);
        assert!(matches!(
            provider.calls().as_slice(),
            [Call::Create(_), Call::Inspect(_), Call::Destroy(_, false)]
        ));
    }

    #[test]
    fn forced_shutdown_reports_failed_cleanup() {
        let signals = ProbeCancellation::default();
        let provider = FakeProvider::new(FakeBehavior::CancelAfterCreate(2), signals.clone());
        let profiles = BTreeMap::from([environment("linux", profile_digest(0x91), 0xa1)]);

        let error = admit_environment_profiles(&provider, &profiles, policy(), &signals)
            .expect_err("forced cancellation may interrupt cleanup but cannot hide it");
        assert_eq!(error.kind(), ProfileAdmissionErrorKind::InspectFailed);
        assert_eq!(
            error.cleanup_status(),
            ProfileAdmissionCleanupStatus::Failed
        );
        assert_eq!(provider.resource_count(), 1);
        assert!(matches!(
            provider.calls().last(),
            Some(Call::Destroy(_, true))
        ));
    }

    #[test]
    fn cleanup_failure_preserves_primary_inspection_failure() {
        let signals = ProbeCancellation::default();
        let provider = FakeProvider::new(FakeBehavior::InspectAndDestroyFailure, signals.clone());
        let profiles = BTreeMap::from([environment("linux", profile_digest(0xb1), 0xc1)]);

        let error = admit_environment_profiles(&provider, &profiles, policy(), &signals)
            .expect_err("cleanup failure cannot admit profile");
        assert_eq!(error.kind(), ProfileAdmissionErrorKind::InspectFailed);
        assert_eq!(
            error.cleanup_status(),
            ProfileAdmissionCleanupStatus::Failed
        );
        assert_eq!(
            error.provider_error().map(ProviderError::kind),
            Some(ProviderErrorKind::AdapterUnavailable)
        );
        assert_eq!(
            error.cleanup_error().map(ProviderError::kind),
            Some(ProviderErrorKind::BackendRejected)
        );
    }

    #[test]
    fn disappearance_before_initial_destroy_fails_admission() {
        let signals = ProbeCancellation::default();
        let provider = FakeProvider::new(FakeBehavior::DestroyInitiallyAbsent, signals.clone());
        let profiles = BTreeMap::from([environment("linux", profile_digest(0xc1), 0xd1)]);

        let error = admit_environment_profiles(&provider, &profiles, policy(), &signals)
            .expect_err("an initially absent destroy target invalidates lifecycle evidence");
        assert_eq!(
            error.kind(),
            ProfileAdmissionErrorKind::InvalidDestroyEvidence
        );
        assert_eq!(
            error.cleanup_status(),
            ProfileAdmissionCleanupStatus::Complete
        );
        assert_eq!(provider.resource_count(), 0);
    }

    #[test]
    fn uncertain_destroy_is_replayed_and_reconciled_absent() {
        let signals = ProbeCancellation::default();
        let provider = FakeProvider::new(FakeBehavior::DestroyUncertainOnce, signals.clone());
        let profiles = BTreeMap::from([environment("linux", profile_digest(0xc7), 0xd7)]);

        assert_eq!(
            admit_environment_profiles(&provider, &profiles, policy(), &signals),
            Ok(ProfileAdmissionOutcome::Admitted)
        );
        assert_eq!(provider.resource_count(), 0);
        let calls = provider.calls();
        assert!(matches!(
            calls.as_slice(),
            [Call::Create(_), Call::Inspect(_), Call::Destroy(first, false), Call::Destroy(second, false)]
                if first == second
        ));
    }

    #[test]
    fn deterministic_operation_collision_fails_before_mutation() {
        let signals = ProbeCancellation::default();
        let provider = FakeProvider::new(FakeBehavior::default(), signals.clone());
        let first_digest = profile_digest(0xd1);
        let mut colliding_digest = first_digest;
        colliding_digest[0] ^= 0x5a;
        colliding_digest[16] ^= 0x5a;
        let profiles = BTreeMap::from([
            environment("linux", first_digest, 0xe1),
            environment("linux", colliding_digest, 0xf1),
        ]);

        let error = admit_environment_profiles(&provider, &profiles, policy(), &signals)
            .expect_err("colliding replay coordinates must fail before create");
        assert_eq!(error.kind(), ProfileAdmissionErrorKind::InvalidCatalog);
        assert_eq!(
            error.cleanup_status(),
            ProfileAdmissionCleanupStatus::NotRequired
        );
        assert!(provider.calls().is_empty());
    }

    #[test]
    fn replay_coordinates_bind_full_digest_and_profile_identity() {
        let (first, _) = environment("linux", profile_digest(0x17), 0x27);
        let mut changed_lower_half = profile_digest(0x17);
        changed_lower_half[16] ^= 0x80;
        let (changed_digest, _) = environment("linux", changed_lower_half, 0x27);
        let (changed_id, _) = environment("linux-other", profile_digest(0x17), 0x27);

        assert_ne!(
            AdmissionOperationIds::for_profile(&first).values(),
            AdmissionOperationIds::for_profile(&changed_digest).values()
        );
        assert_ne!(
            AdmissionOperationIds::for_profile(&first).values(),
            AdmissionOperationIds::for_profile(&changed_id).values()
        );
    }
}
