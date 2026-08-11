use std::collections::BTreeMap;

use automata_ci_core::{JobResourceAllocation, ResourceCapacity};
use automata_ci_execution::{
    ImmutableImage, NetworkPolicy as SandboxNetworkPolicy, RootFilesystemPolicy, SandboxSpec,
};
use k8s_openapi::{
    api::{
        core::v1::{
            Capabilities, Container, EmptyDirVolumeSource, ExecAction, Pod, PodSecurityContext,
            PodSpec, Probe, ResourceRequirements, SeccompProfile, SecurityContext, Volume,
            VolumeMount,
        },
        networking::v1::{NetworkPolicy, NetworkPolicySpec},
    },
    apimachinery::pkg::{
        api::resource::Quantity,
        apis::meta::v1::{LabelSelector, ObjectMeta},
    },
};
use sha2::{Digest as _, Sha256};

use crate::{
    KUBERNETES_PROVIDER_ID, MINIMUM_KUBERNETES_SANDBOX_MEMORY_BYTES,
    config::KubernetesSandboxConfig, invalid_configuration,
};

pub(crate) const MANAGED_LABEL: &str = "ci.automata.dev/managed";
pub(crate) const SANDBOX_LABEL: &str = "ci.automata.dev/sandbox";
pub(crate) const GENERATION_ANNOTATION: &str = "ci.automata.dev/generation";
pub(crate) const PROFILE_ID_ANNOTATION: &str = "ci.automata.dev/profile-id";
pub(crate) const PROFILE_DIGEST_ANNOTATION: &str = "ci.automata.dev/profile-digest";
pub(crate) const FINGERPRINT_ANNOTATION: &str = "ci.automata.dev/spec-sha256";
pub(crate) const MAIN_CONTAINER: &str = "job";
pub(crate) const GUEST_BINARY: &str = "/automata/bin/automata-ci-sandbox-guest";
pub(crate) const GUEST_SOCKET: &str = "@automata-ci-control-v1";

#[derive(Debug)]
pub(crate) struct SandboxObjects {
    pub(crate) pod: Pod,
    pub(crate) network_policy: NetworkPolicy,
    pub(crate) fingerprint: String,
}

pub(crate) fn build_objects(
    name: &str,
    spec: &SandboxSpec,
    config: &KubernetesSandboxConfig,
) -> Result<SandboxObjects, automata_ci_execution::ProviderError> {
    let allocation = validated_allocation(spec, config)?;
    let image = spec
        .profile()
        .image()
        .ok_or_else(|| invalid_configuration(automata_ci_execution::ProviderStage::Validate))?;
    let fingerprint = fingerprint(spec, image, allocation, config);
    let labels = object_labels(name);
    let annotations = object_annotations(spec, &fingerprint);
    let pod = build_pod(
        name,
        spec,
        image,
        config,
        allocation,
        labels.clone(),
        annotations.clone(),
    );
    let network_policy = deny_all_network_policy(name, config, labels, annotations);
    Ok(SandboxObjects {
        pod,
        network_policy,
        fingerprint,
    })
}

fn validated_allocation(
    spec: &SandboxSpec,
    config: &KubernetesSandboxConfig,
) -> Result<JobResourceAllocation, automata_ci_execution::ProviderError> {
    if spec.network() != SandboxNetworkPolicy::Disabled
        || !spec.services().is_empty()
        || spec.privilege() != automata_ci_execution::SandboxPrivilegePolicy::Unprivileged
        || !spec.has_coherent_resource_contract()
    {
        return Err(invalid_configuration(
            automata_ci_execution::ProviderStage::Validate,
        ));
    }
    let allocation = spec
        .resource_allocation()
        .ok_or_else(|| invalid_configuration(automata_ci_execution::ProviderStage::Validate))?;
    if allocation.limits().gpu_count() > 0 && config.gpu_resource_name().is_none() {
        return Err(invalid_configuration(
            automata_ci_execution::ProviderStage::Validate,
        ));
    }
    if allocation.limits().ephemeral_disk_bytes() > 0 && !config.ephemeral_storage_enforced() {
        return Err(invalid_configuration(
            automata_ci_execution::ProviderStage::Validate,
        ));
    }
    if config.process_limit() != Some(spec.resources().pids()) {
        return Err(invalid_configuration(
            automata_ci_execution::ProviderStage::Validate,
        ));
    }
    if allocation.limits().memory_bytes() < MINIMUM_KUBERNETES_SANDBOX_MEMORY_BYTES {
        return Err(invalid_configuration(
            automata_ci_execution::ProviderStage::Validate,
        ));
    }
    Ok(allocation)
}

fn object_labels(name: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (MANAGED_LABEL.into(), "true".into()),
        (SANDBOX_LABEL.into(), name.into()),
    ])
}

fn object_annotations(spec: &SandboxSpec, fingerprint: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            GENERATION_ANNOTATION.into(),
            spec.generation().get().to_string(),
        ),
        (
            PROFILE_ID_ANNOTATION.into(),
            spec.profile().attestation().id().as_str().into(),
        ),
        (
            PROFILE_DIGEST_ANNOTATION.into(),
            spec.profile().attestation().digest().to_string(),
        ),
        (FINGERPRINT_ANNOTATION.into(), fingerprint.into()),
    ])
}

fn build_pod(
    name: &str,
    spec: &SandboxSpec,
    image: &ImmutableImage,
    config: &KubernetesSandboxConfig,
    allocation: JobResourceAllocation,
    labels: BTreeMap<String, String>,
    annotations: BTreeMap<String, String>,
) -> Pod {
    let security_context = container_security_context(spec, config);
    let init_container = guest_init_container(config, &security_context, guest_volume_mount(false));
    let container = job_container(
        spec,
        image,
        config,
        allocation,
        security_context,
        guest_volume_mount(true),
    );
    Pod {
        metadata: ObjectMeta {
            name: Some(name.into()),
            namespace: Some(config.namespace().into()),
            labels: Some(labels),
            annotations: Some(annotations),
            ..ObjectMeta::default()
        },
        spec: Some(pod_spec(config, init_container, container)),
        status: None,
    }
}

fn container_security_context(
    spec: &SandboxSpec,
    config: &KubernetesSandboxConfig,
) -> SecurityContext {
    SecurityContext {
        allow_privilege_escalation: Some(false),
        capabilities: Some(Capabilities {
            add: None,
            drop: Some(vec!["ALL".into()]),
        }),
        privileged: Some(false),
        read_only_root_filesystem: Some(matches!(
            spec.root_filesystem(),
            RootFilesystemPolicy::ReadOnly
        )),
        run_as_group: Some(config.run_as_group()),
        run_as_non_root: Some(true),
        run_as_user: Some(config.run_as_user()),
        seccomp_profile: Some(runtime_default_seccomp()),
        ..SecurityContext::default()
    }
}

fn runtime_default_seccomp() -> SeccompProfile {
    SeccompProfile {
        localhost_profile: None,
        type_: "RuntimeDefault".into(),
    }
}

fn guest_volume_mount(read_only: bool) -> VolumeMount {
    VolumeMount {
        mount_path: "/automata/bin".into(),
        name: "automata-guest-bin".into(),
        read_only: Some(read_only),
        ..VolumeMount::default()
    }
}

fn guest_init_container(
    config: &KubernetesSandboxConfig,
    security_context: &SecurityContext,
    guest_mount: VolumeMount,
) -> Container {
    Container {
        name: "install-automata-guest".into(),
        image: Some(config.guest_image().reference().into()),
        image_pull_policy: Some("IfNotPresent".into()),
        command: Some(vec![
            "/usr/local/bin/automata-ci-sandbox-guest".into(),
            "install".into(),
            GUEST_BINARY.into(),
        ]),
        security_context: Some(SecurityContext {
            read_only_root_filesystem: Some(true),
            ..security_context.clone()
        }),
        resources: Some(guest_init_resources()),
        termination_message_path: Some("/dev/null".into()),
        termination_message_policy: Some("File".into()),
        volume_mounts: Some(vec![guest_mount]),
        ..Container::default()
    }
}

fn job_container(
    spec: &SandboxSpec,
    image: &ImmutableImage,
    config: &KubernetesSandboxConfig,
    allocation: JobResourceAllocation,
    security_context: SecurityContext,
    guest_mount: VolumeMount,
) -> Container {
    Container {
        name: MAIN_CONTAINER.into(),
        image: Some(image.reference().into()),
        image_pull_policy: Some("IfNotPresent".into()),
        command: Some(vec![
            GUEST_BINARY.into(),
            "serve".into(),
            GUEST_SOCKET.into(),
        ]),
        resources: Some(resource_requirements(allocation, config)),
        readiness_probe: Some(guest_probe(6, Some(1))),
        startup_probe: Some(guest_probe(30, None)),
        security_context: Some(security_context),
        termination_message_path: Some("/dev/null".into()),
        termination_message_policy: Some("File".into()),
        volume_mounts: Some(vec![guest_mount, workspace_volume_mount(spec)]),
        working_dir: Some(spec.workspace().as_str().into()),
        ..Container::default()
    }
}

fn guest_probe(failure_threshold: i32, initial_delay_seconds: Option<i32>) -> Probe {
    Probe {
        exec: Some(ExecAction {
            command: Some(vec![
                GUEST_BINARY.into(),
                "probe".into(),
                GUEST_SOCKET.into(),
            ]),
        }),
        failure_threshold: Some(failure_threshold),
        initial_delay_seconds,
        period_seconds: Some(1),
        success_threshold: Some(1),
        timeout_seconds: Some(1),
        ..Probe::default()
    }
}

fn workspace_volume_mount(spec: &SandboxSpec) -> VolumeMount {
    VolumeMount {
        mount_path: spec.workspace().as_str().into(),
        name: "workspace".into(),
        ..VolumeMount::default()
    }
}

fn pod_spec(
    config: &KubernetesSandboxConfig,
    init_container: Container,
    container: Container,
) -> PodSpec {
    PodSpec {
        automount_service_account_token: Some(false),
        containers: vec![container],
        dns_policy: Some("Default".into()),
        enable_service_links: Some(false),
        host_ipc: Some(false),
        host_network: Some(false),
        host_pid: Some(false),
        init_containers: Some(vec![init_container]),
        node_selector: (!config.node_selector().is_empty()).then(|| config.node_selector().clone()),
        restart_policy: Some("Never".into()),
        runtime_class_name: config.runtime_class_name().map(str::to_owned),
        security_context: Some(PodSecurityContext {
            fs_group: Some(config.run_as_group()),
            run_as_group: Some(config.run_as_group()),
            run_as_non_root: Some(true),
            run_as_user: Some(config.run_as_user()),
            seccomp_profile: Some(runtime_default_seccomp()),
            ..PodSecurityContext::default()
        }),
        termination_grace_period_seconds: Some(5),
        volumes: Some(vec![
            empty_dir_volume("automata-guest-bin"),
            empty_dir_volume("workspace"),
        ]),
        ..PodSpec::default()
    }
}

fn guest_init_resources() -> ResourceRequirements {
    ResourceRequirements {
        requests: Some(BTreeMap::from([
            ("cpu".into(), Quantity("10m".into())),
            ("memory".into(), Quantity((8 * 1_024 * 1_024).to_string())),
        ])),
        limits: Some(BTreeMap::from([
            ("cpu".into(), Quantity("100m".into())),
            ("memory".into(), Quantity((32 * 1_024 * 1_024).to_string())),
        ])),
        ..ResourceRequirements::default()
    }
}

fn empty_dir_volume(name: &str) -> Volume {
    Volume {
        name: name.into(),
        empty_dir: Some(EmptyDirVolumeSource::default()),
        ..Volume::default()
    }
}

fn deny_all_network_policy(
    name: &str,
    config: &KubernetesSandboxConfig,
    labels: BTreeMap<String, String>,
    annotations: BTreeMap<String, String>,
) -> NetworkPolicy {
    NetworkPolicy {
        metadata: ObjectMeta {
            name: Some(network_policy_name(name)),
            namespace: Some(config.namespace().into()),
            labels: Some(labels),
            annotations: Some(annotations),
            ..ObjectMeta::default()
        },
        spec: Some(NetworkPolicySpec {
            egress: Some(Vec::new()),
            ingress: Some(Vec::new()),
            pod_selector: Some(LabelSelector {
                match_labels: Some(BTreeMap::from([(SANDBOX_LABEL.into(), name.into())])),
                ..LabelSelector::default()
            }),
            policy_types: Some(vec!["Ingress".into(), "Egress".into()]),
        }),
    }
}

fn resource_requirements(
    allocation: JobResourceAllocation,
    config: &KubernetesSandboxConfig,
) -> ResourceRequirements {
    ResourceRequirements {
        requests: Some(resource_map(allocation.requests(), config)),
        limits: Some(resource_map(allocation.limits(), config)),
        ..ResourceRequirements::default()
    }
}

fn resource_map(
    resources: ResourceCapacity,
    config: &KubernetesSandboxConfig,
) -> BTreeMap<String, Quantity> {
    let mut values = BTreeMap::from([
        (
            "cpu".into(),
            Quantity(format!("{}m", resources.cpu_millis())),
        ),
        (
            "memory".into(),
            Quantity(resources.memory_bytes().to_string()),
        ),
    ]);
    if resources.ephemeral_disk_bytes() > 0 {
        values.insert(
            "ephemeral-storage".into(),
            Quantity(resources.ephemeral_disk_bytes().to_string()),
        );
    }
    if resources.gpu_count() > 0 {
        values.insert(
            config
                .gpu_resource_name()
                .expect("GPU mapping was validated")
                .into(),
            Quantity(resources.gpu_count().to_string()),
        );
    }
    values
}

fn fingerprint(
    spec: &SandboxSpec,
    image: &ImmutableImage,
    allocation: JobResourceAllocation,
    config: &KubernetesSandboxConfig,
) -> String {
    let mut digest = Sha256::new();
    let operation_id = spec.operation_id().to_string();
    let generation = spec.generation().get().to_string();
    let profile_digest = spec.profile().attestation().digest().to_string();
    for value in [
        KUBERNETES_PROVIDER_ID,
        &operation_id,
        &generation,
        spec.profile().attestation().id().as_str(),
        &profile_digest,
        image.reference(),
        spec.workspace().as_str(),
        config.guest_image().reference(),
    ] {
        hash_fingerprint_field(&mut digest, value.as_bytes());
    }
    digest.update([spec.network() as u8]);
    digest.update([spec.root_filesystem() as u8]);
    digest.update([spec.privilege() as u8]);
    digest.update(config.run_as_user().to_be_bytes());
    digest.update(config.run_as_group().to_be_bytes());
    digest.update([u8::from(config.ephemeral_storage_enforced())]);
    match config.process_limit() {
        Some(value) => {
            digest.update([1]);
            digest.update(value.to_be_bytes());
        }
        None => digest.update([0]),
    }
    match config.gpu_resource_name() {
        Some(value) => {
            digest.update([1]);
            hash_fingerprint_field(&mut digest, value.as_bytes());
        }
        None => digest.update([0]),
    }
    digest.update(
        u64::try_from(config.node_selector().len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for (key, value) in config.node_selector() {
        hash_fingerprint_field(&mut digest, key.as_bytes());
        hash_fingerprint_field(&mut digest, value.as_bytes());
    }
    match config.runtime_class_name() {
        Some(value) => {
            digest.update([1]);
            hash_fingerprint_field(&mut digest, value.as_bytes());
        }
        None => digest.update([0]),
    }
    for resources in [allocation.requests(), allocation.limits()] {
        digest.update(resources.cpu_millis().to_be_bytes());
        digest.update(resources.memory_bytes().to_be_bytes());
        digest.update(resources.ephemeral_disk_bytes().to_be_bytes());
        digest.update(resources.gpu_count().to_be_bytes());
    }
    format!("{:x}", digest.finalize())
}

fn hash_fingerprint_field(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

pub(crate) fn network_policy_name(sandbox_name: &str) -> String {
    format!("{sandbox_name}-deny")
}

#[cfg(test)]
mod tests {
    use automata_ci_core::{EnvironmentProfile, EnvironmentProfileId, OperationId, Sha256Digest};
    use automata_ci_execution::{
        ExecutionArgv, ExecutionEnvironment, ImmutableImage, NetworkPolicy, ResourceLimits,
        RootFilesystemPolicy, SandboxEnvironment, SandboxGeneration, SandboxSpec, TargetPath,
    };

    use super::*;
    use crate::{
        VerifiedEphemeralStorageEnforcement, VerifiedNetworkIsolation,
        VerifiedProcessLimitEnforcement,
    };

    fn immutable_image(repository: &str, byte: u8) -> ImmutableImage {
        ImmutableImage::new(format!(
            "{repository}@sha256:{}",
            format!("{byte:02x}").repeat(32)
        ))
        .expect("immutable image")
    }

    fn config() -> KubernetesSandboxConfig {
        KubernetesSandboxConfig::new(
            "automata-runners",
            immutable_image("registry.example/automata/guest", 1),
            VerifiedNetworkIsolation,
        )
        .expect("config")
        .with_verified_ephemeral_storage(VerifiedEphemeralStorageEnforcement)
        .with_verified_process_limit(
            VerifiedProcessLimitEnforcement::new(512).expect("process limit"),
        )
        .with_gpu_resource_name("nvidia.com/gpu")
        .expect("gpu mapping")
    }

    fn sandbox_spec() -> SandboxSpec {
        let profile = EnvironmentProfile::new(
            EnvironmentProfileId::new("example.com/linux").expect("profile id"),
            Sha256Digest::from_bytes([2; 32]),
        );
        let workspace = TargetPath::posix("/workspace").expect("workspace");
        let environment = SandboxEnvironment::new(
            profile,
            immutable_image("registry.example/automata/job", 3),
            ExecutionArgv::new(
                TargetPath::posix("/bin/sleep").expect("program"),
                vec!["infinity".into()],
            )
            .expect("argv"),
            workspace.clone(),
            ExecutionEnvironment::empty(),
        )
        .expect("environment");
        let allocation = JobResourceAllocation::new(
            ResourceCapacity::new(250, 256 * 1024 * 1024, 1024 * 1024 * 1024, 1),
            ResourceCapacity::new(1_500, 1024 * 1024 * 1024, 2 * 1024 * 1024 * 1024, 1),
        )
        .expect("allocation");
        SandboxSpec::new(
            OperationId::new(),
            SandboxGeneration::new(7).expect("generation"),
            environment,
            workspace,
            NetworkPolicy::Disabled,
            RootFilesystemPolicy::ReadOnly,
            ResourceLimits::new(1024 * 1024 * 1024, 1_500, 512).expect("limits"),
        )
        .with_resource_allocation(allocation)
    }

    #[test]
    fn renders_hardened_pod_and_exact_kubernetes_quantities() {
        let config = config()
            .with_node_selector([("automata.dev/pool".into(), "jobs".into())])
            .expect("node selector")
            .with_runtime_class_name("kata")
            .expect("runtime class");
        let objects = build_objects("a-test-7", &sandbox_spec(), &config).expect("objects");
        let pod_spec = objects.pod.spec.expect("pod spec");
        assert_eq!(pod_spec.automount_service_account_token, Some(false));
        assert_eq!(pod_spec.host_network, Some(false));
        assert_eq!(
            pod_spec
                .node_selector
                .as_ref()
                .and_then(|selector| selector.get("automata.dev/pool"))
                .map(String::as_str),
            Some("jobs")
        );
        assert_eq!(pod_spec.runtime_class_name.as_deref(), Some("kata"));
        let init = &pod_spec.init_containers.as_ref().expect("init containers")[0];
        let init_resources = init.resources.as_ref().expect("init resources");
        assert_eq!(
            init_resources.requests.as_ref().expect("init requests")["cpu"].0,
            "10m"
        );
        assert_eq!(
            init_resources.limits.as_ref().expect("init limits")["memory"].0,
            (32 * 1024 * 1024).to_string()
        );
        assert_eq!(init.termination_message_path.as_deref(), Some("/dev/null"));
        assert_eq!(
            init.volume_mounts.as_ref().expect("init mounts")[0].read_only,
            Some(false)
        );
        let container = pod_spec
            .containers
            .iter()
            .find(|container| container.name == MAIN_CONTAINER)
            .expect("main container");
        let resources = container.resources.as_ref().expect("resources");
        let requests = resources.requests.as_ref().expect("requests");
        let limits = resources.limits.as_ref().expect("limits");
        assert_eq!(requests["cpu"].0, "250m");
        assert_eq!(limits["cpu"].0, "1500m");
        assert_eq!(requests["memory"].0, (256 * 1024 * 1024).to_string());
        assert_eq!(
            limits["ephemeral-storage"].0,
            (2_u64 * 1024 * 1024 * 1024).to_string()
        );
        assert_eq!(limits["nvidia.com/gpu"].0, "1");
        assert_eq!(
            container.termination_message_path.as_deref(),
            Some("/dev/null")
        );
        assert_eq!(
            container
                .volume_mounts
                .as_ref()
                .expect("main mounts")
                .iter()
                .find(|mount| mount.name == "automata-guest-bin")
                .expect("guest mount")
                .read_only,
            Some(true)
        );
        assert_eq!(
            container
                .readiness_probe
                .as_ref()
                .expect("readiness probe")
                .success_threshold,
            Some(1)
        );
        let security = container
            .security_context
            .as_ref()
            .expect("security context");
        assert_eq!(security.run_as_non_root, Some(true));
        assert_eq!(security.allow_privilege_escalation, Some(false));
        assert_eq!(security.read_only_root_filesystem, Some(true));
        assert_eq!(
            security
                .capabilities
                .as_ref()
                .and_then(|value| value.drop.as_ref()),
            Some(&vec!["ALL".into()])
        );
    }

    #[test]
    fn renders_explicit_default_deny_network_policy() {
        let objects = build_objects("a-test-7", &sandbox_spec(), &config()).expect("objects");
        let policy = objects.network_policy.spec.expect("network policy");
        assert_eq!(policy.ingress, Some(Vec::new()));
        assert_eq!(policy.egress, Some(Vec::new()));
        assert_eq!(
            policy.policy_types,
            Some(vec!["Ingress".into(), "Egress".into()])
        );
        assert_eq!(
            policy
                .pod_selector
                .and_then(|selector| selector.match_labels)
                .and_then(|labels| labels.get(SANDBOX_LABEL).cloned()),
            Some("a-test-7".into())
        );
    }

    #[test]
    fn storage_allocation_requires_explicit_cluster_enforcement_evidence() {
        let config = KubernetesSandboxConfig::new(
            "automata-runners",
            immutable_image("registry.example/automata/guest", 1),
            VerifiedNetworkIsolation,
        )
        .expect("config")
        .with_verified_process_limit(
            VerifiedProcessLimitEnforcement::new(512).expect("process limit"),
        )
        .with_gpu_resource_name("nvidia.com/gpu")
        .expect("gpu mapping");
        let error = build_objects("a-test-7", &sandbox_spec(), &config)
            .expect_err("storage without enforcement evidence must reject");
        assert_eq!(
            error.kind(),
            automata_ci_execution::ProviderErrorKind::InvalidConfiguration
        );
    }

    #[test]
    fn guest_overhead_and_resource_identity_fail_closed() {
        let original = sandbox_spec();
        let missing_allocation = SandboxSpec::new(
            original.operation_id(),
            original.generation(),
            original.profile().clone(),
            original.workspace().clone(),
            original.network(),
            original.root_filesystem(),
            original.resources(),
        );
        assert!(build_objects("a-test-7", &missing_allocation, &config()).is_err());

        let too_small = JobResourceAllocation::new(
            ResourceCapacity::new(250, 128 * 1024 * 1024, 0, 0),
            ResourceCapacity::new(1_500, 128 * 1024 * 1024, 0, 0),
        )
        .expect("small allocation");
        let too_small = SandboxSpec::new(
            original.operation_id(),
            original.generation(),
            original.profile().clone(),
            original.workspace().clone(),
            original.network(),
            original.root_filesystem(),
            ResourceLimits::new(128 * 1024 * 1024, 1_500, 512).expect("limits"),
        )
        .with_resource_allocation(too_small);
        assert!(build_objects("a-test-7", &too_small, &config()).is_err());

        let incoherent = JobResourceAllocation::new(
            ResourceCapacity::new(250, 256 * 1024 * 1024, 0, 0),
            ResourceCapacity::new(1_000, 1024 * 1024 * 1024, 0, 0),
        )
        .expect("incoherent allocation");
        let incoherent = SandboxSpec::new(
            original.operation_id(),
            original.generation(),
            original.profile().clone(),
            original.workspace().clone(),
            original.network(),
            original.root_filesystem(),
            original.resources(),
        )
        .with_resource_allocation(incoherent);
        assert!(build_objects("a-test-7", &incoherent, &config()).is_err());
    }
}
