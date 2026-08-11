use std::{collections::BTreeMap, time::Duration};

use automata_ci_execution::ImmutableImage;
use thiserror::Error;

/// Operator assertion that the runner namespace has verified job isolation.
///
/// This assertion covers both enforcement of Kubernetes `NetworkPolicy` and
/// supplemental denial of node-local, instance-metadata, and other host paths
/// that the standard API cannot deny. Constructing the marker is an explicit
/// trust-boundary decision; a plain default-deny `NetworkPolicy` is not enough.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedNetworkIsolation;

/// Operator assertion that kubelet local ephemeral-storage accounting is
/// enabled and enforced on every node eligible for Automata job Pods.
///
/// Kubernetes does not enforce this limit for unsupported node filesystem
/// layouts. The marker makes that cluster acceptance decision explicit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedEphemeralStorageEnforcement;

/// Operator evidence for one node-level Pod PID ceiling shared by every node
/// eligible for Automata job Pods.
///
/// Kubernetes has no per-Pod PID-limit field. This evidence therefore attests
/// an external kubelet/runtime scheduling contract, such as a homogeneous
/// `podPidsLimit` across a dedicated node pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedProcessLimitEnforcement {
    maximum_pids: u32,
}

impl VerifiedProcessLimitEnforcement {
    /// Records the positive process ceiling verified outside the adapter.
    ///
    /// # Errors
    ///
    /// Rejects zero, which cannot enforce the runner execution contract.
    pub const fn new(maximum_pids: u32) -> Result<Self, KubernetesConfigurationError> {
        if maximum_pids == 0 {
            return Err(KubernetesConfigurationError::InvalidProcessLimit);
        }
        Ok(Self { maximum_pids })
    }

    pub(crate) const fn maximum_pids(self) -> u32 {
        self.maximum_pids
    }
}

/// Validated, secret-free Kubernetes adapter configuration.
#[derive(Clone, Debug)]
pub struct KubernetesSandboxConfig {
    namespace: String,
    guest_image: ImmutableImage,
    operation_timeout: Duration,
    readiness_timeout: Duration,
    run_as_user: i64,
    run_as_group: i64,
    gpu_resource_name: Option<String>,
    ephemeral_storage_enforced: bool,
    process_limit: Option<u32>,
    node_selector: BTreeMap<String, String>,
    runtime_class_name: Option<String>,
}

impl KubernetesSandboxConfig {
    /// Creates a fail-closed adapter configuration.
    ///
    /// The isolation marker is intentionally required: Kubernetes accepts a
    /// `NetworkPolicy` object even when the installed CNI ignores it, and the
    /// standard policy model always permits traffic to and from the Pod's node.
    ///
    /// # Errors
    ///
    /// Rejects a noncanonical namespace.
    pub fn new(
        namespace: impl Into<String>,
        guest_image: ImmutableImage,
        _network_isolation: VerifiedNetworkIsolation,
    ) -> Result<Self, KubernetesConfigurationError> {
        let namespace = namespace.into();
        if !valid_dns_subdomain(&namespace) {
            return Err(KubernetesConfigurationError::InvalidNamespace);
        }
        Ok(Self {
            namespace,
            guest_image,
            operation_timeout: Duration::from_secs(30),
            readiness_timeout: Duration::from_mins(5),
            run_as_user: 65_532,
            run_as_group: 65_532,
            gpu_resource_name: None,
            ephemeral_storage_enforced: false,
            process_limit: None,
            node_selector: BTreeMap::new(),
            runtime_class_name: None,
        })
    }

    /// Attests that eligible nodes enforce local ephemeral-storage limits.
    #[must_use]
    pub const fn with_verified_ephemeral_storage(
        mut self,
        _enforcement: VerifiedEphemeralStorageEnforcement,
    ) -> Self {
        self.ephemeral_storage_enforced = true;
        self
    }

    /// Attests a homogeneous external Pod process ceiling.
    #[must_use]
    pub const fn with_verified_process_limit(
        mut self,
        enforcement: VerifiedProcessLimitEnforcement,
    ) -> Self {
        self.process_limit = Some(enforcement.maximum_pids());
        self
    }

    /// Selects bounded API and exec operation timeouts.
    ///
    /// # Errors
    ///
    /// Rejects zero values and durations longer than one hour.
    pub fn with_timeouts(
        mut self,
        operation_timeout: Duration,
        readiness_timeout: Duration,
    ) -> Result<Self, KubernetesConfigurationError> {
        let maximum = Duration::from_hours(1);
        if operation_timeout.is_zero()
            || readiness_timeout.is_zero()
            || operation_timeout > maximum
            || readiness_timeout > maximum
        {
            return Err(KubernetesConfigurationError::InvalidTimeout);
        }
        self.operation_timeout = operation_timeout;
        self.readiness_timeout = readiness_timeout;
        Ok(self)
    }

    /// Selects the non-root identity used by the guest and workload image.
    ///
    /// # Errors
    ///
    /// Rejects root or negative identities.
    pub fn with_run_as(
        mut self,
        user: i64,
        group: i64,
    ) -> Result<Self, KubernetesConfigurationError> {
        if user <= 0 || group <= 0 {
            return Err(KubernetesConfigurationError::InvalidIdentity);
        }
        self.run_as_user = user;
        self.run_as_group = group;
        Ok(self)
    }

    /// Maps Automata's generic GPU count to one Kubernetes extended resource.
    ///
    /// # Errors
    ///
    /// Rejects names that are not domain-qualified extended resources.
    pub fn with_gpu_resource_name(
        mut self,
        name: impl Into<String>,
    ) -> Result<Self, KubernetesConfigurationError> {
        let name = name.into();
        let Some((domain, resource)) = name.split_once('/') else {
            return Err(KubernetesConfigurationError::InvalidGpuResourceName);
        };
        if !valid_dns_subdomain(domain)
            || resource.is_empty()
            || resource.len() > 63
            || !resource
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !resource
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !resource
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            return Err(KubernetesConfigurationError::InvalidGpuResourceName);
        }
        self.gpu_resource_name = Some(name);
        Ok(self)
    }

    /// Restricts job Pods to an exact provider-controlled node selector.
    ///
    /// # Errors
    ///
    /// Rejects duplicate, excessive, or noncanonical Kubernetes label pairs.
    pub fn with_node_selector(
        mut self,
        selector: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, KubernetesConfigurationError> {
        let mut values = BTreeMap::new();
        for (key, value) in selector {
            if values.len() >= 64
                || !valid_label_key(&key)
                || !valid_label_value(&value)
                || values.insert(key, value).is_some()
            {
                return Err(KubernetesConfigurationError::InvalidNodeSelector);
            }
        }
        if values.is_empty() {
            return Err(KubernetesConfigurationError::InvalidNodeSelector);
        }
        self.node_selector = values;
        Ok(self)
    }

    /// Selects an exact Kubernetes `RuntimeClass` for every job Pod.
    ///
    /// # Errors
    ///
    /// Rejects a noncanonical `RuntimeClass` object name.
    pub fn with_runtime_class_name(
        mut self,
        name: impl Into<String>,
    ) -> Result<Self, KubernetesConfigurationError> {
        let name = name.into();
        if !valid_dns_subdomain(&name) {
            return Err(KubernetesConfigurationError::InvalidRuntimeClass);
        }
        self.runtime_class_name = Some(name);
        Ok(self)
    }

    /// Returns the namespace that exclusively contains runner-owned objects.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Returns the deadline for one Kubernetes API or exec operation.
    #[must_use]
    pub const fn operation_timeout(&self) -> Duration {
        self.operation_timeout
    }

    /// Returns the aggregate Pod readiness deadline.
    #[must_use]
    pub const fn readiness_timeout(&self) -> Duration {
        self.readiness_timeout
    }

    /// Returns the non-root workload UID.
    #[must_use]
    pub const fn run_as_user(&self) -> i64 {
        self.run_as_user
    }

    /// Returns the non-root workload GID.
    #[must_use]
    pub const fn run_as_group(&self) -> i64 {
        self.run_as_group
    }

    /// Returns the immutable image supplying the sandbox guest binary.
    #[must_use]
    pub const fn guest_image(&self) -> &ImmutableImage {
        &self.guest_image
    }

    /// Returns the extended resource mapped to Automata GPUs, when configured.
    #[must_use]
    pub fn gpu_resource_name(&self) -> Option<&str> {
        self.gpu_resource_name.as_deref()
    }

    /// Reports whether eligible nodes were attested to enforce ephemeral storage.
    #[must_use]
    pub const fn ephemeral_storage_enforced(&self) -> bool {
        self.ephemeral_storage_enforced
    }

    /// Returns the attested homogeneous Pod process ceiling.
    #[must_use]
    pub const fn process_limit(&self) -> Option<u32> {
        self.process_limit
    }

    /// Returns the provider-controlled node selector.
    #[must_use]
    pub const fn node_selector(&self) -> &BTreeMap<String, String> {
        &self.node_selector
    }

    /// Returns the selected `RuntimeClass`, when configured.
    #[must_use]
    pub fn runtime_class_name(&self) -> Option<&str> {
        self.runtime_class_name.as_deref()
    }
}

/// Invalid Kubernetes adapter configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum KubernetesConfigurationError {
    /// Namespace is not a Kubernetes DNS subdomain.
    #[error("Kubernetes namespace is invalid")]
    InvalidNamespace,
    /// An operation deadline is zero or outside the hard bound.
    #[error("Kubernetes adapter timeout is invalid")]
    InvalidTimeout,
    /// The configured container identity is root or negative.
    #[error("Kubernetes sandbox identity must be non-root")]
    InvalidIdentity,
    /// The GPU resource is not a domain-qualified extended-resource name.
    #[error("Kubernetes GPU extended resource name is invalid")]
    InvalidGpuResourceName,
    /// Node selector is empty, excessive, duplicated, or not a label map.
    #[error("Kubernetes node selector is invalid")]
    InvalidNodeSelector,
    /// `RuntimeClass` name is not a Kubernetes DNS subdomain.
    #[error("Kubernetes runtime class is invalid")]
    InvalidRuntimeClass,
    /// The attested external Pod PID ceiling is zero.
    #[error("Kubernetes process-limit enforcement is invalid")]
    InvalidProcessLimit,
    /// A core provider value could not be constructed.
    #[error("Kubernetes provider identity is invalid")]
    InvalidProviderIdentity,
}

fn valid_dns_subdomain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn valid_label_key(value: &str) -> bool {
    let (prefix, name) = value
        .rsplit_once('/')
        .map_or((None, value), |(prefix, name)| (Some(prefix), name));
    prefix.is_none_or(valid_dns_subdomain) && valid_label_name(name, false)
}

fn valid_label_value(value: &str) -> bool {
    valid_label_name(value, true)
}

fn valid_label_name(value: &str, empty_allowed: bool) -> bool {
    if value.is_empty() {
        return empty_allowed;
    }
    value.len() <= 63
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}
