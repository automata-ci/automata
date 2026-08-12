//! Quantitative resources and provider capability sets.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{ContainerFeature, IsolationLevel, SandboxFeature};

/// Quantitative capacity available for one matched job.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceCapacity {
    cpu_millis: u32,
    memory_bytes: u64,
    ephemeral_disk_bytes: u64,
    gpu_count: u16,
}

impl ResourceCapacity {
    /// Creates a provider-neutral resource description.
    #[must_use]
    pub const fn new(
        cpu_millis: u32,
        memory_bytes: u64,
        ephemeral_disk_bytes: u64,
        gpu_count: u16,
    ) -> Self {
        Self {
            cpu_millis,
            memory_bytes,
            ephemeral_disk_bytes,
            gpu_count,
        }
    }

    /// Returns CPU capacity in thousandths of one logical CPU.
    #[must_use]
    pub const fn cpu_millis(self) -> u32 {
        self.cpu_millis
    }

    /// Returns enforceable memory capacity in bytes.
    #[must_use]
    pub const fn memory_bytes(self) -> u64 {
        self.memory_bytes
    }

    /// Returns enforceable ephemeral-storage capacity in bytes.
    ///
    /// Zero means no positive disk capacity is advertised; it does not mean
    /// unlimited storage.
    #[must_use]
    pub const fn ephemeral_disk_bytes(self) -> u64 {
        self.ephemeral_disk_bytes
    }

    /// Returns the number of GPU devices available to one job.
    #[must_use]
    pub const fn gpu_count(self) -> u16 {
        self.gpu_count
    }

    /// Returns whether every resource dimension fits within `available`.
    #[must_use]
    pub const fn fits_within(self, available: Self) -> bool {
        self.cpu_millis <= available.cpu_millis
            && self.memory_bytes <= available.memory_bytes
            && self.ephemeral_disk_bytes <= available.ephemeral_disk_bytes
            && self.gpu_count <= available.gpu_count
    }

    /// Adds two resource vectors, returning `None` if any dimension overflows.
    #[must_use]
    pub const fn checked_add(self, other: Self) -> Option<Self> {
        let Some(cpu_millis) = self.cpu_millis.checked_add(other.cpu_millis) else {
            return None;
        };
        let Some(memory_bytes) = self.memory_bytes.checked_add(other.memory_bytes) else {
            return None;
        };
        let Some(ephemeral_disk_bytes) = self
            .ephemeral_disk_bytes
            .checked_add(other.ephemeral_disk_bytes)
        else {
            return None;
        };
        let Some(gpu_count) = self.gpu_count.checked_add(other.gpu_count) else {
            return None;
        };
        Some(Self::new(
            cpu_millis,
            memory_bytes,
            ephemeral_disk_bytes,
            gpu_count,
        ))
    }

    /// Subtracts a resource vector, returning `None` if any dimension is insufficient.
    #[must_use]
    pub const fn checked_sub(self, other: Self) -> Option<Self> {
        let Some(cpu_millis) = self.cpu_millis.checked_sub(other.cpu_millis) else {
            return None;
        };
        let Some(memory_bytes) = self.memory_bytes.checked_sub(other.memory_bytes) else {
            return None;
        };
        let Some(ephemeral_disk_bytes) = self
            .ephemeral_disk_bytes
            .checked_sub(other.ephemeral_disk_bytes)
        else {
            return None;
        };
        let Some(gpu_count) = self.gpu_count.checked_sub(other.gpu_count) else {
            return None;
        };
        Some(Self::new(
            cpu_millis,
            memory_bytes,
            ephemeral_disk_bytes,
            gpu_count,
        ))
    }
}

/// Minimum quantitative resources requested by a job.
pub type ResourceRequirements = ResourceCapacity;

/// Resolved resource reservation and enforcement contract for one job.
///
/// Requests are used for placement and durable capacity reservation. Limits
/// describe the maximum resources the selected sandbox must enforce. The type
/// is provider-neutral and deliberately stores canonical integer units rather
/// than Kubernetes quantity strings.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedJobResourceAllocation")]
pub struct JobResourceAllocation {
    requests: ResourceCapacity,
    limits: ResourceCapacity,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedJobResourceAllocation {
    requests: ResourceCapacity,
    limits: ResourceCapacity,
}

impl JobResourceAllocation {
    /// Creates a resolved allocation after checking its cross-field invariants.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceAllocationError`] when CPU or memory is zero, a
    /// request exceeds its corresponding limit, or GPU requests and limits
    /// differ.
    pub const fn new(
        requests: ResourceCapacity,
        limits: ResourceCapacity,
    ) -> Result<Self, ResourceAllocationError> {
        if requests.cpu_millis == 0 || limits.cpu_millis == 0 {
            return Err(ResourceAllocationError::CpuRequired);
        }
        if requests.memory_bytes == 0 || limits.memory_bytes == 0 {
            return Err(ResourceAllocationError::MemoryRequired);
        }
        if !requests.fits_within(limits) {
            return Err(ResourceAllocationError::RequestExceedsLimit);
        }
        if requests.gpu_count != limits.gpu_count {
            return Err(ResourceAllocationError::GpuRequestLimitMismatch);
        }
        Ok(Self { requests, limits })
    }

    /// Returns the resources reserved for placement.
    #[must_use]
    pub const fn requests(self) -> ResourceCapacity {
        self.requests
    }

    /// Returns the maximum resources the sandbox must enforce.
    #[must_use]
    pub const fn limits(self) -> ResourceCapacity {
        self.limits
    }
}

impl TryFrom<UncheckedJobResourceAllocation> for JobResourceAllocation {
    type Error = ResourceAllocationError;

    fn try_from(value: UncheckedJobResourceAllocation) -> Result<Self, Self::Error> {
        Self::new(value.requests, value.limits)
    }
}

/// Repository-pinned defaults and bounds for workflow resource allocations.
///
/// Projection fills omitted workflow values from `defaults`, then verifies the
/// complete request against these immutable bounds. Pinning this value with a
/// run prevents retries from observing changed `SaaS` configuration.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedJobResourcePolicy")]
pub struct JobResourcePolicy {
    defaults: JobResourceAllocation,
    minimum_requests: ResourceCapacity,
    maximum_limits: ResourceCapacity,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedJobResourcePolicy {
    defaults: JobResourceAllocation,
    minimum_requests: ResourceCapacity,
    maximum_limits: ResourceCapacity,
}

impl JobResourcePolicy {
    /// Creates an internally coherent default-and-bounds policy.
    ///
    /// # Errors
    ///
    /// Rejects a minimum above the default request or a default limit above
    /// the maximum. CPU and memory bounds must remain positive.
    pub const fn new(
        defaults: JobResourceAllocation,
        minimum_requests: ResourceCapacity,
        maximum_limits: ResourceCapacity,
    ) -> Result<Self, ResourcePolicyError> {
        if minimum_requests.cpu_millis == 0
            || minimum_requests.memory_bytes == 0
            || maximum_limits.cpu_millis == 0
            || maximum_limits.memory_bytes == 0
        {
            return Err(ResourcePolicyError::RequiredDimensionIsZero);
        }
        if !minimum_requests.fits_within(defaults.requests)
            || !defaults.limits.fits_within(maximum_limits)
            || minimum_requests.gpu_count > maximum_limits.gpu_count
        {
            return Err(ResourcePolicyError::DefaultsOutsideBounds);
        }
        Ok(Self {
            defaults,
            minimum_requests,
            maximum_limits,
        })
    }

    /// Returns the allocation used when a workflow omits resource values.
    #[must_use]
    pub const fn defaults(self) -> JobResourceAllocation {
        self.defaults
    }

    /// Returns the smallest placement request accepted from a workflow.
    #[must_use]
    pub const fn minimum_requests(self) -> ResourceCapacity {
        self.minimum_requests
    }

    /// Returns the largest enforceable limit accepted from a workflow.
    #[must_use]
    pub const fn maximum_limits(self) -> ResourceCapacity {
        self.maximum_limits
    }

    /// Validates one completely resolved allocation against the policy.
    ///
    /// # Errors
    ///
    /// Rejects requests below the minimum or limits above the maximum.
    pub const fn validate_allocation(
        self,
        allocation: JobResourceAllocation,
    ) -> Result<(), ResourcePolicyError> {
        if !self.minimum_requests.fits_within(allocation.requests) {
            return Err(ResourcePolicyError::RequestBelowMinimum);
        }
        if !allocation.limits.fits_within(self.maximum_limits) {
            return Err(ResourcePolicyError::LimitAboveMaximum);
        }
        Ok(())
    }
}

impl TryFrom<UncheckedJobResourcePolicy> for JobResourcePolicy {
    type Error = ResourcePolicyError;

    fn try_from(value: UncheckedJobResourcePolicy) -> Result<Self, Self::Error> {
        Self::new(value.defaults, value.minimum_requests, value.maximum_limits)
    }
}

/// Invalid pinned job-resource defaults or bounds.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ResourcePolicyError {
    /// CPU and memory policy dimensions must be positive.
    #[error("resource policy CPU and memory dimensions must be positive")]
    RequiredDimensionIsZero,
    /// Default requests or limits fall outside the configured bounds.
    #[error("resource policy defaults fall outside configured bounds")]
    DefaultsOutsideBounds,
    /// A workflow request is below the repository minimum.
    #[error("job resource request is below the repository minimum")]
    RequestBelowMinimum,
    /// A workflow limit is above the repository maximum.
    #[error("job resource limit is above the repository maximum")]
    LimitAboveMaximum,
}

/// Invalid resolved resource allocation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ResourceAllocationError {
    /// CPU requests and limits must both be positive.
    #[error("CPU requests and limits must be positive")]
    CpuRequired,
    /// Memory requests and limits must both be positive.
    #[error("memory requests and limits must be positive")]
    MemoryRequired,
    /// At least one requested dimension is greater than its limit.
    #[error("resource request exceeds its corresponding limit")]
    RequestExceedsLimit,
    /// GPUs are indivisible and cannot be overcommitted by this abstraction.
    #[error("GPU request and limit must be equal")]
    GpuRequestLimitMismatch,
}

/// Parses Kubernetes-style CPU quantities into thousandths of one CPU.
///
/// Supported forms are positive millicores such as `500m` and decimal cores
/// with at most three fractional digits such as `2` or `1.25`.
///
/// # Errors
///
/// Rejects empty, zero, negative, over-precise, or overflowing quantities.
pub fn parse_cpu_quantity(value: &str) -> Result<u32, ResourceQuantityError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(ResourceQuantityError::InvalidCpu);
    }
    let millis = if let Some(number) = value.strip_suffix('m') {
        parse_positive_digits_u32(number).ok_or(ResourceQuantityError::InvalidCpu)?
    } else {
        let mut parts = value.split('.');
        let whole = parts.next().ok_or(ResourceQuantityError::InvalidCpu)?;
        let fraction = parts.next();
        if parts.next().is_some()
            || whole.is_empty()
            || !whole.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(ResourceQuantityError::InvalidCpu);
        }
        let whole = whole
            .parse::<u32>()
            .map_err(|_| ResourceQuantityError::CpuOverflow)?;
        let fractional_millis = match fraction {
            None => 0,
            Some(fraction)
                if !fraction.is_empty()
                    && fraction.len() <= 3
                    && fraction.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                let width = fraction.len();
                let fraction = fraction
                    .parse::<u32>()
                    .map_err(|_| ResourceQuantityError::InvalidCpu)?;
                fraction * 10_u32.pow(u32::try_from(3 - width).unwrap_or(0))
            }
            Some(_) => return Err(ResourceQuantityError::InvalidCpu),
        };
        whole
            .checked_mul(1_000)
            .and_then(|whole| whole.checked_add(fractional_millis))
            .ok_or(ResourceQuantityError::CpuOverflow)?
    };
    if millis == 0 {
        return Err(ResourceQuantityError::InvalidCpu);
    }
    Ok(millis)
}

/// Parses a positive Kubernetes-style storage quantity into bytes.
///
/// Binary `Ki`, `Mi`, `Gi`, `Ti`, `Pi`, `Ei` and decimal `K`, `M`, `G`,
/// `T`, `P`, `E` suffixes are accepted, together with an unsuffixed byte count.
/// Fractions and exponent notation are intentionally excluded from the stable
/// Automata workflow dialect.
///
/// # Errors
///
/// Rejects empty, zero, fractional, negative, unknown-unit, or overflowing quantities.
pub fn parse_storage_quantity(value: &str) -> Result<u64, ResourceQuantityError> {
    let value = value.trim();
    let (number, multiplier) = [
        ("Ei", 1_u64 << 60),
        ("Pi", 1_u64 << 50),
        ("Ti", 1_u64 << 40),
        ("Gi", 1_u64 << 30),
        ("Mi", 1_u64 << 20),
        ("Ki", 1_u64 << 10),
        ("E", 1_000_000_000_000_000_000),
        ("P", 1_000_000_000_000_000),
        ("T", 1_000_000_000_000),
        ("G", 1_000_000_000),
        ("M", 1_000_000),
        ("K", 1_000),
    ]
    .into_iter()
    .find_map(|(suffix, multiplier)| {
        value
            .strip_suffix(suffix)
            .map(|number| (number, multiplier))
    })
    .unwrap_or((value, 1));
    let number = parse_positive_digits_u64(number).ok_or(ResourceQuantityError::InvalidStorage)?;
    number
        .checked_mul(multiplier)
        .ok_or(ResourceQuantityError::StorageOverflow)
}

fn parse_positive_digits_u32(value: &str) -> Option<u32> {
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse::<u32>().ok())
        .flatten()
        .filter(|value| *value > 0)
}

fn parse_positive_digits_u64(value: &str) -> Option<u64> {
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse::<u64>().ok())
        .flatten()
        .filter(|value| *value > 0)
}

/// Invalid workflow resource quantity.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ResourceQuantityError {
    /// CPU quantity does not use the supported grammar.
    #[error("invalid CPU quantity")]
    InvalidCpu,
    /// CPU quantity is syntactically valid but cannot fit the canonical representation.
    #[error("CPU quantity overflows millicores")]
    CpuOverflow,
    /// Storage quantity does not use the supported grammar.
    #[error("invalid storage quantity")]
    InvalidStorage,
    /// Storage quantity is syntactically valid but cannot fit the canonical representation.
    #[error("storage quantity overflows bytes")]
    StorageOverflow,
}

/// Sandbox abilities advertised by a runner.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxCapabilities {
    maximum_isolation: IsolationLevel,
    features: BTreeSet<SandboxFeature>,
}

impl SandboxCapabilities {
    /// Creates a sandbox advertisement from its maximum isolation and features.
    #[must_use]
    pub fn new(
        maximum_isolation: IsolationLevel,
        features: impl IntoIterator<Item = SandboxFeature>,
    ) -> Self {
        Self {
            maximum_isolation,
            features: features.into_iter().collect(),
        }
    }

    /// Returns the strongest isolation boundary this provider can enforce.
    #[must_use]
    pub const fn maximum_isolation(&self) -> IsolationLevel {
        self.maximum_isolation
    }

    /// Returns provider-neutral sandbox features available to a job.
    #[must_use]
    pub const fn features(&self) -> &BTreeSet<SandboxFeature> {
        &self.features
    }
}

/// Container abilities advertised by a runner.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerCapabilities {
    features: BTreeSet<ContainerFeature>,
}

impl ContainerCapabilities {
    /// Creates a container-runtime advertisement.
    #[must_use]
    pub fn new(features: impl IntoIterator<Item = ContainerFeature>) -> Self {
        Self {
            features: features.into_iter().collect(),
        }
    }

    /// Returns provider-neutral container features available to a job.
    #[must_use]
    pub const fn features(&self) -> &BTreeSet<ContainerFeature> {
        &self.features
    }
}
