#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! GitHub job-permission to workload-OIDC runtime-authority bridge.
//!
//! Product composition injects a durable provisioner that authenticates and
//! reserves the exact execution authority before the deterministic private
//! request bearer can be published. The issuer remains optional and fails
//! closed when workload OIDC is not explicitly configured.

mod runtime_authority;

pub use runtime_authority::{
    RandomWorkloadOidcAuthorityIdGenerator, ReserveWorkloadOidcRuntimeAuthority,
    ReservedWorkloadOidcRuntimeAuthority, UnavailableWorkloadOidcRuntimeAuthorityIssuer,
    WorkloadOidcAuthorityIdGenerator, WorkloadOidcAuthorityProvisioner,
    WorkloadOidcRuntimeAuthorityIssuer, WorkloadOidcRuntimeAuthorityIssuerConfigurationError,
};
