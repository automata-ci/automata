//! Job-attempt lifecycle, leases, and fencing.

mod attempt;
mod authorization;
mod lease;
mod lifecycle;
mod windows;

pub use attempt::{AttemptStateError, FenceError, JobAttemptState};
pub use authorization::{
    MAX_SANDBOX_AUTHORIZATION_NAME_BYTES, MAX_SANDBOX_AUTHORIZATION_PAYLOAD_BYTES,
    MAX_SANDBOX_AUTHORIZATIONS, SANDBOX_AUTHORIZATIONS_SCHEMA_VERSION, SandboxAuthorization,
    SandboxAuthorizationError, SandboxAuthorizationName, SandboxAuthorizations,
};
pub use lease::{Lease, LeaseError, LeaseGuard};
pub use lifecycle::{JobLifecycle, TransitionError};
pub use windows::{
    WINDOWS_HYPERV_BROKER_GRANT_SCHEMA_V4, WINDOWS_HYPERV_SANDBOX_AUTHORIZATION_NAME,
    WindowsHyperVBrokerGrant, WindowsHyperVBrokerGrantClaims, WindowsHyperVBrokerGrantError,
};
