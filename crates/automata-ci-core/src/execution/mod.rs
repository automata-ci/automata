//! Job-attempt lifecycle, leases, and fencing.

mod attempt;
mod lease;
mod lifecycle;
mod windows;

pub use attempt::{AttemptStateError, FenceError, JobAttemptState};
pub use lease::{Lease, LeaseError, LeaseGuard};
pub use lifecycle::{JobLifecycle, TransitionError};
pub use windows::{
    WINDOWS_HYPERV_BROKER_GRANT_SCHEMA_V3, WindowsHyperVBrokerGrant,
    WindowsHyperVBrokerGrantClaims, WindowsHyperVBrokerGrantError,
};
