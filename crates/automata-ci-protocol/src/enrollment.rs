//! HTTP contract shared by runner enrollment clients and the control plane.

use serde::{Deserialize, Serialize};

/// Exact control-plane path for creating one runner enrollment token.
pub const RUNNER_ENROLLMENTS_PATH: &str = "/api/v1/runner-enrollments";

/// Exact control-plane path for initial runner enrollment redemption.
pub const RUNNER_ENROLLMENT_REDEEM_PATH: &str = "/api/v1/runner-enrollments/redeem";

/// Exact control-plane path for expired-certificate runner recovery.
pub const RUNNER_ENROLLMENT_RECOVER_PATH: &str = "/api/v1/runner-enrollments/recover";

/// Exact predecessor certificate claimed by an expired-custody recovery request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerEnrollmentRecoveryPredecessor {
    /// SHA-256 digest of the locally held predecessor leaf certificate.
    pub certificate_leaf_sha256: [u8; 32],
    /// Exact X.509 expiry of that predecessor, in Unix seconds.
    pub certificate_expires_at_seconds: i64,
}
