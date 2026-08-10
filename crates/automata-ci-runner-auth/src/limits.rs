use thiserror::Error;

const DEFAULT_CHAIN_CERTIFICATES: usize = 8;
const DEFAULT_CERTIFICATE_BYTES: usize = 64 * 1_024;
const DEFAULT_CHAIN_BYTES: usize = 256 * 1_024;
const HARD_MAX_CHAIN_CERTIFICATES: usize = 32;
const HARD_MAX_CERTIFICATE_BYTES: usize = 1_024 * 1_024;
const HARD_MAX_CHAIN_BYTES: usize = 4 * 1_024 * 1_024;

/// Resource ceilings applied before hashing or durable lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunnerMachineAuthLimits {
    chain_certificates: usize,
    certificate_bytes: usize,
    chain_bytes: usize,
}

impl RunnerMachineAuthLimits {
    /// Creates bounded, internally consistent certificate evidence limits.
    ///
    /// # Errors
    ///
    /// Rejects zero values, a per-certificate limit larger than the total, and
    /// limits above the crate hard ceilings.
    pub const fn new(
        maximum_chain_certificates: usize,
        maximum_certificate_bytes: usize,
        maximum_chain_bytes: usize,
    ) -> Result<Self, RunnerMachineAuthLimitsError> {
        if maximum_chain_certificates == 0
            || maximum_chain_certificates > HARD_MAX_CHAIN_CERTIFICATES
            || maximum_certificate_bytes == 0
            || maximum_certificate_bytes > HARD_MAX_CERTIFICATE_BYTES
            || maximum_chain_bytes == 0
            || maximum_chain_bytes > HARD_MAX_CHAIN_BYTES
            || maximum_certificate_bytes > maximum_chain_bytes
        {
            return Err(RunnerMachineAuthLimitsError);
        }
        Ok(Self {
            chain_certificates: maximum_chain_certificates,
            certificate_bytes: maximum_certificate_bytes,
            chain_bytes: maximum_chain_bytes,
        })
    }

    /// Returns the inclusive chain entry ceiling.
    #[must_use]
    pub const fn maximum_chain_certificates(self) -> usize {
        self.chain_certificates
    }

    /// Returns the inclusive DER byte ceiling for one certificate.
    #[must_use]
    pub const fn maximum_certificate_bytes(self) -> usize {
        self.certificate_bytes
    }

    /// Returns the inclusive aggregate DER byte ceiling.
    #[must_use]
    pub const fn maximum_chain_bytes(self) -> usize {
        self.chain_bytes
    }
}

impl Default for RunnerMachineAuthLimits {
    fn default() -> Self {
        Self {
            chain_certificates: DEFAULT_CHAIN_CERTIFICATES,
            certificate_bytes: DEFAULT_CERTIFICATE_BYTES,
            chain_bytes: DEFAULT_CHAIN_BYTES,
        }
    }
}

/// Invalid runner machine authentication resource ceilings.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("runner machine authentication limits are invalid")]
pub struct RunnerMachineAuthLimitsError;
