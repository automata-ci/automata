use std::{collections::BTreeMap, fmt, sync::Arc};

use automata_ci_auth::secret::{SecretString, SharedSensitiveString};
use automata_ci_core::SecretBinding;
use thiserror::Error;

use crate::{PortError, PortErrorKind, SecretPort};

/// Maximum number of exact-version bindings retained for one running job.
pub const MAX_EPHEMERAL_JOB_SECRETS: usize = 256;

/// Maximum aggregate plaintext bytes retained for one running job.
pub const MAX_EPHEMERAL_JOB_SECRET_BYTES: usize = 1_048_576;

/// Validates the projected aggregate plaintext held by one job.
///
/// # Errors
///
/// Rejects a value above [`MAX_EPHEMERAL_JOB_SECRET_BYTES`].
pub const fn validate_ephemeral_job_secret_bytes(
    observed: usize,
) -> Result<(), EphemeralJobSecretsError> {
    if observed > MAX_EPHEMERAL_JOB_SECRET_BYTES {
        return Err(EphemeralJobSecretsError::AggregatePlaintextTooLarge);
    }
    Ok(())
}

/// One exact-version secret value prepared for a single job execution.
///
/// The value is zeroized after the final shared [`SecretString`] owner drops,
/// and neither this entry nor the containing custody object implements `Clone`
/// or serialization.
pub struct EphemeralJobSecret {
    binding_id: String,
    version_id: String,
    value: Arc<SecretString>,
}

impl EphemeralJobSecret {
    /// Binds plaintext to one immutable version selected by the control plane.
    ///
    /// # Errors
    ///
    /// Rejects a binding without an exact version ID.
    pub fn new(
        binding: &SecretBinding,
        value: SecretString,
    ) -> Result<Self, EphemeralJobSecretsError> {
        let version_id = binding
            .version_id()
            .ok_or(EphemeralJobSecretsError::MissingVersion)?
            .to_owned();
        Ok(Self {
            binding_id: binding.binding_id().to_owned(),
            version_id,
            value: Arc::new(value),
        })
    }

    /// Returns the non-secret opaque binding ID.
    #[must_use]
    pub fn binding_id(&self) -> &str {
        &self.binding_id
    }

    /// Returns the non-secret immutable version ID.
    #[must_use]
    pub fn version_id(&self) -> &str {
        &self.version_id
    }

    fn value(&self) -> &Arc<SecretString> {
        &self.value
    }
}

impl fmt::Debug for EphemeralJobSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EphemeralJobSecret")
            .field("binding_id", &self.binding_id())
            .field("version_id", &self.version_id())
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// In-memory, per-job implementation of the executor's secret boundary.
///
/// The private runner delivery path installs values here only after checking
/// the lease-bound overlay. Lookup remains exact by binding ID with no fallback
/// by name, provider, scope, or version.
pub struct EphemeralJobSecrets {
    values: BTreeMap<String, EphemeralJobSecret>,
}

impl EphemeralJobSecrets {
    /// Builds bounded per-job custody from already-authorized secret values.
    ///
    /// # Errors
    ///
    /// Rejects too many entries, duplicate binding IDs, a missing immutable
    /// version, or plaintext exceeding the aggregate per-job bound.
    pub fn new(
        entries: impl IntoIterator<Item = EphemeralJobSecret>,
    ) -> Result<Self, EphemeralJobSecretsError> {
        let mut values = BTreeMap::new();
        let mut aggregate_plaintext_bytes = 0_usize;
        for entry in entries {
            if values.len() == MAX_EPHEMERAL_JOB_SECRETS {
                return Err(EphemeralJobSecretsError::TooManyBindings);
            }
            aggregate_plaintext_bytes = aggregate_plaintext_bytes
                .checked_add(entry.value().expose_secret().len())
                .ok_or(EphemeralJobSecretsError::AggregatePlaintextTooLarge)?;
            validate_ephemeral_job_secret_bytes(aggregate_plaintext_bytes)?;
            let binding_id = entry.binding_id().to_owned();
            if values.insert(binding_id, entry).is_some() {
                return Err(EphemeralJobSecretsError::DuplicateBinding);
            }
        }
        Ok(Self { values })
    }

    /// Returns the number of exact bindings held for this job.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns whether this job has no readable-secret bindings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

impl SecretPort for EphemeralJobSecrets {
    fn resolve(&self, reference: &str) -> Result<SharedSensitiveString, PortError> {
        let entry = self
            .values
            .get(reference)
            .ok_or_else(|| PortError::new(PortErrorKind::NotFound))?;
        Ok(SharedSensitiveString::from_secret(Arc::clone(
            entry.value(),
        )))
    }
}

impl fmt::Debug for EphemeralJobSecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EphemeralJobSecrets")
            .field("binding_count", &self.values.len())
            .field("values", &"[REDACTED]")
            .finish()
    }
}

/// Closed validation failures for per-job secret custody.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EphemeralJobSecretsError {
    /// A binding did not select one immutable secret version.
    #[error("a job secret binding must select an immutable version")]
    MissingVersion,
    /// More than one value claimed the same binding ID.
    #[error("a job contains duplicate secret binding IDs")]
    DuplicateBinding,
    /// The number of bindings exceeded the per-job ceiling.
    #[error("a job contains too many secret bindings")]
    TooManyBindings,
    /// The total readable plaintext exceeded the per-job memory ceiling.
    #[error("a job's aggregate secret plaintext exceeds its bound")]
    AggregatePlaintextTooLarge,
}
