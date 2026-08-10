//! Product gate for authenticated secret-custody readiness receipts.

use std::{fmt, sync::Arc, time::Duration};

use automata_ci_store::{
    SecretCustodyKeySet, SecretCustodyRepository, VerifiedSecretCustody, VerifySecretCustody,
    VerifySecretCustodyOutcome,
};
use thiserror::Error;

/// Reusable absent-or-configured verifier shared by readiness and every write path.
pub(crate) struct SecretCustodyVerifier {
    repository: Arc<dyn SecretCustodyRepository>,
    configured_keys: Option<SecretCustodyKeySet>,
    #[cfg(test)]
    test_verified: bool,
}

impl SecretCustodyVerifier {
    pub(crate) const fn new(
        repository: Arc<dyn SecretCustodyRepository>,
        configured_keys: Option<SecretCustodyKeySet>,
    ) -> Self {
        Self {
            repository,
            configured_keys,
            #[cfg(test)]
            test_verified: false,
        }
    }

    /// Refreshes and consumes one adapter-issued receipt for the exact mode.
    pub(crate) async fn verify(&self) -> Result<(), SecretCustodyVerificationError> {
        #[cfg(test)]
        if self.test_verified {
            return Ok(());
        }

        let request = self
            .configured_keys
            .as_ref()
            .map_or_else(VerifySecretCustody::absent, |keys| {
                VerifySecretCustody::configured(keys.clone())
            });
        let outcome = self
            .repository
            .verify_or_create_secret_custody(request)
            .await
            .map_err(|_| SecretCustodyVerificationError)?;
        match (&self.configured_keys, outcome) {
            (None, VerifySecretCustodyOutcome::NotRequired) => Ok(()),
            (Some(expected), VerifySecretCustodyOutcome::Verified(receipt)) => {
                consume_configured_receipt(expected, receipt)
            }
            (None, VerifySecretCustodyOutcome::Verified(_))
            | (Some(_), VerifySecretCustodyOutcome::NotRequired) => {
                Err(SecretCustodyVerificationError)
            }
        }
    }

    /// Refreshes one exact receipt without allowing durable custody work to stall startup.
    pub(crate) async fn verify_within(
        &self,
        maximum_wait: Duration,
    ) -> Result<(), SecretCustodyVerificationError> {
        if maximum_wait.is_zero() {
            return Err(SecretCustodyVerificationError);
        }
        tokio::time::timeout(maximum_wait, self.verify())
            .await
            .map_err(|_| SecretCustodyVerificationError)?
    }

    #[cfg(test)]
    pub(crate) fn verified_for_tests() -> Arc<Self> {
        Arc::new(Self {
            repository: Arc::new(UnavailableTestRepository),
            configured_keys: None,
            test_verified: true,
        })
    }

    #[cfg(test)]
    pub(crate) fn unavailable_for_tests() -> Arc<Self> {
        Arc::new(Self {
            repository: Arc::new(UnavailableTestRepository),
            configured_keys: None,
            test_verified: false,
        })
    }

    #[cfg(test)]
    pub(crate) fn available_then_unavailable_for_tests(
        successful_verifications: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            repository: Arc::new(AvailableThenUnavailableTestRepository {
                remaining_successes: std::sync::Mutex::new(successful_verifications),
            }),
            configured_keys: None,
            test_verified: false,
        })
    }
}

fn consume_configured_receipt(
    expected: &SecretCustodyKeySet,
    receipt: VerifiedSecretCustody,
) -> Result<(), SecretCustodyVerificationError> {
    if receipt.active_key_id() != expected.active_key_id()
        || receipt.configured_key_set_digest() != expected.digest()
    {
        return Err(SecretCustodyVerificationError);
    }
    // Moving the non-constructible receipt through this function is the
    // product's explicit consumption boundary. Its requirements digest and
    // canary generations were authenticated by the durable adapter.
    drop(receipt);
    Ok(())
}

impl fmt::Debug for SecretCustodyVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretCustodyVerifier")
            .field("configured", &self.configured_keys.is_some())
            .field("key_identities", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Sanitized custody-gate failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("secret custody verification failed")]
pub(crate) struct SecretCustodyVerificationError;

#[cfg(test)]
#[derive(Debug)]
struct UnavailableTestRepository;

#[cfg(test)]
#[async_trait::async_trait]
impl SecretCustodyRepository for UnavailableTestRepository {
    async fn inspect_secret_custody_requirements(
        &self,
    ) -> Result<
        automata_ci_store::SecretCustodyRequirements,
        automata_ci_store::SecretCustodyRepositoryError,
    > {
        Err(automata_ci_store::SecretCustodyRepositoryError::Unavailable)
    }

    async fn verify_or_create_secret_custody(
        &self,
        _request: VerifySecretCustody,
    ) -> Result<VerifySecretCustodyOutcome, automata_ci_store::SecretCustodyRepositoryError> {
        Err(automata_ci_store::SecretCustodyRepositoryError::Unavailable)
    }
}

#[cfg(test)]
#[derive(Debug)]
struct NotRequiredTestRepository;

#[cfg(test)]
#[async_trait::async_trait]
impl SecretCustodyRepository for NotRequiredTestRepository {
    async fn inspect_secret_custody_requirements(
        &self,
    ) -> Result<
        automata_ci_store::SecretCustodyRequirements,
        automata_ci_store::SecretCustodyRepositoryError,
    > {
        Err(automata_ci_store::SecretCustodyRepositoryError::Unavailable)
    }

    async fn verify_or_create_secret_custody(
        &self,
        _request: VerifySecretCustody,
    ) -> Result<VerifySecretCustodyOutcome, automata_ci_store::SecretCustodyRepositoryError> {
        Ok(VerifySecretCustodyOutcome::NotRequired)
    }
}

#[cfg(test)]
#[derive(Debug)]
struct AvailableThenUnavailableTestRepository {
    remaining_successes: std::sync::Mutex<usize>,
}

#[cfg(test)]
#[async_trait::async_trait]
impl SecretCustodyRepository for AvailableThenUnavailableTestRepository {
    async fn inspect_secret_custody_requirements(
        &self,
    ) -> Result<
        automata_ci_store::SecretCustodyRequirements,
        automata_ci_store::SecretCustodyRepositoryError,
    > {
        Err(automata_ci_store::SecretCustodyRepositoryError::Unavailable)
    }

    async fn verify_or_create_secret_custody(
        &self,
        _request: VerifySecretCustody,
    ) -> Result<VerifySecretCustodyOutcome, automata_ci_store::SecretCustodyRepositoryError> {
        let mut remaining = self
            .remaining_successes
            .lock()
            .expect("custody verification sequence lock");
        if *remaining == 0 {
            return Err(automata_ci_store::SecretCustodyRepositoryError::Unavailable);
        }
        *remaining -= 1;
        Ok(VerifySecretCustodyOutcome::NotRequired)
    }
}

#[cfg(test)]
#[derive(Debug)]
struct PendingTestRepository;

#[cfg(test)]
#[async_trait::async_trait]
impl SecretCustodyRepository for PendingTestRepository {
    async fn inspect_secret_custody_requirements(
        &self,
    ) -> Result<
        automata_ci_store::SecretCustodyRequirements,
        automata_ci_store::SecretCustodyRepositoryError,
    > {
        Err(automata_ci_store::SecretCustodyRepositoryError::Unavailable)
    }

    async fn verify_or_create_secret_custody(
        &self,
        _request: VerifySecretCustody,
    ) -> Result<VerifySecretCustodyOutcome, automata_ci_store::SecretCustodyRepositoryError> {
        std::future::pending().await
    }
}

#[cfg(test)]
mod tests {
    use automata_ci_key_management::KeyId;

    use super::*;

    #[tokio::test]
    async fn absent_mode_accepts_only_the_adapter_not_required_outcome() {
        let repository: Arc<dyn SecretCustodyRepository> = Arc::new(NotRequiredTestRepository);
        let absent = SecretCustodyVerifier::new(Arc::clone(&repository), None);
        assert_eq!(absent.verify().await, Ok(()));

        let keys =
            SecretCustodyKeySet::new(KeyId::new("secret-key-v1").expect("key ID"), Vec::new())
                .expect("key set");
        let configured = SecretCustodyVerifier::new(repository, Some(keys));
        assert_eq!(
            configured.verify().await,
            Err(SecretCustodyVerificationError)
        );
    }

    #[tokio::test]
    async fn repository_failures_and_debug_are_sanitized() {
        let verifier = SecretCustodyVerifier::unavailable_for_tests();
        assert_eq!(verifier.verify().await, Err(SecretCustodyVerificationError));
        let debug = format!("{verifier:?}");
        assert!(debug.contains("key_identities: \"[REDACTED]\""));
        assert!(!debug.contains("secret-key-v1"));
    }

    #[tokio::test]
    async fn bounded_verification_times_out_a_pending_custody_writer() {
        let verifier = SecretCustodyVerifier::new(Arc::new(PendingTestRepository), None);
        assert_eq!(
            verifier.verify_within(Duration::from_millis(1)).await,
            Err(SecretCustodyVerificationError)
        );
        assert_eq!(
            verifier.verify_within(Duration::ZERO).await,
            Err(SecretCustodyVerificationError)
        );
    }
}
