//! Protected result-store adapter for exact broker operation replay.

use std::{fmt, sync::Arc};

use automata_ci_runner_spool::{
    ContentKind, DurableContentPublication, DurableContentRef, DurableContentStore,
    EndpointResultCapacityReservation, RetainedContentError, RetainedContentSource, SpoolError,
    SpoolInvariantError,
};

use super::{
    BrokerResultCapacityReservation, BrokerResultPublication, BrokerResultStore,
    BrokerResultStoreError,
};

/// Broker result store backed by an authenticated, encrypted durable content store.
///
/// The adapter always uses the protected endpoint-result content kind. The
/// supplied store therefore must reserve capacity before host mutation and
/// protect bytes before any filesystem write.
pub struct ProtectedBrokerResultStore {
    content: Arc<dyn DurableContentStore>,
}

impl ProtectedBrokerResultStore {
    /// Wraps an already configured protected durable content store.
    #[must_use]
    pub fn new(content: Arc<dyn DurableContentStore>) -> Self {
        Self { content }
    }
}

impl fmt::Debug for ProtectedBrokerResultStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedBrokerResultStore")
            .field("content", &"configured")
            .finish_non_exhaustive()
    }
}

struct ProtectedResultReservation<'store> {
    inner: Box<dyn EndpointResultCapacityReservation<'store> + 'store>,
}

impl fmt::Debug for ProtectedResultReservation<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedResultReservation")
            .finish_non_exhaustive()
    }
}

struct ProtectedResultPublication<'store> {
    inner: Option<DurableContentPublication<'store>>,
    reference: DurableContentRef,
}

impl fmt::Debug for ProtectedResultPublication<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedResultPublication")
            .field("reference", &self.reference)
            .field("state", &"awaiting-ledger-adoption")
            .finish()
    }
}

impl<'store> BrokerResultCapacityReservation<'store> for ProtectedResultReservation<'store> {
    fn persist(
        self: Box<Self>,
        plaintext: &[u8],
    ) -> Result<Box<dyn BrokerResultPublication + 'store>, BrokerResultStoreError> {
        let publication = self
            .inner
            .persist(plaintext)
            .map_err(|error| classify_spool_error(&error))?;
        let reference = publication.reference().clone();
        Ok(Box::new(ProtectedResultPublication {
            inner: Some(publication),
            reference,
        }))
    }
}

impl BrokerResultPublication for ProtectedResultPublication<'_> {
    fn reference(&self) -> &DurableContentRef {
        &self.reference
    }

    fn adopt(mut self: Box<Self>) {
        let publication = self
            .inner
            .take()
            .expect("a protected result publication is adopted at most once");
        match publication.commit_with(|_| Ok::<(), ()>(())) {
            Ok(()) => {}
            Err(_) => unreachable!("the result-store adoption closure is infallible"),
        }
    }
}

#[derive(Debug)]
struct RetainedResults<'a>(&'a [DurableContentRef]);

impl RetainedContentSource for RetainedResults<'_> {
    fn retained_content(&self) -> Result<Vec<DurableContentRef>, RetainedContentError> {
        Ok(self.0.to_vec())
    }
}

impl BrokerResultStore for ProtectedBrokerResultStore {
    fn reserve(
        &self,
        maximum_plaintext_bytes: u64,
    ) -> Result<Box<dyn BrokerResultCapacityReservation<'_> + '_>, BrokerResultStoreError> {
        let inner = self
            .content
            .reserve_endpoint_result(maximum_plaintext_bytes)
            .map_err(|error| classify_spool_error(&error))?;
        Ok(Box::new(ProtectedResultReservation { inner }))
    }

    fn load(&self, reference: &DurableContentRef) -> Result<Vec<u8>, BrokerResultStoreError> {
        if reference.kind() != ContentKind::EndpointResult {
            return Err(BrokerResultStoreError::Corrupt);
        }
        self.content
            .load(reference)
            .map_err(|error| classify_spool_error(&error))
    }

    fn remove(&self, reference: &DurableContentRef) -> Result<bool, BrokerResultStoreError> {
        if reference.kind() != ContentKind::EndpointResult {
            return Err(BrokerResultStoreError::Corrupt);
        }
        self.content
            .remove(reference)
            .map_err(|error| classify_spool_error(&error))
    }

    fn reconcile(&self, retained: &[DurableContentRef]) -> Result<(), BrokerResultStoreError> {
        if retained
            .iter()
            .any(|reference| reference.kind() != ContentKind::EndpointResult)
        {
            return Err(BrokerResultStoreError::Corrupt);
        }
        self.content
            .reconcile(&RetainedResults(retained))
            .map_err(|error| classify_spool_error(&error))
    }
}

fn classify_spool_error(error: &SpoolError) -> BrokerResultStoreError {
    match error {
        SpoolError::CapacityExhausted
        | SpoolError::Invariant(
            SpoolInvariantError::ObjectTooLarge
            | SpoolInvariantError::InvalidLimits
            | SpoolInvariantError::ProtectionOverheadExceeded,
        ) => BrokerResultStoreError::Capacity,
        SpoolError::ContentMissing
        | SpoolError::PathSecurity
        | SpoolError::Invariant(
            SpoolInvariantError::InvalidContentIdentity
            | SpoolInvariantError::InvalidCacheKey
            | SpoolInvariantError::ContentMismatch
            | SpoolInvariantError::EndpointResultReservationRequired
            | SpoolInvariantError::InvalidProtectionId,
        )
        | SpoolError::Protection(
            automata_ci_runner_spool::ContentProtectionError::AuthenticationFailed,
        ) => BrokerResultStoreError::Corrupt,
        SpoolError::Root(_)
        | SpoolError::Protection(
            automata_ci_runner_spool::ContentProtectionError::KeyUnavailable
            | automata_ci_runner_spool::ContentProtectionError::Failed,
        )
        | SpoolError::AlreadyLocked
        | SpoolError::UnsupportedPlatform
        | SpoolError::PublicationsInFlight
        | SpoolError::ReconciliationInProgress
        | SpoolError::RetainedContent(_)
        | SpoolError::CommitOutcomeUnknown
        | SpoolError::RemovalOutcomeUnknown { .. }
        | SpoolError::ReconciliationOutcomeUnknown
        | SpoolError::Poisoned
        | SpoolError::InjectedFault(_)
        | SpoolError::Io { .. } => BrokerResultStoreError::Unavailable,
    }
}
