use std::collections::HashSet;

use crate::{ContentCommitFaultInjector, DurableContentRef, SpoolError, SpoolLimits, SpoolRoot};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SpoolUsage {
    pub(crate) objects: u32,
    pub(crate) protected_bytes: u64,
}

#[derive(Debug)]
pub(crate) struct PlatformDirectory;

#[derive(Debug)]
pub(crate) struct CommitFailure {
    error: SpoolError,
}

impl CommitFailure {
    pub(crate) const fn renamed(&self) -> bool {
        false
    }

    pub(crate) fn into_public(self) -> SpoolError {
        self.error
    }
}

impl PlatformDirectory {
    pub(crate) fn open(_root: &SpoolRoot) -> Result<Self, SpoolError> {
        Err(SpoolError::UnsupportedPlatform)
    }

    pub(crate) fn cleanup_staging(&self) -> Result<(), SpoolError> {
        unreachable!()
    }

    pub(crate) fn scan_usage(&self, _limits: SpoolLimits) -> Result<SpoolUsage, SpoolError> {
        unreachable!()
    }

    pub(crate) fn prune_except(
        &self,
        _retained: &HashSet<Vec<u8>>,
        _limits: SpoolLimits,
    ) -> Result<SpoolUsage, CommitFailure> {
        unreachable!()
    }

    pub(crate) fn read(
        &self,
        _reference: &DurableContentRef,
        _maximum: u64,
    ) -> Result<Option<Vec<u8>>, SpoolError> {
        unreachable!()
    }

    pub(crate) fn remove(&self, _reference: &DurableContentRef) -> Result<bool, CommitFailure> {
        unreachable!()
    }

    pub(crate) fn commit(
        &self,
        _reference: &DurableContentRef,
        _bytes: &[u8],
        _faults: &dyn ContentCommitFaultInjector,
    ) -> Result<(), CommitFailure> {
        unreachable!()
    }
}
