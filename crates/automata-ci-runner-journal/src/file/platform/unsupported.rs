use crate::{CommitFaultInjector, JournalError, StateRoot};

#[derive(Debug)]
pub(crate) struct PlatformDirectory;

#[derive(Debug)]
pub(crate) struct CommitFailure {
    error: JournalError,
}

impl CommitFailure {
    pub(crate) const fn renamed(&self) -> bool {
        false
    }

    pub(crate) fn into_public(self) -> JournalError {
        self.error
    }
}

impl PlatformDirectory {
    pub(crate) fn open(_root: &StateRoot) -> Result<Self, JournalError> {
        Err(JournalError::UnsupportedPlatform)
    }

    pub(crate) fn cleanup_staging(&self) -> Result<(), JournalError> {
        unreachable!()
    }

    pub(crate) fn read_state(&self) -> Result<Option<Vec<u8>>, JournalError> {
        unreachable!()
    }

    pub(crate) fn commit(
        &self,
        _revision: u64,
        _bytes: &[u8],
        _faults: &dyn CommitFaultInjector,
    ) -> Result<(), CommitFailure> {
        unreachable!()
    }
}
