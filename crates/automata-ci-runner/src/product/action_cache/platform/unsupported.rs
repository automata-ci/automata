use automata_ci_action::{ActionReferenceIndexError, ActionReferenceIndexErrorKind};

use super::super::ActionReferenceIndexRoot;

pub(crate) struct PlatformDirectory;

impl PlatformDirectory {
    pub(crate) fn open(
        _root: &ActionReferenceIndexRoot,
    ) -> Result<Self, ActionReferenceIndexError> {
        Err(unsupported())
    }

    pub(crate) fn cleanup_staging(&self) -> Result<(), ActionReferenceIndexError> {
        Err(unsupported())
    }

    pub(crate) fn read_index(
        &self,
        _maximum_bytes: usize,
    ) -> Result<Option<Vec<u8>>, ActionReferenceIndexError> {
        Err(unsupported())
    }

    pub(crate) fn commit(&self, _generation: u64, _bytes: &[u8]) -> Result<(), CommitFailure> {
        Err(CommitFailure)
    }
}

pub(crate) struct CommitFailure;

impl CommitFailure {
    pub(crate) const fn renamed(&self) -> bool {
        false
    }
}

const fn unsupported() -> ActionReferenceIndexError {
    ActionReferenceIndexError::new(ActionReferenceIndexErrorKind::Unsupported)
}
