use automata_runner_spool::{DurableContentRef, RetainedContentError, RetainedContentSource};

use crate::RunnerJournal;

/// Reconciliation adapter that snapshots one journal after publication fencing.
#[derive(Clone, Copy)]
pub struct JournalContentRetainSet<'a> {
    journal: &'a dyn RunnerJournal,
}

impl<'a> JournalContentRetainSet<'a> {
    #[must_use]
    pub const fn new(journal: &'a dyn RunnerJournal) -> Self {
        Self { journal }
    }
}

impl std::fmt::Debug for JournalContentRetainSet<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JournalContentRetainSet")
            .field("journal", &"configured")
            .finish()
    }
}

impl RetainedContentSource for JournalContentRetainSet<'_> {
    fn retained_content(&self) -> Result<Vec<DurableContentRef>, RetainedContentError> {
        let snapshot = self
            .journal
            .snapshot()
            .map_err(|_| RetainedContentError::Unavailable)?;
        Ok(snapshot.content_references().cloned().collect())
    }
}
