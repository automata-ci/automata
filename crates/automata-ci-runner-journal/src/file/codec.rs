use serde::Deserialize;

use crate::{JournalError, MAX_JOURNAL_BYTES, RUNNER_JOURNAL_SCHEMA_VERSION, model::StoredJournal};

#[derive(Deserialize)]
struct SchemaProbe {
    schema_version: u16,
}

pub(super) fn encode(state: &StoredJournal) -> Result<Vec<u8>, JournalError> {
    state.validate()?;
    let bytes = serde_json::to_vec(state).map_err(|_| JournalError::Corrupt)?;
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(JournalError::Oversized {
            maximum: MAX_JOURNAL_BYTES,
            received: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        });
    }
    Ok(bytes)
}

pub(super) fn decode(bytes: &[u8]) -> Result<StoredJournal, JournalError> {
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(JournalError::Oversized {
            maximum: MAX_JOURNAL_BYTES,
            received: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        });
    }
    let probe: SchemaProbe = serde_json::from_slice(bytes).map_err(|_| JournalError::Corrupt)?;
    if probe.schema_version != RUNNER_JOURNAL_SCHEMA_VERSION {
        return Err(JournalError::UnsupportedSchema {
            supported: RUNNER_JOURNAL_SCHEMA_VERSION,
            received: probe.schema_version,
        });
    }
    let state: StoredJournal = serde_json::from_slice(bytes).map_err(|_| JournalError::Corrupt)?;
    state.validate().map_err(|_| JournalError::Corrupt)?;
    let canonical = serde_json::to_vec(&state).map_err(|_| JournalError::Corrupt)?;
    if canonical != bytes {
        return Err(JournalError::Corrupt);
    }
    Ok(state)
}
