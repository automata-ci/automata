use automata_core::{JobIrVersion, RunnerId, RunnerSessionId};
use automata_protocol::{CommandCursor, ProtocolVersion};
use serde::{Deserialize, Serialize};

use crate::{
    CommandTombstone, JournalError, MAX_JOURNAL_BYTES, RUNNER_JOURNAL_SCHEMA_VERSION,
    SessionBinding, SessionSnapshot, SlotSnapshot,
    model::{DiskSchemaVersion, StoredJournal},
};

const LEGACY_RUNNER_JOURNAL_SCHEMA_VERSION: u16 = 3;

#[derive(Deserialize)]
struct SchemaProbe {
    schema_version: u16,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacySessionSnapshotV3 {
    session_id: RunnerSessionId,
    selected_protocol: ProtocolVersion,
    selected_job_ir: JobIrVersion,
    command_cursor: CommandCursor,
    command_tombstones: Vec<CommandTombstone>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyStoredJournalV3 {
    schema_version: DiskSchemaVersion,
    revision: u64,
    runner_id: RunnerId,
    session: Option<LegacySessionSnapshotV3>,
    slots: Vec<SlotSnapshot>,
}

pub(super) struct DecodedJournal {
    pub(super) state: StoredJournal,
    pub(super) migrated: bool,
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

pub(super) fn decode(bytes: &[u8]) -> Result<DecodedJournal, JournalError> {
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(JournalError::Oversized {
            maximum: MAX_JOURNAL_BYTES,
            received: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        });
    }
    let probe: SchemaProbe = serde_json::from_slice(bytes).map_err(|_| JournalError::Corrupt)?;
    match probe.schema_version {
        RUNNER_JOURNAL_SCHEMA_VERSION => decode_current(bytes),
        LEGACY_RUNNER_JOURNAL_SCHEMA_VERSION => decode_v3(bytes),
        received => Err(JournalError::UnsupportedSchema {
            supported: RUNNER_JOURNAL_SCHEMA_VERSION,
            received,
        }),
    }
}

fn decode_current(bytes: &[u8]) -> Result<DecodedJournal, JournalError> {
    let state: StoredJournal = serde_json::from_slice(bytes).map_err(|_| JournalError::Corrupt)?;
    state.validate().map_err(|_| JournalError::Corrupt)?;
    let canonical = serde_json::to_vec(&state).map_err(|_| JournalError::Corrupt)?;
    if canonical != bytes {
        return Err(JournalError::Corrupt);
    }
    Ok(DecodedJournal {
        state,
        migrated: false,
    })
}

fn decode_v3(bytes: &[u8]) -> Result<DecodedJournal, JournalError> {
    let legacy: LegacyStoredJournalV3 =
        serde_json::from_slice(bytes).map_err(|_| JournalError::Corrupt)?;
    if legacy.schema_version.get() != LEGACY_RUNNER_JOURNAL_SCHEMA_VERSION
        || (legacy.session.is_some() && legacy.revision == 0)
    {
        return Err(JournalError::Corrupt);
    }
    let canonical = serde_json::to_vec(&legacy).map_err(|_| JournalError::Corrupt)?;
    if canonical != bytes {
        return Err(JournalError::Corrupt);
    }
    let session = legacy.session.map(|session| {
        SessionSnapshot::migrated_v3(
            SessionBinding::new(
                session.session_id,
                session.selected_protocol,
                session.selected_job_ir,
            ),
            session.command_cursor,
            session.command_tombstones,
        )
    });
    let state =
        StoredJournal::migrated_v3(legacy.revision, legacy.runner_id, session, legacy.slots)
            .map_err(|_| JournalError::Corrupt)?;
    Ok(DecodedJournal {
        state,
        migrated: true,
    })
}
