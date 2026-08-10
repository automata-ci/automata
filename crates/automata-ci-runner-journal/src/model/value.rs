use serde::{Deserialize, Serialize};

/// Versioned disk envelope field with a deliberately private constructor.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub(crate) struct DiskSchemaVersion(u16);

impl DiskSchemaVersion {
    pub(crate) const CURRENT: Self = Self(crate::RUNNER_JOURNAL_SCHEMA_VERSION);

    pub(crate) const fn get(self) -> u16 {
        self.0
    }
}
