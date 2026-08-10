use automata_ci_core::UnixMillis;

/// Why a durable runner command or RPC response envelope was erased.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RunnerPayloadTombstoneReason {
    /// The runner cumulatively acknowledged delivery of the command.
    Acknowledged,
    /// The owning session closed without being replaced by a newer session.
    SessionClosed,
    /// A newer runner session superseded the owning session.
    SessionSuperseded,
}

impl RunnerPayloadTombstoneReason {
    /// Returns the closed durable representation used by the `PostgreSQL` schema.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Acknowledged => "acknowledged",
            Self::SessionClosed => "session_closed",
            Self::SessionSuperseded => "session_superseded",
        }
    }

    pub(crate) fn from_durable(value: &str) -> Option<Self> {
        match value {
            "acknowledged" => Some(Self::Acknowledged),
            "session_closed" => Some(Self::SessionClosed),
            "session_superseded" => Some(Self::SessionSuperseded),
            _ => None,
        }
    }
}

/// Durable evidence that an encrypted runner payload is intentionally gone.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RunnerPayloadTombstone {
    reason: RunnerPayloadTombstoneReason,
    tombstoned_at: UnixMillis,
}

impl RunnerPayloadTombstone {
    #[must_use]
    pub const fn new(reason: RunnerPayloadTombstoneReason, tombstoned_at: UnixMillis) -> Self {
        Self {
            reason,
            tombstoned_at,
        }
    }

    #[must_use]
    pub const fn reason(self) -> RunnerPayloadTombstoneReason {
        self.reason
    }

    #[must_use]
    pub const fn tombstoned_at(self) -> UnixMillis {
        self.tombstoned_at
    }
}
