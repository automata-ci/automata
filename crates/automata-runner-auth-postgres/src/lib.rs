//! `PostgreSQL` implementation of Automata's durable runner-machine directory.
//!
//! This adapter performs one fresh, exact leaf-digest lookup for every call. It
//! neither caches authority nor parses certificates. The caller must supply the
//! SHA-256 digest of the leaf certificate already validated by
//! `automata-runner-transport`; identity and lifecycle authority come only from
//! the joined server-owned rows.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod directory;

pub use directory::PostgresRunnerMachineDirectory;
