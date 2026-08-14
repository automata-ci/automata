//! Encrypted built-in `PostgreSQL` secret provider for Automata.
//!
//! Plaintext is envelope-encrypted before any SQL statement is executed. The
//! durable envelope is bound to the exact tenant and immutable secret-version
//! UUID, and `PostgreSQL` receives no plaintext value or generic provider handle.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod provider;
mod storage;
mod support;

pub use provider::{
    BUILTIN_POSTGRES_PROVIDER_ID, BUILTIN_SECRET_VALUE_KEY_PURPOSE, PostgresSecretProvider,
};
