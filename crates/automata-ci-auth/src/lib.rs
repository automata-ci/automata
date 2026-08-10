//! Authentication, identity, sessions, and authorization contracts for Automata.
//!
//! The boundaries in this crate intentionally keep human login, machine identity,
//! session issuance, authorization, and provider-token storage independent.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Role-based and resource-scoped authorization policy contracts.
pub mod authorization;
/// GitHub-backed human authentication flows and provider ports.
pub mod github;
/// Numeric GitHub organization/team role-mapping management contracts.
pub mod github_mapping_management;
/// Authenticated human identities and their durable provenance.
pub mod human;
/// First-installation authentication and tenant binding contracts.
pub mod installation;
/// Provider-neutral login transactions and identity assertions.
pub mod login;
/// Machine identity authentication contracts for runners.
pub mod machine;
/// Privileged authentication-management commands and repository ports.
pub mod management;
/// Request-time session authentication snapshots and resolution ports.
pub mod request_auth;
/// Redacted secret, opaque-token, and PKCE primitives.
pub mod secret;
/// Durable browser and CLI session lifecycle contracts.
pub mod session;
/// Domain-separated session-credential derivation and lookup contracts.
pub mod session_credential;
/// Atomic human sign-in finalization contracts.
pub mod sign_in;
/// Injectable clocks and bounded Unix timestamp arithmetic.
pub mod time;
/// Provider-token custody and key-encryption boundaries.
pub mod vault;
