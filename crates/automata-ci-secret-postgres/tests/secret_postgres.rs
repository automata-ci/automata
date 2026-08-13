//! `PostgreSQL` built-in secret-provider adapter tests.

mod support;

#[path = "postgres_provider.rs"]
mod postgres_provider;
#[path = "postgres_provider_replay.rs"]
mod postgres_provider_replay;
