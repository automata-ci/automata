#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Pure policy and contracts for privileged Windows broker admission.
//!
//! This crate has no filesystem, service-state, custody, or host-compute
//! implementation. Those adapters belong to `automata-ci-windows-broker`.

pub mod admission;
pub mod host_input;
pub mod request;
