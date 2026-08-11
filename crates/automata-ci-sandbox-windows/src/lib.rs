#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Trusted native Windows whole-job sandbox provider.
//!
//! This adapter is intentionally not a VM or filesystem/network sandbox. It
//! exposes explicit host-network and host-filesystem capabilities for trusted
//! workloads while enforcing a race-free Windows Job Object boundary and hard
//! whole-tree resource limits through `processkit`.

#[cfg(windows)]
mod endpoint;
#[cfg(windows)]
mod filesystem;
#[cfg(windows)]
mod path;
#[cfg(windows)]
mod persistence;
#[cfg(windows)]
mod provider;
#[cfg(not(windows))]
mod unsupported;

#[cfg(windows)]
pub use provider::{WindowsSandboxProvider, WindowsSandboxProviderOptions};
#[cfg(not(windows))]
pub use unsupported::{WindowsSandboxProvider, WindowsSandboxProviderOptions};
