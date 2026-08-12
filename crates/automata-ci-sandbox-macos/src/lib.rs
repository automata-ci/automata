#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Trusted native macOS whole-job sandbox provider.
//!
//! This adapter is a process-lifetime boundary for trusted jobs, not a VM or
//! hostile-workload sandbox. Commands inherit the dedicated runner account,
//! host network, host filesystem, and shared host resources. A same-binary
//! supervisor owns each POSIX process group and observes a private control
//! channel so runner loss terminates the job process tree.

#[cfg(target_os = "macos")]
mod endpoint;
#[cfg(target_os = "macos")]
mod filesystem;
#[cfg(target_os = "macos")]
mod path;
#[cfg(target_os = "macos")]
mod persistence;
#[cfg(target_os = "macos")]
mod provider;
#[cfg(target_os = "macos")]
mod supervisor;
#[cfg(not(target_os = "macos"))]
mod unsupported;

#[cfg(target_os = "macos")]
pub use provider::{MacosSandboxProvider, MacosSandboxProviderOptions};
#[cfg(target_os = "macos")]
pub use supervisor::run_supervisor;
#[cfg(not(target_os = "macos"))]
pub use unsupported::{MacosSandboxProvider, MacosSandboxProviderOptions, run_supervisor};

/// Hidden command name used for the same-binary command supervisor.
pub const SUPERVISOR_COMMAND: &str = "__macos-job-supervisor";
