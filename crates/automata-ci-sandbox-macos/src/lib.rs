#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Disposable Virtualization.framework macOS whole-job sandbox provider.
//!
//! Every job cold-boots an APFS-cloned, digest-attested macOS template without
//! a virtual NIC or host directory share. A signed Swift helper owns the VM;
//! runner pipe loss destructively stops it. Job commands and bounded copies
//! cross only the Virtio socket guest protocol.

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
mod template;
#[cfg(not(target_os = "macos"))]
mod unsupported;
#[cfg(target_os = "macos")]
mod vm;

#[cfg(target_os = "macos")]
pub use provider::{MacosVirtualizationProvider, MacosVirtualizationProviderOptions};
#[cfg(not(target_os = "macos"))]
pub use unsupported::{MacosVirtualizationProvider, MacosVirtualizationProviderOptions};
