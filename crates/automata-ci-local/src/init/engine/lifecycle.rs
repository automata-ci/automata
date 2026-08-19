// Recovery and mutation transaction boundaries remain explicit inside the private lifecycle
// modules; the facade below intentionally exposes only the existing engine-facing surface.
#![allow(
    clippy::large_futures,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

mod cas;
mod common;
mod lock;
mod recovery;
#[cfg(test)]
mod tests;
mod topology;
mod validation;

pub(in crate::init) use lock::{
    LifecycleLockHolder, LifecycleLockObservation, LifecycleMutationFence,
};
pub(in crate::init) use topology::LifecycleTopology;

pub(super) fn lifecycle_lock_name(installation: &crate::Installation) -> String {
    lock::lifecycle_lock_name(installation)
}
