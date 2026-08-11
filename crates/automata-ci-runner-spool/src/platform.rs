#[cfg(unix)]
mod unix;

#[cfg(unix)]
pub(crate) use unix::{PlatformDirectory, SpoolUsage};

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub(crate) use windows::{PlatformDirectory, SpoolUsage};

#[cfg(not(any(unix, windows)))]
mod unsupported;

#[cfg(not(any(unix, windows)))]
pub(crate) use unsupported::{PlatformDirectory, SpoolUsage};
