#[cfg(unix)]
mod unix;

#[cfg(unix)]
pub(super) use unix::PlatformDirectory;

#[cfg(not(unix))]
mod unsupported;

#[cfg(not(unix))]
pub(super) use unsupported::PlatformDirectory;
