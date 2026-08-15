#[cfg(unix)]
mod unix;

#[cfg(unix)]
pub(crate) use unix::PlatformDirectory;

#[cfg(not(unix))]
mod unsupported;

#[cfg(not(unix))]
pub(crate) use unsupported::PlatformDirectory;
