#[cfg(unix)]
mod unix;

#[cfg(unix)]
pub(super) use unix::PlatformDirectory;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub(super) use windows::PlatformDirectory;

#[cfg(not(any(unix, windows)))]
mod unsupported;

#[cfg(not(any(unix, windows)))]
pub(super) use unsupported::PlatformDirectory;
