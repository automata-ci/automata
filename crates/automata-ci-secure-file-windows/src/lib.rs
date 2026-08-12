//! Reviewed Windows secure private-file input adapter.

#[cfg(windows)]
mod reader;

#[cfg(windows)]
pub use reader::{SecureFileError, current_user_sid_text, read_owner_private};
