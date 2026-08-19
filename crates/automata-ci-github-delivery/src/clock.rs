//! Clock contract for GitHub Checks publication.

use automata_ci_core::UnixMillis;

/// Trusted wall clock for GitHub Checks publication.
pub trait GithubDeliveryClock: std::fmt::Debug + Send + Sync {
    /// Returns the trusted current Unix time in milliseconds.
    fn now(&self) -> UnixMillis;
}
