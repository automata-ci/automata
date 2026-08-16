#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Shared `PostgreSQL` integration-test support for Automata's domain adapters.

#[cfg(all(test, not(feature = "test-support")))]
mod test_support;
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod test_support;
