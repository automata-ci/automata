#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Scheduling, lease orchestration, and authenticated runner control for Automata.

pub mod github_oidc;
pub mod lease;
pub mod runner_auth;
pub mod runner_control;
pub mod scheduling;
