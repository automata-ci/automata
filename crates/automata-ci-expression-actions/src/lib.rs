#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Bounded evaluation of the GitHub Actions expression dialect.
//!
//! Programs are parsed and admitted by the workflow frontend, then evaluated
//! here against runner-owned late contexts. The implementation follows the
//! pinned `actions/runner@v2.336.0` expression semantics while keeping file and
//! provider access behind explicit ports.

mod coercion;
mod context;
mod error;
mod evaluator;
mod functions;
mod value;

pub use context::{
    ExtensionFunctionResult, GithubEvaluationContext, GithubExpressionFunctionProvider,
    GithubStatus, MapContext, MapContextError, NoExtensionFunctions,
};
pub use error::{GithubExpressionEvaluationError, GithubExpressionEvaluationErrorKind};
pub use evaluator::{GithubExpressionEvaluator, GithubExpressionLimits};
pub use value::{GithubObject, GithubSensitiveValue, GithubValue, GithubValueError};
