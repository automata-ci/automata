//! Canonical GitHub-native control evidence decoded by the GitHub resolver.

use automata_ci_provider::{
    MAX_PROVIDER_CONTROL_DOCUMENT_BYTES, ProviderControlDocument, ProviderSchemaVersion,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::GithubCheckRunAction;

const SCHEMA: u16 = 2;

/// Exact native GitHub Check target retained inside a common rerun control.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GithubCheckControlTarget {
    /// Rerun one exact Automata-owned Check Run.
    Run {
        /// Exact Check Run identity.
        run_id: u64,
        /// Exact parent Check Suite identity.
        suite_id: u64,
        /// Automata result-subject identity echoed by GitHub.
        external_id: String,
        /// Exact requested Check Run action.
        action: GithubCheckRunAction,
    },
    /// Rerun all eligible Automata Check Runs in one exact Check Suite.
    Suite {
        /// Exact Check Suite identity.
        suite_id: u64,
    },
}

/// Exact GitHub Check rerun target retained inside a common provider control.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubCheckControl {
    installation_id: u64,
    app_id: u64,
    target: GithubCheckControlTarget,
}

impl GithubCheckControl {
    /// Constructs a bounded Check Run rerun target.
    ///
    /// # Errors
    ///
    /// Rejects zero, non-durable numeric IDs, invalid external identity, or a
    /// non-rerun action.
    pub fn check_run(
        installation_id: u64,
        app_id: u64,
        run_id: u64,
        suite_id: u64,
        external_id: impl Into<String>,
        action: GithubCheckRunAction,
    ) -> Result<Self, GithubControlError> {
        let external_id = external_id.into();
        validate_ids([installation_id, app_id, run_id, suite_id])?;
        if external_id.is_empty()
            || external_id.len() > 1_024
            || external_id.chars().any(char::is_control)
        {
            return Err(GithubControlError);
        }
        Ok(Self {
            installation_id,
            app_id,
            target: GithubCheckControlTarget::Run {
                run_id,
                suite_id,
                external_id,
                action,
            },
        })
    }

    /// Constructs a bounded Check Suite rerequest target.
    ///
    /// # Errors
    ///
    /// Rejects zero or non-durable numeric IDs.
    pub fn check_suite(
        installation_id: u64,
        app_id: u64,
        suite_id: u64,
    ) -> Result<Self, GithubControlError> {
        validate_ids([installation_id, app_id, suite_id])?;
        Ok(Self {
            installation_id,
            app_id,
            target: GithubCheckControlTarget::Suite { suite_id },
        })
    }

    /// Decodes only the current exact canonical GitHub control schema.
    ///
    /// # Errors
    ///
    /// Rejects schema drift, unknown fields, noncanonical bytes, or invalid values.
    pub fn decode(document: &ProviderControlDocument) -> Result<Self, GithubControlError> {
        if document.schema().get() != SCHEMA {
            return Err(GithubControlError);
        }
        let wire: GithubControlDocument =
            serde_json::from_slice(document.bytes()).map_err(|_| GithubControlError)?;
        if wire.schema != SCHEMA {
            return Err(GithubControlError);
        }
        let control = match wire.target {
            GithubControlTarget::CheckRun {
                app_id,
                run_id,
                suite_id,
                external_id,
                action,
            } => Self::check_run(
                wire.installation_id,
                app_id,
                run_id,
                suite_id,
                external_id,
                parse_action(&action)?,
            )?,
            GithubControlTarget::CheckSuite { app_id, suite_id } => {
                Self::check_suite(wire.installation_id, app_id, suite_id)?
            }
        };
        if control.document()?.bytes() != document.bytes() {
            return Err(GithubControlError);
        }
        Ok(control)
    }

    /// Encodes the exact canonical adapter document stored by common ingress.
    ///
    /// # Errors
    ///
    /// Fails only if canonical serialization violates the common document bound.
    pub fn document(&self) -> Result<ProviderControlDocument, GithubControlError> {
        let target = match &self.target {
            GithubCheckControlTarget::Run {
                run_id,
                suite_id,
                external_id,
                action,
            } => GithubControlTarget::CheckRun {
                app_id: self.app_id,
                run_id: *run_id,
                suite_id: *suite_id,
                external_id: external_id.clone(),
                action: action.as_str().to_owned(),
            },
            GithubCheckControlTarget::Suite { suite_id } => GithubControlTarget::CheckSuite {
                app_id: self.app_id,
                suite_id: *suite_id,
            },
        };
        let bytes = serde_json::to_vec(&GithubControlDocument {
            schema: SCHEMA,
            installation_id: self.installation_id,
            target,
        })
        .map_err(|_| GithubControlError)?;
        if bytes.len() > MAX_PROVIDER_CONTROL_DOCUMENT_BYTES {
            return Err(GithubControlError);
        }
        ProviderControlDocument::new(
            ProviderSchemaVersion::new(SCHEMA).map_err(|_| GithubControlError)?,
            bytes,
        )
        .map_err(|_| GithubControlError)
    }

    /// Returns the GitHub App installation.
    #[must_use]
    pub const fn installation_id(&self) -> u64 {
        self.installation_id
    }

    /// Returns the GitHub App that owns the Check target.
    #[must_use]
    pub const fn app_id(&self) -> u64 {
        self.app_id
    }

    /// Returns the exact native rerun target.
    #[must_use]
    pub const fn target(&self) -> &GithubCheckControlTarget {
        &self.target
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GithubControlDocument {
    schema: u16,
    installation_id: u64,
    target: GithubControlTarget,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum GithubControlTarget {
    CheckRun {
        app_id: u64,
        run_id: u64,
        suite_id: u64,
        external_id: String,
        action: String,
    },
    CheckSuite {
        app_id: u64,
        suite_id: u64,
    },
}

fn validate_ids<const N: usize>(values: [u64; N]) -> Result<(), GithubControlError> {
    if values
        .into_iter()
        .any(|value| value == 0 || i64::try_from(value).is_err())
    {
        Err(GithubControlError)
    } else {
        Ok(())
    }
}

fn parse_action(value: &str) -> Result<GithubCheckRunAction, GithubControlError> {
    match value {
        "rerequested" => Ok(GithubCheckRunAction::Rerequested),
        "rerun_all" => Ok(GithubCheckRunAction::RerunAll),
        "rerun_failed" => Ok(GithubCheckRunAction::RerunFailed),
        "rerun_job" => Ok(GithubCheckRunAction::RerunJob),
        _ => Err(GithubControlError),
    }
}

/// Invalid or noncanonical GitHub control evidence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub control evidence is invalid")]
pub struct GithubControlError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_run_and_suite_documents_round_trip_canonically() {
        for control in [
            GithubCheckControl::check_run(
                71,
                501,
                601,
                701,
                "automata-result-subject",
                GithubCheckRunAction::Rerequested,
            )
            .expect("run control"),
            GithubCheckControl::check_suite(71, 501, 701).expect("suite control"),
        ] {
            let document = control.document().expect("document");
            assert_eq!(GithubCheckControl::decode(&document), Ok(control));
        }
    }

    #[test]
    fn superseded_unknown_and_noncanonical_documents_fail_closed() {
        for (schema, bytes) in [
            (
                1,
                br#"{"schema":1,"installation_id":71,"target":{"kind":"check_run","app_id":501,"run_id":601,"suite_id":701,"external_id":"subject","action":"rerequested"}}"#.to_vec(),
            ),
            (
                2,
                br#"{"schema":2,"installation_id":71,"target":{"kind":"check_suite","app_id":501,"suite_id":701,"future":true}}"#.to_vec(),
            ),
            (
                2,
                br#"{ "schema":2,"installation_id":71,"target":{"kind":"check_suite","app_id":501,"suite_id":701}}"#.to_vec(),
            ),
        ] {
            let document = ProviderControlDocument::new(
                ProviderSchemaVersion::new(schema).expect("schema"),
                bytes,
            )
            .expect("bounded document");
            assert_eq!(GithubCheckControl::decode(&document), Err(GithubControlError));
        }
    }
}
