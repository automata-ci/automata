//! Canonical GitHub-native control evidence decoded by the GitHub resolver.

use automata_ci_provider::{
    MAX_PROVIDER_CONTROL_DOCUMENT_BYTES, ProviderControlDocument, ProviderSchemaVersion,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::GithubCheckRunAction;

const SCHEMA: u16 = 1;

/// Exact GitHub Check Run target retained inside a common rerun control.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubCheckRunControl {
    installation_id: u64,
    app_id: u64,
    run_id: u64,
    suite_id: u64,
    external_id: String,
    action: GithubCheckRunAction,
}

impl GithubCheckRunControl {
    /// Constructs bounded positive GitHub Check Run identity.
    ///
    /// # Errors
    ///
    /// Rejects zero, non-durable numeric IDs or an invalid external identity.
    pub fn new(
        installation_id: u64,
        app_id: u64,
        run_id: u64,
        suite_id: u64,
        external_id: impl Into<String>,
        action: GithubCheckRunAction,
    ) -> Result<Self, GithubControlError> {
        let external_id = external_id.into();
        if [installation_id, app_id, run_id, suite_id]
            .into_iter()
            .any(|value| value == 0 || i64::try_from(value).is_err())
            || external_id.is_empty()
            || external_id.len() > 1_024
            || external_id.chars().any(char::is_control)
        {
            return Err(GithubControlError);
        }
        Ok(Self {
            installation_id,
            app_id,
            run_id,
            suite_id,
            external_id,
            action,
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
            } => Self::new(
                wire.installation_id,
                app_id,
                run_id,
                suite_id,
                external_id,
                parse_action(&action)?,
            )?,
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
        let bytes = serde_json::to_vec(&GithubControlDocument {
            schema: SCHEMA,
            installation_id: self.installation_id,
            target: GithubControlTarget::CheckRun {
                app_id: self.app_id,
                run_id: self.run_id,
                suite_id: self.suite_id,
                external_id: self.external_id.clone(),
                action: self.action.as_str().to_owned(),
            },
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

    /// Returns the GitHub App that owns the Check.
    #[must_use]
    pub const fn app_id(&self) -> u64 {
        self.app_id
    }

    /// Returns the exact Check Run identity.
    #[must_use]
    pub const fn run_id(&self) -> u64 {
        self.run_id
    }

    /// Returns the exact parent Check Suite identity.
    #[must_use]
    pub const fn suite_id(&self) -> u64 {
        self.suite_id
    }

    /// Returns Automata's external result-subject identity echoed by GitHub.
    #[must_use]
    pub fn external_id(&self) -> &str {
        &self.external_id
    }

    /// Returns the requested Check Run rerun action.
    #[must_use]
    pub const fn action(&self) -> GithubCheckRunAction {
        self.action
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
    fn current_document_round_trips_canonically() {
        let control = GithubCheckRunControl::new(
            71,
            501,
            601,
            701,
            "automata-result-subject",
            GithubCheckRunAction::Rerequested,
        )
        .expect("control");
        let document = control.document().expect("document");
        assert_eq!(
            GithubCheckRunControl::decode(&document).expect("decode"),
            control
        );
    }

    #[test]
    fn unknown_fields_and_noncanonical_bytes_fail_closed() {
        let schema = ProviderSchemaVersion::new(1).expect("schema");
        for bytes in [
            br#"{"schema":1,"installation_id":71,"target":{"kind":"check_run","app_id":501,"run_id":601,"suite_id":701,"external_id":"subject","action":"rerequested","future":true}}"#.to_vec(),
            br#"{ "schema":1,"installation_id":71,"target":{"kind":"check_run","app_id":501,"run_id":601,"suite_id":701,"external_id":"subject","action":"rerequested"}}"#.to_vec(),
        ] {
            let document = ProviderControlDocument::new(schema, bytes).expect("bounded document");
            assert_eq!(
                GithubCheckRunControl::decode(&document),
                Err(GithubControlError)
            );
        }
    }
}
