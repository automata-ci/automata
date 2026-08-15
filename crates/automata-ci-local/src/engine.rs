//! Exact-endpoint Docker Engine adapters for local installation resources.

use std::{collections::BTreeMap, fmt, sync::Arc};

use async_trait::async_trait;
use thiserror::Error;

use crate::{
    ApiVersion, DoctorReport, EngineSelection, Installation, InstallationId, InstallationName,
    capped_adapter_api, normalize_architecture,
};

mod http_engine;
mod transport;

use http_engine::HttpEngine;

const MANAGED_LABEL_PREFIX: &str = "io.automata.local.";
const LABEL_MANAGED: &str = "io.automata.local.managed";
const LABEL_IDENTITY_SCHEMA: &str = "io.automata.local.identity-schema";
const LABEL_INSTALLATION_ID: &str = "io.automata.local.installation-id";
const LABEL_INSTALLATION_KEY: &str = "io.automata.local.installation-key";
const LABEL_COMPOSE_PROJECT: &str = "io.automata.local.compose-project";
const LABEL_RESOURCE_KIND: &str = "io.automata.local.resource-kind";
const MANAGED_VALUE: &str = "true";
const IDENTITY_SCHEMA: &str = "1";
const IDENTITY_ANCHOR_KIND: &str = "identity-anchor";

/// Stable reason for a local Docker Engine adapter failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalEngineErrorCode {
    /// The supplied doctor report did not pass every mandatory preflight gate.
    PreflightRequired,
    /// An Engine API request failed or timed out.
    EngineRequestFailed,
    /// The endpoint no longer identifies the engine selected by preflight.
    EngineIdentityChanged,
    /// Docker returned an incomplete or internally inconsistent response.
    InvalidEngineResponse,
    /// The deterministic anchor name is occupied by a foreign resource.
    IdentityCollision,
    /// An owned-looking anchor does not satisfy the immutable contract.
    InvalidIdentityAnchor,
    /// A container is attached to the identity anchor.
    IdentityAnchorAttached,
    /// A mutating request may have succeeded but its final state is indeterminate.
    MutationOutcomeUncertain,
}

impl LocalEngineErrorCode {
    const fn message(self) -> &'static str {
        match self {
            Self::PreflightRequired => {
                "local Docker preflight must be ready before engine mutation"
            }
            Self::EngineRequestFailed => "the Docker Engine request failed",
            Self::EngineIdentityChanged => {
                "the Docker Engine identity changed after preflight; run local doctor again"
            }
            Self::InvalidEngineResponse => {
                "the Docker Engine returned an incomplete or inconsistent response"
            }
            Self::IdentityCollision => {
                "the deterministic installation anchor name is occupied by a foreign resource"
            }
            Self::InvalidIdentityAnchor => {
                "the installation anchor does not satisfy its immutable ownership contract"
            }
            Self::IdentityAnchorAttached => {
                "the installation identity anchor is unexpectedly attached to a container"
            }
            Self::MutationOutcomeUncertain => {
                "the Docker mutation outcome is uncertain; inspect the installation before retrying"
            }
        }
    }
}

/// Redacted failure returned by the local Docker Engine adapter.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("{message}")]
pub struct LocalEngineError {
    code: LocalEngineErrorCode,
    message: &'static str,
}

impl LocalEngineError {
    const fn new(code: LocalEngineErrorCode) -> Self {
        Self {
            code,
            message: code.message(),
        }
    }

    /// Returns the stable machine-readable reason.
    pub const fn code(self) -> LocalEngineErrorCode {
        self.code
    }

    /// Returns a non-sensitive operator-facing explanation.
    pub const fn message(self) -> &'static str {
        self.message
    }
}

/// Docker Engine adapter restricted to local-installation identity operations.
///
/// It deliberately exposes no generic volume mutation, deletion, pruning,
/// image pulling, container lifecycle, or Compose API.
pub struct DockerInstallationAdapter {
    engine: Arc<dyn EngineApi>,
    selection: EngineSelection,
}

impl fmt::Debug for DockerInstallationAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DockerInstallationAdapter")
            .field("selection", &self.selection)
            .finish_non_exhaustive()
    }
}

impl DockerInstallationAdapter {
    /// Connects only to the exact local endpoint retained by a successful
    /// [`crate::inspect`] result and verifies that the daemon identity still
    /// agrees with preflight.
    ///
    /// # Errors
    ///
    /// Returns [`LocalEngineError`] when the first bounded request to the exact
    /// endpoint fails or it no longer reports the selected engine facts.
    pub async fn connect(report: &DoctorReport) -> Result<Self, LocalEngineError> {
        if !report.ready() {
            return Err(LocalEngineError::new(
                LocalEngineErrorCode::PreflightRequired,
            ));
        }
        let selection = report
            .selected_engine()
            .cloned()
            .ok_or_else(|| LocalEngineError::new(LocalEngineErrorCode::PreflightRequired))?;
        let api = adapter_api_version(selection.api_version())?;
        let engine = Arc::new(HttpEngine::connect(selection.connection(), api).map_err(
            |_error| LocalEngineError::new(LocalEngineErrorCode::InvalidEngineResponse),
        )?);
        let adapter = Self { engine, selection };
        adapter.verify_engine().await?;
        Ok(adapter)
    }

    /// Inspects and verifies the deterministic identity anchor without
    /// creating or changing any engine resource.
    ///
    /// # Errors
    ///
    /// Returns [`LocalEngineError`] for engine drift, failed requests, foreign
    /// collisions, malformed ownership labels, unsafe volume configuration, or
    /// any container attachment.
    pub async fn inspect_identity(
        &self,
        name: &InstallationName,
    ) -> Result<Option<Installation>, LocalEngineError> {
        self.verify_engine().await?;
        let installation = self.inspect_verified_identity(name).await?;
        self.verify_engine().await?;
        Ok(installation)
    }

    /// Creates an absent identity anchor or adopts an exact matching anchor.
    ///
    /// Docker's volume-create response is never trusted. The deterministic name
    /// is freshly inspected after the request, including when the request
    /// reports a transport failure or loses a concurrent create race.
    ///
    /// # Errors
    ///
    /// Returns [`LocalEngineError`] when engine identity changes, a foreign
    /// collision is found, the resulting anchor is unsafe, or a mutation's
    /// final outcome cannot be proven. This method never attempts rollback.
    pub async fn create_or_adopt_identity(
        &self,
        name: &InstallationName,
    ) -> Result<Installation, LocalEngineError> {
        self.verify_engine().await?;
        if let Some(installation) = self.inspect_verified_identity(name).await? {
            self.verify_engine().await?;
            return Ok(installation);
        }

        let requested = Installation::verified(name.clone(), InstallationId::new());
        let _create_outcome = self
            .engine
            .create_volume(CreateVolume {
                name: requested.anchor_volume_name().to_owned(),
                labels: identity_labels(&requested),
            })
            .await;

        let inspected = self.inspect_verified_identity(name).await;
        let Ok(Some(installation)) = inspected else {
            return Err(LocalEngineError::new(
                LocalEngineErrorCode::MutationOutcomeUncertain,
            ));
        };
        if self.verify_engine().await.is_err() {
            return Err(LocalEngineError::new(
                LocalEngineErrorCode::MutationOutcomeUncertain,
            ));
        }
        Ok(installation)
    }

    async fn verify_engine(&self) -> Result<(), LocalEngineError> {
        let facts = self.engine.engine_facts().await.map_err(map_engine_call)?;
        let expected_api = adapter_api_version(self.selection.api_version())?;
        let minimum_api = ApiVersion::parse(&facts.minimum_api_version)
            .ok_or_else(|| LocalEngineError::new(LocalEngineErrorCode::InvalidEngineResponse))?;
        let maximum_api = ApiVersion::parse(&facts.maximum_api_version)
            .ok_or_else(|| LocalEngineError::new(LocalEngineErrorCode::InvalidEngineResponse))?;
        let architecture = normalize_architecture(&facts.architecture)
            .ok_or_else(|| LocalEngineError::new(LocalEngineErrorCode::InvalidEngineResponse))?;
        if facts.engine_id != self.selection.engine_id()
            || facts.server_version != self.selection.server_version()
            || facts.operating_system != "linux"
            || architecture != self.selection.architecture()
            || minimum_api > expected_api
            || maximum_api < expected_api
        {
            return Err(LocalEngineError::new(
                LocalEngineErrorCode::EngineIdentityChanged,
            ));
        }
        Ok(())
    }

    async fn inspect_verified_identity(
        &self,
        name: &InstallationName,
    ) -> Result<Option<Installation>, LocalEngineError> {
        inspect_verified_identity(self.engine.as_ref(), name).await
    }

    #[cfg(test)]
    fn with_test_engine(selection: EngineSelection, engine: Arc<dyn EngineApi>) -> Self {
        Self { engine, selection }
    }
}

async fn inspect_verified_identity(
    engine: &dyn EngineApi,
    name: &InstallationName,
) -> Result<Option<Installation>, LocalEngineError> {
    let expected = Installation::expected(name);
    let Some(volume) = engine
        .inspect_volume(&expected.anchor_volume_name)
        .await
        .map_err(map_engine_call)?
    else {
        return Ok(None);
    };
    if volume.name != expected.anchor_volume_name
        || volume.driver != "local"
        || volume.scope != "local"
        || !volume.options.is_empty()
    {
        return Err(LocalEngineError::new(
            LocalEngineErrorCode::IdentityCollision,
        ));
    }
    let id = validate_identity_labels(&volume.labels, &expected)?;
    if engine
        .volume_attachments(&expected.anchor_volume_name)
        .await
        .map_err(map_engine_call)?
        .is_empty()
    {
        Ok(Some(Installation::verified(name.clone(), id)))
    } else {
        Err(LocalEngineError::new(
            LocalEngineErrorCode::IdentityAnchorAttached,
        ))
    }
}

fn identity_labels(installation: &Installation) -> BTreeMap<String, String> {
    BTreeMap::from([
        (LABEL_MANAGED.to_owned(), MANAGED_VALUE.to_owned()),
        (LABEL_IDENTITY_SCHEMA.to_owned(), IDENTITY_SCHEMA.to_owned()),
        (
            LABEL_INSTALLATION_ID.to_owned(),
            installation.id().to_string(),
        ),
        (
            LABEL_INSTALLATION_KEY.to_owned(),
            installation.selector_key().to_string(),
        ),
        (
            LABEL_COMPOSE_PROJECT.to_owned(),
            installation.compose_project().to_string(),
        ),
        (
            LABEL_RESOURCE_KIND.to_owned(),
            IDENTITY_ANCHOR_KIND.to_owned(),
        ),
    ])
}

fn validate_identity_labels(
    labels: &BTreeMap<String, String>,
    expected: &crate::installation::ExpectedInstallation,
) -> Result<InstallationId, LocalEngineError> {
    let managed: BTreeMap<&str, &str> = labels
        .iter()
        .filter(|(key, _value)| key.starts_with(MANAGED_LABEL_PREFIX))
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    let Some(id) = managed
        .get(LABEL_INSTALLATION_ID)
        .and_then(|value| InstallationId::parse_canonical(value))
    else {
        return Err(classify_label_failure(&managed));
    };
    let selector_key = expected.selector_key.to_string();
    if managed.len() != 6
        || managed.get(LABEL_MANAGED).copied() != Some(MANAGED_VALUE)
        || managed.get(LABEL_IDENTITY_SCHEMA).copied() != Some(IDENTITY_SCHEMA)
        || managed.get(LABEL_INSTALLATION_KEY).copied() != Some(selector_key.as_str())
        || managed.get(LABEL_COMPOSE_PROJECT).copied() != Some(expected.compose_project.as_str())
        || managed.get(LABEL_RESOURCE_KIND).copied() != Some(IDENTITY_ANCHOR_KIND)
    {
        return Err(classify_label_failure(&managed));
    }
    Ok(id)
}

fn classify_label_failure(managed: &BTreeMap<&str, &str>) -> LocalEngineError {
    let owned = managed.get(LABEL_MANAGED).copied() == Some(MANAGED_VALUE)
        && managed.get(LABEL_RESOURCE_KIND).copied() == Some(IDENTITY_ANCHOR_KIND);
    LocalEngineError::new(if owned {
        LocalEngineErrorCode::InvalidIdentityAnchor
    } else {
        LocalEngineErrorCode::IdentityCollision
    })
}

fn map_engine_call(error: EngineApiError) -> LocalEngineError {
    match error {
        EngineApiError::RequestFailed => {
            LocalEngineError::new(LocalEngineErrorCode::EngineRequestFailed)
        }
        EngineApiError::InvalidResponse => {
            LocalEngineError::new(LocalEngineErrorCode::InvalidEngineResponse)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EngineFacts {
    engine_id: String,
    server_version: String,
    minimum_api_version: String,
    maximum_api_version: String,
    operating_system: String,
    architecture: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InspectedVolume {
    name: String,
    driver: String,
    scope: String,
    options: BTreeMap<String, String>,
    labels: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CreateVolume {
    name: String,
    labels: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EngineApiError {
    RequestFailed,
    InvalidResponse,
}

#[async_trait]
trait EngineApi: Send + Sync {
    async fn engine_facts(&self) -> Result<EngineFacts, EngineApiError>;

    async fn inspect_volume(&self, name: &str) -> Result<Option<InspectedVolume>, EngineApiError>;

    async fn create_volume(&self, request: CreateVolume) -> Result<(), EngineApiError>;

    async fn volume_attachments(&self, name: &str) -> Result<Vec<String>, EngineApiError>;
}

fn adapter_api_version(selected: &str) -> Result<ApiVersion, LocalEngineError> {
    let selected = ApiVersion::parse(selected)
        .ok_or_else(|| LocalEngineError::new(LocalEngineErrorCode::InvalidEngineResponse))?;
    Ok(capped_adapter_api(selected))
}

#[cfg(test)]
mod tests;
