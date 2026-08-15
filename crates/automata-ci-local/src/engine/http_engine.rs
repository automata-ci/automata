use std::{collections::BTreeMap, time::Duration};

use async_trait::async_trait;
use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};

use super::{
    CreateVolume, EngineApi, EngineApiError, EngineFacts, InspectedVolume,
    transport::{
        BoundedMap, BoundedVec, DockerHttpTransport, TransportError, deadline,
        encode_path_component,
    },
};
use crate::{ApiVersion, DockerConnection, normalize_architecture};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const FACTS_BYTES: usize = 128 * 1024;
const VOLUME_BYTES: usize = 256 * 1024;
const CONTAINER_LIST_BYTES: usize = 256 * 1024;
const MAX_ATTACHMENTS: usize = 8;
const MAX_LABELS: usize = 256;
const MAX_VOLUME_OPTIONS: usize = 32;

pub(super) struct HttpEngine {
    transport: DockerHttpTransport,
}

impl HttpEngine {
    pub(super) fn connect(
        connection: &DockerConnection,
        api: ApiVersion,
    ) -> Result<Self, TransportError> {
        Ok(Self {
            transport: DockerHttpTransport::connect(connection, api)?,
        })
    }

    #[cfg(test)]
    pub(super) async fn remove_volume_for_test(&self, name: &str) -> Result<(), EngineApiError> {
        let path = format!("/volumes/{}?force=false", encode_path_component(name));
        deadline(
            REQUEST_TIMEOUT,
            self.transport
                .empty_or_not_found(Method::DELETE, &path, StatusCode::NO_CONTENT),
        )
        .await
        .map_err(map_transport)
    }
}

#[async_trait]
impl EngineApi for HttpEngine {
    async fn engine_facts(&self) -> Result<EngineFacts, EngineApiError> {
        let (info, version) = deadline(REQUEST_TIMEOUT, async {
            tokio::try_join!(
                self.transport.json::<InfoResponse, ()>(
                    Method::GET,
                    "/info",
                    None,
                    StatusCode::OK,
                    FACTS_BYTES,
                ),
                self.transport.json::<VersionResponse, ()>(
                    Method::GET,
                    "/version",
                    None,
                    StatusCode::OK,
                    FACTS_BYTES,
                )
            )
        })
        .await
        .map_err(map_transport)?;
        let info_architecture =
            normalize_architecture(&info.architecture).ok_or(EngineApiError::InvalidResponse)?;
        let version_architecture =
            normalize_architecture(&version.architecture).ok_or(EngineApiError::InvalidResponse)?;
        if info.id.is_empty()
            || info.server_version != version.version
            || info_architecture != version_architecture
            || info.operating_system != version.operating_system
        {
            return Err(EngineApiError::InvalidResponse);
        }
        Ok(EngineFacts {
            engine_id: info.id,
            server_version: version.version,
            minimum_api_version: version.minimum_api_version,
            maximum_api_version: version.api_version,
            operating_system: version.operating_system,
            architecture: version.architecture,
        })
    }

    async fn inspect_volume(&self, name: &str) -> Result<Option<InspectedVolume>, EngineApiError> {
        let path = format!("/volumes/{}", encode_path_component(name));
        let volume: Option<VolumeResponse> = deadline(
            REQUEST_TIMEOUT,
            self.transport.optional_json(&path, VOLUME_BYTES),
        )
        .await
        .map_err(map_transport)?;
        Ok(volume.map(|volume| InspectedVolume {
            name: volume.name,
            driver: volume.driver,
            scope: volume.scope,
            options: volume
                .options
                .map_or_else(BTreeMap::new, BoundedMap::into_inner),
            labels: volume
                .labels
                .map_or_else(BTreeMap::new, BoundedMap::into_inner),
        }))
    }

    async fn create_volume(&self, request: CreateVolume) -> Result<(), EngineApiError> {
        let body = VolumeCreateRequest {
            name: request.name,
            driver: "local",
            driver_options: BTreeMap::new(),
            labels: request.labels,
        };
        let created: VolumeResponse = deadline(
            REQUEST_TIMEOUT,
            self.transport.json(
                Method::POST,
                "/volumes/create",
                Some(&body),
                StatusCode::CREATED,
                VOLUME_BYTES,
            ),
        )
        .await
        .map_err(map_transport)?;
        if created.name != body.name {
            return Err(EngineApiError::InvalidResponse);
        }
        Ok(())
    }

    async fn volume_attachments(&self, name: &str) -> Result<Vec<String>, EngineApiError> {
        let filters = serde_json::to_string(&BTreeMap::from([("volume", [name])]))
            .map_err(|_| EngineApiError::InvalidResponse)?;
        let path = format!(
            "/containers/json?all=true&filters={}",
            encode_path_component(&filters)
        );
        let containers: BoundedVec<ContainerSummary, MAX_ATTACHMENTS> = deadline(
            REQUEST_TIMEOUT,
            self.transport.json::<_, ()>(
                Method::GET,
                &path,
                None,
                StatusCode::OK,
                CONTAINER_LIST_BYTES,
            ),
        )
        .await
        .map_err(map_transport)?;
        containers
            .into_inner()
            .into_iter()
            .map(|container| {
                if valid_container_id(&container.id) {
                    Ok(container.id)
                } else {
                    Err(EngineApiError::InvalidResponse)
                }
            })
            .collect()
    }
}

const fn map_transport(error: TransportError) -> EngineApiError {
    match error {
        TransportError::InvalidRequest
        | TransportError::InvalidResponse
        | TransportError::ResponseTooLarge => EngineApiError::InvalidResponse,
        TransportError::RequestFailed | TransportError::Rejected(_) => {
            EngineApiError::RequestFailed
        }
    }
}

fn valid_container_id(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Deserialize)]
struct InfoResponse {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "ServerVersion")]
    server_version: String,
    #[serde(rename = "Architecture")]
    architecture: String,
    #[serde(rename = "OSType")]
    operating_system: String,
}

#[derive(Deserialize)]
struct VersionResponse {
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "ApiVersion")]
    api_version: String,
    #[serde(rename = "MinAPIVersion")]
    minimum_api_version: String,
    #[serde(rename = "Arch")]
    architecture: String,
    #[serde(rename = "Os")]
    operating_system: String,
}

#[derive(Deserialize)]
struct VolumeResponse {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Driver")]
    driver: String,
    #[serde(rename = "Scope")]
    scope: String,
    #[serde(rename = "Options")]
    options: Option<BoundedMap<String, String, MAX_VOLUME_OPTIONS>>,
    #[serde(rename = "Labels")]
    labels: Option<BoundedMap<String, String, MAX_LABELS>>,
}

#[derive(Serialize)]
struct VolumeCreateRequest {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Driver")]
    driver: &'static str,
    #[serde(rename = "DriverOpts")]
    driver_options: BTreeMap<String, String>,
    #[serde(rename = "Labels")]
    labels: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct ContainerSummary {
    #[serde(rename = "Id")]
    id: String,
}

#[cfg(test)]
mod tests {
    use super::valid_container_id;

    #[test]
    fn accepts_only_full_hex_container_ids() {
        assert!(valid_container_id(&"a".repeat(64)));
        assert!(!valid_container_id(&"a".repeat(63)));
        assert!(!valid_container_id(&"g".repeat(64)));
    }
}
