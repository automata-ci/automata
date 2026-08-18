use std::time::Duration;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    future::Future,
    pin::Pin,
};

use automata_ci_core::Sha256Digest;
use bollard::{
    Docker, body_full,
    container::{AttachContainerResults, LogOutput},
    errors::Error as BollardError,
    models::{
        ContainerCreateBody, ContainerSummary, HostConfig, HostConfigCgroupnsModeEnum,
        HostConfigLogConfig, Mount, MountType, MountVolumeOptions, Network, RestartPolicy,
        RestartPolicyNameEnum, Volume, VolumeCreateRequest,
    },
    query_parameters::{
        AttachContainerOptionsBuilder, CreateContainerOptionsBuilder, CreateImageOptionsBuilder,
        ImportImageOptionsBuilder, ListContainersOptionsBuilder, ListNetworksOptionsBuilder,
        ListVolumesOptionsBuilder, LogsOptionsBuilder, RemoveContainerOptionsBuilder,
        WaitContainerOptionsBuilder,
    },
};
use bytes::Bytes;
use futures::{StreamExt as _, TryStreamExt as _};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncWrite, AsyncWriteExt as _};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::{DockerInstallationAdapter, Installation, installation::ExpectedInstallation};

use super::{
    LocalInitError, LocalInitErrorCode,
    catalog::{LiveImageEvidence, VerifiedCatalog},
    materializer::{MaterializeRequest, VolumeRole},
};

const ENGINE_TIMEOUT: Duration = Duration::from_secs(10);
const IMAGE_TIMEOUT: Duration = Duration::from_mins(15);
const HELPER_TIMEOUT: Duration = Duration::from_mins(2);
const MATERIAL_SCHEMA: &str = "automata.local/material/v1";
const MATERIAL_GENERATION: &str = "1";
const MANAGED_PREFIX: &str = "io.automata.local.";
const MANAGED_PROJECT_LABEL: &str = "io.automata.local.compose-project";
const COMPOSE_PROJECT_LABEL: &str = "com.docker.compose.project";
const HELPER_KIND: &str = "init-materializer";
const HELPER_MEMORY_BYTES: i64 = 128 * 1024 * 1024;
const HELPER_PIDS: i64 = 64;
const HELPER_NANO_CPUS: i64 = 1_000_000_000;
const RESPONSE_SCHEMA: &str = "automata.local/materialize-response/v1";
const MAX_HELPER_LOG_BYTES: usize = 16 * 1024;
const HELPER_EXPOSED_PORT: &str = "8080/tcp";
const MAX_ENGINE_RESOURCES: usize = 4096;
const INIT_VOLUME_ORDER: [VolumeRole; 12] = [
    VolumeRole::Desired,
    VolumeRole::BootstrapState,
    VolumeRole::ControlMaterial,
    VolumeRole::EngineRelay,
    VolumeRole::ObjectData,
    VolumeRole::PostgresConfig,
    VolumeRole::PostgresData,
    VolumeRole::RelayBinding,
    VolumeRole::RunnerConfig,
    VolumeRole::RunnerData,
    VolumeRole::RunnerSecrets,
    VolumeRole::RustfsConfig,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct InitOwnedUnion {
    pub(super) anchor_present: bool,
    pub(super) roles: BTreeSet<VolumeRole>,
    pub(super) helper_id: Option<String>,
}

struct OwnedUnionVolumes {
    warnings: bool,
    volumes: Vec<Volume>,
}

#[async_trait::async_trait]
trait OwnedUnionDriver: Sync {
    async fn list_owned_union_volumes(&self) -> Result<OwnedUnionVolumes, LocalInitError>;
    async fn list_owned_union_containers(&self) -> Result<Vec<ContainerSummary>, LocalInitError>;
    async fn list_owned_union_networks(&self) -> Result<Vec<Network>, LocalInitError>;
}

#[async_trait::async_trait]
trait OwnedVolumeDriver: Sync {
    async fn inspect_owned_volume(&self, name: &str) -> Result<Option<Volume>, LocalInitError>;
    async fn owned_volume_attachments(&self, name: &str) -> Result<Vec<String>, LocalInitError>;
}

pub(super) struct QualifiedHelperImage {
    pub(super) reference: String,
    pub(super) id: String,
}

#[derive(Debug)]
struct QualifiedStaleHelper {
    id: String,
    name: String,
    image: String,
    image_id: String,
    volumes: BTreeMap<VolumeRole, String>,
    labels: BTreeMap<String, String>,
    volume_labels: BTreeMap<VolumeRole, BTreeMap<String, String>>,
}

impl QualifiedStaleHelper {
    fn contract(&self) -> HelperContract<'_> {
        HelperContract {
            name: self.name.clone(),
            image: &self.image,
            image_id: &self.image_id,
            volumes: &self.volumes,
            labels: self.labels.clone(),
            volume_labels: self.volume_labels.clone(),
        }
    }
}

pub(super) struct InitEngine<'a> {
    adapter: &'a DockerInstallationAdapter,
    docker: Docker,
}

impl<'a> InitEngine<'a> {
    pub(super) async fn connect(
        adapter: &'a DockerInstallationAdapter,
    ) -> Result<Self, LocalInitError> {
        adapter
            .verify_for_init()
            .await
            .map_err(|_| engine_unavailable())?;
        Ok(Self {
            adapter,
            docker: adapter.exact_docker().map_err(|_| engine_unavailable())?,
        })
    }

    pub(super) async fn inspect_owned_union(
        &self,
        expected: &ExpectedInstallation,
        installation: Option<&Installation>,
    ) -> Result<InitOwnedUnion, LocalInitError> {
        self.verify_selected_engine().await?;
        let owned = inspect_init_owned_union_with_driver(self, expected, installation).await?;
        self.verify_selected_engine().await?;
        Ok(owned)
    }

    pub(super) async fn preflight_owned_union(
        &self,
        catalog: &VerifiedCatalog,
        installation: &Installation,
        epoch_fingerprint: Sha256Digest,
        pre_identity: &InitOwnedUnion,
        cancellation: &CancellationToken,
    ) -> Result<BTreeSet<VolumeRole>, LocalInitError> {
        cancellation_checkpoint(cancellation)?;
        self.verify_selected_engine().await?;
        self.verify_exact_identity(installation).await?;
        let scope = Installation::expected(installation.name());
        let observed =
            inspect_init_owned_union_with_driver(self, &scope, Some(installation)).await?;
        validate_post_identity_transition(pre_identity, &observed)?;
        self.validate_owned_volumes(installation, epoch_fingerprint, &observed)
            .await?;
        self.qualify_stale_helper(
            catalog,
            installation,
            epoch_fingerprint,
            observed.helper_id.as_deref(),
        )
        .await?;
        let repeated =
            inspect_init_owned_union_with_driver(self, &scope, Some(installation)).await?;
        if repeated != observed {
            return Err(engine_resource_mismatch());
        }
        self.validate_owned_volumes(installation, epoch_fingerprint, &repeated)
            .await?;
        self.qualify_stale_helper(
            catalog,
            installation,
            epoch_fingerprint,
            repeated.helper_id.as_deref(),
        )
        .await?;
        self.verify_exact_identity(installation).await?;
        self.verify_selected_engine().await?;
        cancellation_checkpoint(cancellation)?;
        Ok(observed.roles)
    }

    pub(super) async fn elect_desired_and_recover_owned_union(
        &self,
        catalog: &VerifiedCatalog,
        installation: &Installation,
        epoch_fingerprint: Sha256Digest,
        pre_identity: &InitOwnedUnion,
        allow_create: bool,
        cancellation: &CancellationToken,
    ) -> Result<(), LocalInitError> {
        let name = volume_name(installation.compose_project().as_str(), VolumeRole::Desired);
        let labels = volume_labels(installation, epoch_fingerprint, VolumeRole::Desired);
        guard_then_recover(
            elect_desired_guard_with_driver(
                self,
                &name,
                &labels,
                pre_identity.helper_id.as_deref(),
                allow_create,
                cancellation,
            ),
            || async {
                self.recover_owned_union_after_desired(
                    catalog,
                    installation,
                    epoch_fingerprint,
                    pre_identity,
                    cancellation,
                )
                .await
            },
        )
        .await
    }

    pub(super) async fn verify_final_owned_union(
        &self,
        installation: &Installation,
        epoch_fingerprint: Sha256Digest,
    ) -> Result<(), LocalInitError> {
        self.verify_selected_engine().await?;
        self.verify_exact_identity(installation).await?;
        validate_final_owned_union_with_driver(self, installation, epoch_fingerprint).await?;
        self.verify_exact_identity(installation).await?;
        self.verify_selected_engine().await
    }

    pub(super) async fn qualify_images(
        &self,
        catalog: &VerifiedCatalog,
        candidate_load_archive: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<QualifiedHelperImage, LocalInitError> {
        self.verify_selected_engine().await?;
        let qualified =
            cancellation_checkpointed(cancellation, VerifiedCatalog::roles(), |role| async move {
                let image_binding = catalog.image(role);
                let inspection_reference = image_binding.inspection_reference();
                if self.inspect_image(&inspection_reference).await?.is_none() {
                    self.verify_selected_engine().await?;
                    if catalog.is_registry_role(role) {
                        let pull_reference = image_binding.source_reference();
                        let options = CreateImageOptionsBuilder::default()
                            .from_image(pull_reference)
                            .platform("linux/amd64")
                            .build();
                        mutation_after_cancellation_checkpoint(cancellation, || async {
                            tokio::time::timeout(
                                IMAGE_TIMEOUT,
                                self.docker
                                    .create_image(Some(options), None, None)
                                    .try_collect::<Vec<_>>(),
                            )
                            .await
                            .map_err(|_| engine_unavailable())?
                            .map_err(|_| engine_unavailable())?;
                            Ok(())
                        })
                        .await?;
                    } else {
                        replay_candidate_load(
                            self,
                            catalog,
                            role,
                            image_binding,
                            candidate_load_archive,
                            cancellation,
                        )
                        .await?;
                    }
                    self.verify_selected_engine().await?;
                }
                let image = self
                    .inspect_image(&inspection_reference)
                    .await?
                    .ok_or_else(engine_resource_mismatch)?;
                let id = image.id.as_deref().ok_or_else(engine_resource_mismatch)?;
                let os = image.os.as_deref().ok_or_else(engine_resource_mismatch)?;
                let architecture = image
                    .architecture
                    .as_deref()
                    .ok_or_else(engine_resource_mismatch)?;
                let config = serde_json::to_value(
                    image.config.as_ref().ok_or_else(engine_resource_mismatch)?,
                )
                .map_err(|_| engine_resource_mismatch())?;
                catalog
                    .validate_live_image(
                        role,
                        &LiveImageEvidence {
                            image_id: id,
                            operating_system: os,
                            architecture,
                            config: &config,
                            repository_tags: image.repo_tags.as_deref(),
                            repository_digests: image.repo_digests.as_deref(),
                        },
                    )
                    .map_err(|_| engine_resource_mismatch())?;
                self.verify_local_import_resolution(image_binding, &image)
                    .await?;
                Ok((role == "automata").then(|| QualifiedHelperImage {
                    reference: inspection_reference,
                    id: id.to_owned(),
                }))
            })
            .await?;
        self.verify_selected_engine().await?;
        qualified
            .into_iter()
            .flatten()
            .next()
            .ok_or_else(engine_resource_mismatch)
    }

    pub(super) async fn create_or_adopt_volumes(
        &self,
        installation: &Installation,
        epoch_fingerprint: Sha256Digest,
        helper_image: &str,
        helper_image_id: &str,
        allow_create: bool,
        cancellation: &CancellationToken,
    ) -> Result<BTreeMap<VolumeRole, String>, LocalInitError> {
        cancellation_checkpoint(cancellation)?;
        self.verify_selected_engine().await?;
        cancellation_checkpoint(cancellation)?;
        let names = volume_names(installation);
        self.recover_helper(&HelperContract {
            name: helper_name(installation),
            image: helper_image,
            image_id: helper_image_id,
            volumes: &names,
            labels: helper_labels(installation, epoch_fingerprint),
            volume_labels: expected_volume_labels(installation, epoch_fingerprint),
        })
        .await?;
        cancellation_checkpoint(cancellation)?;
        let guard_name = names
            .get(&VolumeRole::Desired)
            .expect("the closed volume map contains the Desired guard");
        let guard_labels = volume_labels(installation, epoch_fingerprint, VolumeRole::Desired);
        let guard = self
            .inspect_volume(guard_name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        validate_volume(&guard, guard_name, &guard_labels)?;
        if !self.volume_attachments(guard_name).await?.is_empty() {
            return Err(engine_resource_mismatch());
        }
        let remaining = INIT_VOLUME_ORDER
            .into_iter()
            .skip(1)
            .map(|role| {
                let name = names
                    .get(&role)
                    .expect("the closed volume map contains every ordered role");
                (role, name.clone())
            })
            .collect::<Vec<_>>();
        cancellation_checkpointed(cancellation, remaining, |(role, name)| async move {
            let labels = volume_labels(installation, epoch_fingerprint, role);
            if let Some(volume) = self.inspect_volume(&name).await? {
                validate_volume(&volume, &name, &labels)?;
            } else {
                if !allow_create {
                    return Err(engine_resource_mismatch());
                }
                create_volume_after_preflight(self, &name, &labels, cancellation).await?;
                self.verify_selected_engine().await?;
                let volume = self
                    .inspect_volume(&name)
                    .await?
                    .ok_or_else(engine_resource_mismatch)?;
                validate_volume(&volume, &name, &labels)?;
            }
            if !self.volume_attachments(&name).await?.is_empty() {
                return Err(engine_resource_mismatch());
            }
            Ok(())
        })
        .await?;
        self.verify_selected_engine().await?;
        Ok(names)
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub(super) async fn run_materializer(
        &self,
        installation: &Installation,
        epoch_fingerprint: Sha256Digest,
        helper_image: &str,
        helper_image_id: &str,
        volumes: &BTreeMap<VolumeRole, String>,
        request: &MaterializeRequest,
        cancellation: &CancellationToken,
    ) -> Result<(), LocalInitError> {
        self.verify_selected_engine().await?;
        let contract = HelperContract {
            name: helper_name(installation),
            image: helper_image,
            image_id: helper_image_id,
            volumes,
            labels: helper_labels(installation, epoch_fingerprint),
            volume_labels: expected_volume_labels(installation, epoch_fingerprint),
        };
        self.recover_helper(&contract).await?;
        run_materializer_with_driver(self, &contract, request, epoch_fingerprint, cancellation)
            .await
    }

    async fn verify_selected_engine(&self) -> Result<(), LocalInitError> {
        self.adapter
            .verify_for_init()
            .await
            .map_err(|_| engine_unavailable())
    }

    async fn verify_exact_identity(
        &self,
        installation: &Installation,
    ) -> Result<(), LocalInitError> {
        let observed = self
            .adapter
            .inspect_identity(installation.name())
            .await
            .map_err(super::map_engine_error)?;
        if observed.as_ref() != Some(installation) {
            return Err(engine_resource_mismatch());
        }
        Ok(())
    }

    async fn inspect_image(
        &self,
        reference: &str,
    ) -> Result<Option<bollard::models::ImageInspect>, LocalInitError> {
        match tokio::time::timeout(ENGINE_TIMEOUT, self.docker.inspect_image(reference)).await {
            Ok(Ok(image)) => Ok(Some(image)),
            Ok(Err(error)) if not_found(&error) => Ok(None),
            _ => Err(engine_unavailable()),
        }
    }

    async fn verify_local_import_resolution(
        &self,
        image_binding: &super::catalog::VerifiedImage,
        image: &bollard::models::ImageInspect,
    ) -> Result<(), LocalInitError> {
        let Some([digest_reference, manifest_id, config_id]) =
            image_binding.local_import_collision_references()
        else {
            return Ok(());
        };
        let imported_id = image.id.as_deref().ok_or_else(engine_resource_mismatch)?;
        let by_id = self
            .inspect_image(imported_id)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        if &by_id != image {
            return Err(engine_resource_mismatch());
        }
        let (alternate_id, expect_digest_reference) = if imported_id == config_id {
            (&manifest_id, false)
        } else if imported_id == manifest_id {
            (&config_id, true)
        } else {
            return Err(engine_resource_mismatch());
        };
        if self.inspect_image(alternate_id).await?.is_some() {
            return Err(engine_resource_mismatch());
        }
        let by_digest = self.inspect_image(&digest_reference).await?;
        if expect_digest_reference {
            if by_digest.as_ref() != Some(image) {
                return Err(engine_resource_mismatch());
            }
        } else if by_digest.is_some() {
            return Err(engine_resource_mismatch());
        }
        Ok(())
    }

    async fn inspect_volume(
        &self,
        name: &str,
    ) -> Result<Option<bollard::models::Volume>, LocalInitError> {
        match tokio::time::timeout(ENGINE_TIMEOUT, self.docker.inspect_volume(name)).await {
            Ok(Ok(volume)) => Ok(Some(volume)),
            Ok(Err(error)) if not_found(&error) => Ok(None),
            _ => Err(engine_unavailable()),
        }
    }

    async fn inspect_container(
        &self,
        name: &str,
    ) -> Result<Option<bollard::models::ContainerInspectResponse>, LocalInitError> {
        match tokio::time::timeout(ENGINE_TIMEOUT, self.docker.inspect_container(name, None)).await
        {
            Ok(Ok(container)) => Ok(Some(container)),
            Ok(Err(error)) if not_found(&error) => Ok(None),
            _ => Err(engine_unavailable()),
        }
    }

    async fn volume_attachments(&self, name: &str) -> Result<Vec<String>, LocalInitError> {
        let filters = HashMap::from([("volume", vec![name])]);
        let options = ListContainersOptionsBuilder::default()
            .all(true)
            .filters(&filters)
            .build();
        let containers =
            tokio::time::timeout(ENGINE_TIMEOUT, self.docker.list_containers(Some(options)))
                .await
                .map_err(|_| engine_unavailable())?
                .map_err(|_| engine_unavailable())?;
        containers
            .into_iter()
            .map(|container| container.id.ok_or_else(engine_resource_mismatch))
            .collect()
    }

    async fn validate_owned_volumes(
        &self,
        installation: &Installation,
        epoch_fingerprint: Sha256Digest,
        owned: &InitOwnedUnion,
    ) -> Result<(), LocalInitError> {
        validate_owned_volumes_with_driver(self, installation, epoch_fingerprint, owned).await
    }

    async fn qualify_stale_helper(
        &self,
        catalog: &VerifiedCatalog,
        installation: &Installation,
        epoch_fingerprint: Sha256Digest,
        helper_id: Option<&str>,
    ) -> Result<Option<QualifiedStaleHelper>, LocalInitError> {
        let Some(helper_id) = helper_id else {
            return Ok(None);
        };
        let image = catalog.image("automata");
        let helper = self
            .inspect_container(&helper_name(installation))
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        let actual_image_id = helper
            .image
            .as_deref()
            .filter(|id| image.accepts_live_id(id))
            .ok_or_else(engine_resource_mismatch)?;
        let qualified = QualifiedStaleHelper {
            id: helper_id.to_owned(),
            name: helper_name(installation),
            image: image.inspection_reference(),
            image_id: actual_image_id.to_owned(),
            volumes: volume_names(installation),
            labels: helper_labels(installation, epoch_fingerprint),
            volume_labels: expected_volume_labels(installation, epoch_fingerprint),
        };
        let contract = qualified.contract();
        validate_helper(
            &helper,
            &qualified.id,
            &contract.name,
            contract.image,
            contract.image_id,
            contract.volumes,
            &contract.labels,
        )?;
        Ok(Some(qualified))
    }

    async fn recover_owned_union_after_desired(
        &self,
        catalog: &VerifiedCatalog,
        installation: &Installation,
        epoch_fingerprint: Sha256Digest,
        pre_identity: &InitOwnedUnion,
        cancellation: &CancellationToken,
    ) -> Result<(), LocalInitError> {
        cancellation_checkpoint(cancellation)?;
        self.verify_selected_engine().await?;
        self.verify_exact_identity(installation).await?;
        let scope = Installation::expected(installation.name());
        let expected = expected_post_desired_union(pre_identity);
        let observed =
            inspect_init_owned_union_with_driver(self, &scope, Some(installation)).await?;
        if observed != expected {
            return Err(engine_resource_mismatch());
        }
        self.validate_owned_volumes(installation, epoch_fingerprint, &observed)
            .await?;
        if let Some(stale) = self
            .qualify_stale_helper(
                catalog,
                installation,
                epoch_fingerprint,
                observed.helper_id.as_deref(),
            )
            .await?
        {
            cancellation_checkpoint(cancellation)?;
            let contract = stale.contract();
            cleanup_helper(self, &contract, Some(&stale.id)).await?;
            self.verify_selected_engine().await?;
        }
        let clean = inspect_init_owned_union_with_driver(self, &scope, Some(installation)).await?;
        let mut expected_clean = expected;
        expected_clean.helper_id = None;
        if clean != expected_clean {
            return Err(engine_resource_mismatch());
        }
        self.validate_owned_volumes(installation, epoch_fingerprint, &clean)
            .await?;
        self.verify_exact_identity(installation).await?;
        self.verify_selected_engine().await?;
        cancellation_checkpoint(cancellation)
    }

    async fn recover_helper(&self, contract: &HelperContract<'_>) -> Result<(), LocalInitError> {
        let Some(container) = self.inspect_container(&contract.name).await? else {
            return Ok(());
        };
        let id = exact_container_id(&container)?.to_owned();
        validate_helper(
            &container,
            &id,
            &contract.name,
            contract.image,
            contract.image_id,
            contract.volumes,
            &contract.labels,
        )?;
        cleanup_helper(self, contract, Some(&id)).await
    }

    async fn helper_logs(&self, name: &str) -> Result<(Vec<u8>, Vec<u8>), LocalInitError> {
        let options = LogsOptionsBuilder::default()
            .follow(false)
            .stdout(true)
            .stderr(true)
            .timestamps(false)
            .tail("all")
            .build();
        let mut frames = self.docker.logs(name, Some(options));
        tokio::time::timeout(ENGINE_TIMEOUT, async {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            while let Some(frame) = frames.next().await {
                let frame = frame.map_err(|_| materialization_failed())?;
                let destination = match frame {
                    LogOutput::StdOut { .. } => &mut stdout,
                    LogOutput::StdErr { .. } => &mut stderr,
                    _ => return Err(materialization_failed()),
                };
                if frame.as_ref().len() > MAX_HELPER_LOG_BYTES.saturating_sub(destination.len()) {
                    return Err(materialization_failed());
                }
                destination.extend_from_slice(frame.as_ref());
            }
            Ok((stdout, stderr))
        })
        .await
        .map_err(|_| materialization_failed())?
    }
}

#[async_trait::async_trait]
impl OwnedUnionDriver for InitEngine<'_> {
    async fn list_owned_union_volumes(&self) -> Result<OwnedUnionVolumes, LocalInitError> {
        let listed = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker
                .list_volumes(Some(ListVolumesOptionsBuilder::default().build())),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())?;
        Ok(OwnedUnionVolumes {
            warnings: listed
                .warnings
                .as_ref()
                .is_some_and(|warnings| !warnings.is_empty()),
            volumes: listed.volumes.unwrap_or_default(),
        })
    }

    async fn list_owned_union_containers(&self) -> Result<Vec<ContainerSummary>, LocalInitError> {
        tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.list_containers(Some(
                ListContainersOptionsBuilder::default().all(true).build(),
            )),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())
    }

    async fn list_owned_union_networks(&self) -> Result<Vec<Network>, LocalInitError> {
        tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker
                .list_networks(Some(ListNetworksOptionsBuilder::default().build())),
        )
        .await
        .map_err(|_| engine_unavailable())?
        .map_err(|_| engine_unavailable())
    }
}

#[async_trait::async_trait]
impl OwnedVolumeDriver for InitEngine<'_> {
    async fn inspect_owned_volume(&self, name: &str) -> Result<Option<Volume>, LocalInitError> {
        self.inspect_volume(name).await
    }

    async fn owned_volume_attachments(&self, name: &str) -> Result<Vec<String>, LocalInitError> {
        self.volume_attachments(name).await
    }
}

async fn validate_owned_volumes_with_driver<D: OwnedVolumeDriver>(
    driver: &D,
    installation: &Installation,
    epoch_fingerprint: Sha256Digest,
    owned: &InitOwnedUnion,
) -> Result<(), LocalInitError> {
    let expected_attachment = owned.helper_id.as_deref();
    for role in INIT_VOLUME_ORDER {
        if !owned.roles.contains(&role) {
            continue;
        }
        let name = volume_name(installation.compose_project().as_str(), role);
        let volume = driver
            .inspect_owned_volume(&name)
            .await?
            .ok_or_else(engine_resource_mismatch)?;
        validate_volume(
            &volume,
            &name,
            &volume_labels(installation, epoch_fingerprint, role),
        )?;
        let attachments = driver.owned_volume_attachments(&name).await?;
        if match expected_attachment {
            Some(expected) => attachments.as_slice() != [expected],
            None => !attachments.is_empty(),
        } {
            return Err(engine_resource_mismatch());
        }
    }
    Ok(())
}

fn validate_post_identity_transition(
    pre_identity: &InitOwnedUnion,
    post_identity: &InitOwnedUnion,
) -> Result<(), LocalInitError> {
    let mut expected = pre_identity.clone();
    expected.anchor_present = true;
    if post_identity != &expected {
        return Err(engine_resource_mismatch());
    }
    Ok(())
}

fn expected_post_desired_union(pre_identity: &InitOwnedUnion) -> InitOwnedUnion {
    let mut expected = pre_identity.clone();
    expected.anchor_present = true;
    expected.roles.insert(VolumeRole::Desired);
    expected
}

async fn validate_final_owned_union_with_driver<D>(
    driver: &D,
    installation: &Installation,
    epoch_fingerprint: Sha256Digest,
) -> Result<(), LocalInitError>
where
    D: OwnedUnionDriver + OwnedVolumeDriver,
{
    let scope = Installation::expected(installation.name());
    let observed = inspect_init_owned_union_with_driver(driver, &scope, Some(installation)).await?;
    let expected_roles = INIT_VOLUME_ORDER.into_iter().collect::<BTreeSet<_>>();
    if !observed.anchor_present || observed.roles != expected_roles || observed.helper_id.is_some()
    {
        return Err(engine_resource_mismatch());
    }
    validate_owned_volumes_with_driver(driver, installation, epoch_fingerprint, &observed).await?;
    let final_observed =
        inspect_init_owned_union_with_driver(driver, &scope, Some(installation)).await?;
    if final_observed != observed {
        return Err(engine_resource_mismatch());
    }
    validate_owned_volumes_with_driver(driver, installation, epoch_fingerprint, &final_observed)
        .await
}

#[allow(clippy::too_many_lines)]
async fn inspect_init_owned_union_with_driver<D: OwnedUnionDriver>(
    driver: &D,
    expected: &ExpectedInstallation,
    installation: Option<&Installation>,
) -> Result<InitOwnedUnion, LocalInitError> {
    let expected_volumes = INIT_VOLUME_ORDER
        .into_iter()
        .map(|role| (volume_name(expected.compose_project.as_str(), role), role))
        .collect::<BTreeMap<_, _>>();
    let listed = driver.list_owned_union_volumes().await?;
    if listed.warnings || listed.volumes.len() > MAX_ENGINE_RESOURCES {
        return Err(engine_resource_mismatch());
    }
    let mut anchor_present = false;
    let mut roles = BTreeSet::new();
    let mut observed_names = BTreeSet::new();
    for volume in listed.volumes {
        if !resource_related(&volume.name, &volume.labels, expected, installation) {
            continue;
        }
        if volume
            .labels
            .get(COMPOSE_PROJECT_LABEL)
            .is_some_and(|project| project != expected.compose_project.as_str())
        {
            return Err(engine_resource_mismatch());
        }
        if !observed_names.insert(volume.name.clone()) {
            return Err(engine_resource_mismatch());
        }
        if volume.name == expected.anchor_volume_name {
            if anchor_present {
                return Err(engine_resource_mismatch());
            }
            anchor_present = true;
        } else if let Some(role) = expected_volumes.get(&volume.name) {
            if !roles.insert(*role) {
                return Err(engine_resource_mismatch());
            }
        } else {
            return Err(engine_resource_mismatch());
        }
    }
    let prefix = validate_init_volume_prefix(&roles)?;
    if !anchor_present && prefix != 0 {
        return Err(engine_resource_mismatch());
    }

    let containers = driver.list_owned_union_containers().await?;
    if containers.len() > MAX_ENGINE_RESOURCES {
        return Err(engine_resource_mismatch());
    }
    let expected_helper_name = format!("{}-init-materializer", expected.compose_project);
    let expected_helper_container_name = format!("/{expected_helper_name}");
    let mut helper_id = None;
    for container in containers {
        let labels = container.labels.clone().unwrap_or_default();
        let related = container.names.as_ref().into_iter().flatten().any(|name| {
            resource_related(
                name.trim_start_matches('/'),
                &labels,
                expected,
                installation,
            )
        }) || resource_labels_related(&labels, expected, installation);
        if !related {
            continue;
        }
        if labels
            .get(COMPOSE_PROJECT_LABEL)
            .is_some_and(|project| project != expected.compose_project.as_str())
        {
            return Err(engine_resource_mismatch());
        }
        let names = container.names.as_deref().unwrap_or_default();
        let id = container
            .id
            .as_deref()
            .filter(|id| exact_container_id_text(id))
            .ok_or_else(engine_resource_mismatch)?;
        if names != [expected_helper_container_name.as_str()]
            || helper_id.replace(id.to_owned()).is_some()
        {
            return Err(engine_resource_mismatch());
        }
    }
    if helper_id.is_some() && prefix != INIT_VOLUME_ORDER.len() {
        return Err(engine_resource_mismatch());
    }

    let networks = driver.list_owned_union_networks().await?;
    if networks.len() > MAX_ENGINE_RESOURCES
        || networks.iter().any(|network| {
            let labels = network.labels.clone().unwrap_or_default();
            network
                .name
                .as_deref()
                .is_some_and(|name| resource_related(name, &labels, expected, installation))
                || resource_labels_related(&labels, expected, installation)
        })
    {
        return Err(engine_resource_mismatch());
    }
    Ok(InitOwnedUnion {
        anchor_present,
        roles,
        helper_id,
    })
}

fn validate_init_volume_prefix(roles: &BTreeSet<VolumeRole>) -> Result<usize, LocalInitError> {
    let prefix = INIT_VOLUME_ORDER
        .into_iter()
        .take_while(|role| roles.contains(role))
        .count();
    if INIT_VOLUME_ORDER[prefix..]
        .iter()
        .any(|role| roles.contains(role))
    {
        return Err(engine_resource_mismatch());
    }
    Ok(prefix)
}

fn resource_related(
    name: &str,
    labels: &HashMap<String, String>,
    expected: &ExpectedInstallation,
    installation: Option<&Installation>,
) -> bool {
    name.starts_with(&format!("{}-", expected.compose_project))
        || resource_labels_related(labels, expected, installation)
}

fn resource_labels_related(
    labels: &HashMap<String, String>,
    expected: &ExpectedInstallation,
    installation: Option<&Installation>,
) -> bool {
    installation.is_some_and(|installation| {
        labels
            .get("io.automata.local.installation-id")
            .is_some_and(|value| value == &installation.id().to_string())
    }) || labels
        .get("io.automata.local.installation-key")
        .is_some_and(|value| value == &expected.selector_key.to_string())
        || labels
            .get(MANAGED_PROJECT_LABEL)
            .is_some_and(|value| value == expected.compose_project.as_str())
        || labels
            .get(COMPOSE_PROJECT_LABEL)
            .is_some_and(|value| value == expected.compose_project.as_str())
}

#[async_trait::async_trait]
trait CandidateLoadDriver: Sync {
    async fn candidate_verify(&self) -> Result<(), LocalInitError>;
    async fn candidate_inspect(
        &self,
        reference: &str,
    ) -> Result<Option<bollard::models::ImageInspect>, LocalInitError>;
    async fn candidate_import_untrusted(&self, archive: &[u8]);
}

#[async_trait::async_trait]
impl CandidateLoadDriver for InitEngine<'_> {
    async fn candidate_verify(&self) -> Result<(), LocalInitError> {
        self.verify_selected_engine().await
    }

    async fn candidate_inspect(
        &self,
        reference: &str,
    ) -> Result<Option<bollard::models::ImageInspect>, LocalInitError> {
        self.inspect_image(reference).await
    }

    async fn candidate_import_untrusted(&self, archive: &[u8]) {
        let options = ImportImageOptionsBuilder::default().build();
        let _untrusted = tokio::time::timeout(
            IMAGE_TIMEOUT,
            self.docker
                .import_image(options, body_full(Bytes::copy_from_slice(archive)), None)
                .try_collect::<Vec<_>>(),
        )
        .await;
    }
}

async fn replay_candidate_load<D: CandidateLoadDriver>(
    driver: &D,
    catalog: &VerifiedCatalog,
    role: &str,
    image: &super::catalog::VerifiedImage,
    archive: &[u8],
    cancellation: &CancellationToken,
) -> Result<(), LocalInitError> {
    let [digest_reference, manifest_id, config_id] = image
        .local_import_collision_references()
        .ok_or_else(engine_resource_mismatch)?;
    let by_manifest = driver.candidate_inspect(&manifest_id).await?;
    let by_config = driver.candidate_inspect(&config_id).await?;
    let partial = match (by_manifest, by_config) {
        (Some(_), Some(_)) => return Err(engine_resource_mismatch()),
        (Some(image), None) | (None, Some(image)) => Some(image),
        (None, None) => None,
    };
    let by_digest = driver.candidate_inspect(&digest_reference).await?;
    if let Some(partial) = partial.as_ref() {
        validate_partial_candidate(catalog, role, partial)?;
        let imported_id = partial.id.as_deref().ok_or_else(engine_resource_mismatch)?;
        if imported_id == manifest_id {
            if by_digest.as_ref() != Some(partial) {
                return Err(engine_resource_mismatch());
            }
        } else if imported_id == config_id {
            if by_digest.is_some() {
                return Err(engine_resource_mismatch());
            }
        } else {
            return Err(engine_resource_mismatch());
        }
    } else if by_digest.is_some() {
        return Err(engine_resource_mismatch());
    }
    driver.candidate_verify().await?;
    mutation_after_cancellation_checkpoint(cancellation, || async {
        driver.candidate_import_untrusted(archive).await;
        Ok(())
    })
    .await?;
    driver.candidate_verify().await?;
    cancellation_checkpoint(cancellation)
}

fn validate_partial_candidate(
    catalog: &VerifiedCatalog,
    role: &str,
    image: &bollard::models::ImageInspect,
) -> Result<(), LocalInitError> {
    let config = serde_json::to_value(image.config.as_ref().ok_or_else(engine_resource_mismatch)?)
        .map_err(|_| engine_resource_mismatch())?;
    catalog
        .validate_partial_local_import(
            role,
            &LiveImageEvidence {
                image_id: image.id.as_deref().ok_or_else(engine_resource_mismatch)?,
                operating_system: image.os.as_deref().ok_or_else(engine_resource_mismatch)?,
                architecture: image
                    .architecture
                    .as_deref()
                    .ok_or_else(engine_resource_mismatch)?,
                config: &config,
                repository_tags: image.repo_tags.as_deref(),
                repository_digests: image.repo_digests.as_deref(),
            },
        )
        .map_err(|_| engine_resource_mismatch())
}

#[async_trait::async_trait]
trait VolumeGuardDriver: Sync {
    async fn guard_verify(&self) -> Result<(), LocalInitError>;
    async fn guard_inspect(
        &self,
        name: &str,
    ) -> Result<Option<bollard::models::Volume>, LocalInitError>;
    async fn guard_attachments(&self, name: &str) -> Result<Vec<String>, LocalInitError>;
    async fn guard_create_untrusted(&self, name: &str, labels: &BTreeMap<String, String>);
}

#[async_trait::async_trait]
impl VolumeGuardDriver for InitEngine<'_> {
    async fn guard_verify(&self) -> Result<(), LocalInitError> {
        self.verify_selected_engine().await
    }

    async fn guard_inspect(
        &self,
        name: &str,
    ) -> Result<Option<bollard::models::Volume>, LocalInitError> {
        self.inspect_volume(name).await
    }

    async fn guard_attachments(&self, name: &str) -> Result<Vec<String>, LocalInitError> {
        self.volume_attachments(name).await
    }

    async fn guard_create_untrusted(&self, name: &str, labels: &BTreeMap<String, String>) {
        let request = VolumeCreateRequest {
            name: Some(name.to_owned()),
            driver: Some("local".to_owned()),
            driver_opts: Some(HashMap::new()),
            labels: Some(labels.clone().into_iter().collect()),
            cluster_volume_spec: None,
        };
        let _untrusted =
            tokio::time::timeout(ENGINE_TIMEOUT, self.docker.create_volume(request)).await;
    }
}

async fn elect_desired_guard_with_driver<D: VolumeGuardDriver>(
    driver: &D,
    name: &str,
    labels: &BTreeMap<String, String>,
    expected_attachment: Option<&str>,
    allow_create: bool,
    cancellation: &CancellationToken,
) -> Result<(), LocalInitError> {
    if expected_attachment.is_some_and(|id| !exact_container_id_text(id)) {
        return Err(engine_resource_mismatch());
    }
    cancellation_checkpoint(cancellation)?;
    driver.guard_verify().await?;
    cancellation_checkpoint(cancellation)?;
    if driver.guard_inspect(name).await?.is_none() {
        cancellation_checkpoint(cancellation)?;
        if !allow_create || expected_attachment.is_some() {
            return Err(engine_resource_mismatch());
        }
        create_volume_after_preflight(driver, name, labels, cancellation).await?;
        driver.guard_verify().await?;
    }
    let guard = driver
        .guard_inspect(name)
        .await?
        .ok_or_else(engine_resource_mismatch)?;
    validate_volume(&guard, name, labels)?;
    let attachments = driver.guard_attachments(name).await?;
    if match expected_attachment {
        Some(expected) => attachments.as_slice() != [expected],
        None => !attachments.is_empty(),
    } {
        return Err(engine_resource_mismatch());
    }
    driver.guard_verify().await?;
    cancellation_checkpoint(cancellation)
}

async fn guard_then_recover<G, F, R>(guard: G, recover: F) -> Result<(), LocalInitError>
where
    G: Future<Output = Result<(), LocalInitError>>,
    F: FnOnce() -> R,
    R: Future<Output = Result<(), LocalInitError>>,
{
    guard.await?;
    recover().await
}

async fn create_volume_after_preflight<D: VolumeGuardDriver>(
    driver: &D,
    name: &str,
    labels: &BTreeMap<String, String>,
    cancellation: &CancellationToken,
) -> Result<(), LocalInitError> {
    driver.guard_verify().await?;
    mutation_after_cancellation_checkpoint(cancellation, || async {
        driver.guard_create_untrusted(name, labels).await;
        Ok(())
    })
    .await
}

struct HelperContract<'a> {
    name: String,
    image: &'a str,
    image_id: &'a str,
    volumes: &'a BTreeMap<VolumeRole, String>,
    labels: BTreeMap<String, String>,
    volume_labels: BTreeMap<VolumeRole, BTreeMap<String, String>>,
}

struct HelperCreateResult {
    id: String,
    warnings: Vec<String>,
}

struct HelperWaitResult {
    status_code: i64,
    has_error: bool,
}

type HelperInput = Pin<Box<dyn AsyncWrite + Send>>;

#[async_trait::async_trait]
trait HelperDriver: Sync {
    async fn driver_verify(&self) -> Result<(), LocalInitError>;
    async fn driver_create(
        &self,
        name: &str,
        body: ContainerCreateBody,
    ) -> Result<HelperCreateResult, LocalInitError>;
    async fn driver_inspect(
        &self,
        target: &str,
    ) -> Result<Option<bollard::models::ContainerInspectResponse>, LocalInitError>;
    async fn driver_inspect_volume(
        &self,
        name: &str,
    ) -> Result<Option<bollard::models::Volume>, LocalInitError>;
    async fn driver_attach(&self, id: &str) -> Result<HelperInput, LocalInitError>;
    async fn driver_start(&self, id: &str) -> Result<(), LocalInitError>;
    async fn driver_send_request(
        &self,
        input: &mut HelperInput,
        request: &[u8],
    ) -> Result<(), LocalInitError>;
    async fn driver_wait(&self, id: &str) -> Result<HelperWaitResult, LocalInitError>;
    async fn driver_logs(&self, id: &str) -> Result<(Vec<u8>, Vec<u8>), LocalInitError>;
    async fn driver_force_remove(&self, id: &str) -> Result<(), LocalInitError>;
    async fn driver_volume_attachments(&self, name: &str) -> Result<Vec<String>, LocalInitError>;
}

#[async_trait::async_trait]
impl HelperDriver for InitEngine<'_> {
    async fn driver_verify(&self) -> Result<(), LocalInitError> {
        self.verify_selected_engine().await
    }

    async fn driver_create(
        &self,
        name: &str,
        body: ContainerCreateBody,
    ) -> Result<HelperCreateResult, LocalInitError> {
        let options = CreateContainerOptionsBuilder::default()
            .name(name)
            .platform("linux/amd64")
            .build();
        let created = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.create_container(Some(options), body),
        )
        .await
        .map_err(|_| materialization_failed())?
        .map_err(|_| materialization_failed())?;
        Ok(HelperCreateResult {
            id: created.id,
            warnings: created.warnings,
        })
    }

    async fn driver_inspect(
        &self,
        target: &str,
    ) -> Result<Option<bollard::models::ContainerInspectResponse>, LocalInitError> {
        self.inspect_container(target).await
    }

    async fn driver_inspect_volume(
        &self,
        name: &str,
    ) -> Result<Option<bollard::models::Volume>, LocalInitError> {
        self.inspect_volume(name).await
    }

    async fn driver_attach(&self, id: &str) -> Result<HelperInput, LocalInitError> {
        let options = AttachContainerOptionsBuilder::default()
            .stdin(true)
            .stdout(false)
            .stderr(false)
            .stream(true)
            .logs(false)
            .build();
        let AttachContainerResults {
            output: _output,
            input,
        } = tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.attach_container(id, Some(options)),
        )
        .await
        .map_err(|_| materialization_failed())?
        .map_err(|_| materialization_failed())?;
        Ok(input)
    }

    async fn driver_start(&self, id: &str) -> Result<(), LocalInitError> {
        tokio::time::timeout(ENGINE_TIMEOUT, self.docker.start_container(id, None))
            .await
            .map_err(|_| materialization_failed())?
            .map_err(|_| materialization_failed())
    }

    async fn driver_send_request(
        &self,
        input: &mut HelperInput,
        request: &[u8],
    ) -> Result<(), LocalInitError> {
        tokio::time::timeout(ENGINE_TIMEOUT, async {
            input.write_all(request).await?;
            input.flush().await?;
            input.shutdown().await
        })
        .await
        .map_err(|_| materialization_failed())?
        .map_err(|_| materialization_failed())
    }

    async fn driver_wait(&self, id: &str) -> Result<HelperWaitResult, LocalInitError> {
        let mut wait_stream = self.docker.wait_container(
            id,
            Some(
                WaitContainerOptionsBuilder::default()
                    .condition("not-running")
                    .build(),
            ),
        );
        let result = tokio::time::timeout(HELPER_TIMEOUT, async {
            let result = wait_stream
                .next()
                .await
                .ok_or_else(materialization_failed)?
                .map_err(|_| materialization_failed())?;
            if wait_stream.next().await.is_some() {
                return Err(materialization_failed());
            }
            Ok(result)
        })
        .await
        .map_err(|_| materialization_failed())??;
        Ok(HelperWaitResult {
            status_code: result.status_code,
            has_error: result.error.is_some(),
        })
    }

    async fn driver_logs(&self, id: &str) -> Result<(Vec<u8>, Vec<u8>), LocalInitError> {
        self.helper_logs(id).await
    }

    async fn driver_force_remove(&self, id: &str) -> Result<(), LocalInitError> {
        self.verify_selected_engine().await?;
        let options = RemoveContainerOptionsBuilder::default()
            .force(true)
            .v(false)
            .link(false)
            .build();
        match tokio::time::timeout(
            ENGINE_TIMEOUT,
            self.docker.remove_container(id, Some(options)),
        )
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) if not_found(&error) => Ok(()),
            _ => Err(materialization_failed()),
        }
    }

    async fn driver_volume_attachments(&self, name: &str) -> Result<Vec<String>, LocalInitError> {
        self.volume_attachments(name).await
    }
}

async fn run_materializer_with_driver<D: HelperDriver>(
    driver: &D,
    contract: &HelperContract<'_>,
    request: &MaterializeRequest,
    epoch_fingerprint: Sha256Digest,
    cancellation: &CancellationToken,
) -> Result<(), LocalInitError> {
    let request_bytes = Zeroizing::new(request.canonical_bytes()?);
    driver.driver_verify().await?;
    cancellation_checkpoint(cancellation)?;
    let created = driver
        .driver_create(
            &contract.name,
            helper_body(contract.image, contract.volumes, &contract.labels),
        )
        .await;
    let pinned_id = created
        .as_ref()
        .ok()
        .filter(|created| exact_container_id_text(&created.id))
        .map(|created| created.id.clone());
    let operation = async {
        let created = created?;
        if !exact_container_id_text(&created.id) || !created.warnings.is_empty() {
            return Err(materialization_failed());
        }
        cancellation_checkpoint(cancellation)?;
        driver.driver_verify().await?;
        attest_helper_target(driver, contract, &created.id, false).await?;
        cancellation_checkpoint(cancellation)?;
        let mut input = driver.driver_attach(&created.id).await?;
        cancellation_checkpoint(cancellation)?;
        driver.driver_verify().await?;
        attest_helper_target(driver, contract, &created.id, false).await?;
        cancellation_checkpoint(cancellation)?;
        driver.driver_start(&created.id).await?;
        cancellation_checkpoint(cancellation)?;
        driver.driver_verify().await?;
        attest_helper_target(driver, contract, &created.id, true).await?;
        cancellation_checkpoint(cancellation)?;
        driver
            .driver_send_request(&mut input, request_bytes.as_slice())
            .await?;
        drop(input);
        cancellation_checkpoint(cancellation)?;
        let wait = driver.driver_wait(&created.id).await?;
        cancellation_checkpoint(cancellation)?;
        if wait.status_code != 0 || wait.has_error {
            return Err(materialization_failed());
        }
        driver.driver_verify().await?;
        let (stdout, stderr) = driver.driver_logs(&created.id).await?;
        validate_response(&stdout, &stderr, epoch_fingerprint)?;
        cancellation_checkpoint(cancellation)?;
        attest_helper_target(driver, contract, &created.id, false).await?;
        Ok(())
    }
    .await;
    let cleanup = cleanup_helper(driver, contract, pinned_id.as_deref()).await;
    match cleanup {
        Err(error) => Err(error),
        Ok(()) => operation,
    }
}

async fn attest_helper_target<D: HelperDriver>(
    driver: &D,
    contract: &HelperContract<'_>,
    pinned_id: &str,
    running: bool,
) -> Result<(), LocalInitError> {
    let by_id = driver
        .driver_inspect(pinned_id)
        .await?
        .ok_or_else(materialization_failed)?;
    validate_helper(
        &by_id,
        pinned_id,
        &contract.name,
        contract.image,
        contract.image_id,
        contract.volumes,
        &contract.labels,
    )?;
    validate_helper_running(&by_id, running)?;
    let by_name = driver
        .driver_inspect(&contract.name)
        .await?
        .ok_or_else(materialization_failed)?;
    validate_helper(
        &by_name,
        pinned_id,
        &contract.name,
        contract.image,
        contract.image_id,
        contract.volumes,
        &contract.labels,
    )?;
    validate_helper_running(&by_name, running)?;
    attest_helper_volumes(driver, contract, pinned_id).await
}

async fn attest_helper_volumes<D: HelperDriver>(
    driver: &D,
    contract: &HelperContract<'_>,
    pinned_id: &str,
) -> Result<(), LocalInitError> {
    for (role, name) in contract.volumes {
        let volume = driver
            .driver_inspect_volume(name)
            .await?
            .ok_or_else(materialization_failed)?;
        let labels = contract
            .volume_labels
            .get(role)
            .ok_or_else(materialization_failed)?;
        validate_volume(&volume, name, labels).map_err(|_| materialization_failed())?;
        let attachments = driver.driver_volume_attachments(name).await?;
        if attachments.as_slice() != [pinned_id] {
            return Err(materialization_failed());
        }
    }
    Ok(())
}

fn validate_helper_running(
    container: &bollard::models::ContainerInspectResponse,
    running: bool,
) -> Result<(), LocalInitError> {
    if container.state.as_ref().and_then(|state| state.running) != Some(running) {
        return Err(materialization_failed());
    }
    Ok(())
}

async fn cleanup_helper<D: HelperDriver>(
    driver: &D,
    contract: &HelperContract<'_>,
    pinned_id: Option<&str>,
) -> Result<(), LocalInitError> {
    driver.driver_verify().await?;
    let pinned_id = if let Some(pinned_id) = pinned_id {
        if !exact_container_id_text(pinned_id) {
            return Err(materialization_failed());
        }
        pinned_id.to_owned()
    } else {
        let Some(by_name) = driver.driver_inspect(&contract.name).await? else {
            verify_helper_absence(driver, contract, None).await?;
            return driver.driver_verify().await;
        };
        let id = exact_container_id(&by_name)?.to_owned();
        validate_helper(
            &by_name,
            &id,
            &contract.name,
            contract.image,
            contract.image_id,
            contract.volumes,
            &contract.labels,
        )?;
        let by_id = driver
            .driver_inspect(&id)
            .await?
            .ok_or_else(materialization_failed)?;
        validate_helper(
            &by_id,
            &id,
            &contract.name,
            contract.image,
            contract.image_id,
            contract.volumes,
            &contract.labels,
        )?;
        id
    };

    let mut cleanup_failure = None;
    match driver.driver_inspect(&pinned_id).await {
        Ok(Some(container)) => {
            if let Err(error) = validate_helper(
                &container,
                &pinned_id,
                &contract.name,
                contract.image,
                contract.image_id,
                contract.volumes,
                &contract.labels,
            ) {
                cleanup_failure = Some(error);
            }
        }
        Ok(None) => {}
        Err(error) => cleanup_failure = Some(error),
    }
    if let Err(error) = driver.driver_force_remove(&pinned_id).await {
        cleanup_failure.get_or_insert(error);
    }
    if let Err(error) = driver.driver_verify().await {
        cleanup_failure.get_or_insert(error);
    }
    if let Err(error) = verify_helper_absence(driver, contract, Some(&pinned_id)).await {
        cleanup_failure.get_or_insert(error);
    }
    if let Err(error) = driver.driver_verify().await {
        cleanup_failure.get_or_insert(error);
    }
    cleanup_failure.map_or(Ok(()), Err)
}

async fn verify_helper_absence<D: HelperDriver>(
    driver: &D,
    contract: &HelperContract<'_>,
    pinned_id: Option<&str>,
) -> Result<(), LocalInitError> {
    if let Some(pinned_id) = pinned_id
        && driver.driver_inspect(pinned_id).await?.is_some()
    {
        return Err(materialization_failed());
    }
    if driver.driver_inspect(&contract.name).await?.is_some() {
        return Err(materialization_failed());
    }
    for name in contract.volumes.values() {
        if !driver.driver_volume_attachments(name).await?.is_empty() {
            return Err(materialization_failed());
        }
    }
    Ok(())
}

async fn cancellation_checkpointed<Items, Item, Output, Operation, OperationFuture>(
    cancellation: &CancellationToken,
    items: Items,
    mut operation: Operation,
) -> Result<Vec<Output>, LocalInitError>
where
    Items: IntoIterator<Item = Item>,
    Operation: FnMut(Item) -> OperationFuture,
    OperationFuture: Future<Output = Result<Output, LocalInitError>>,
{
    let mut outputs = Vec::new();
    for item in items {
        cancellation_checkpoint(cancellation)?;
        outputs.push(operation(item).await?);
        cancellation_checkpoint(cancellation)?;
    }
    Ok(outputs)
}

async fn mutation_after_cancellation_checkpoint<Output, Operation, OperationFuture>(
    cancellation: &CancellationToken,
    operation: Operation,
) -> Result<Output, LocalInitError>
where
    Operation: FnOnce() -> OperationFuture,
    OperationFuture: Future<Output = Result<Output, LocalInitError>>,
{
    cancellation_checkpoint(cancellation)?;
    operation().await
}

fn cancellation_checkpoint(cancellation: &CancellationToken) -> Result<(), LocalInitError> {
    if cancellation.is_cancelled() {
        Err(LocalInitError::new(LocalInitErrorCode::Cancelled))
    } else {
        Ok(())
    }
}

fn exact_container_id(
    container: &bollard::models::ContainerInspectResponse,
) -> Result<&str, LocalInitError> {
    container
        .id
        .as_deref()
        .filter(|id| exact_container_id_text(id))
        .ok_or_else(materialization_failed)
}

fn exact_container_id_text(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn volume_names(installation: &Installation) -> BTreeMap<VolumeRole, String> {
    VolumeRole::ALL
        .into_iter()
        .map(|role| {
            (
                role,
                volume_name(installation.compose_project().as_str(), role),
            )
        })
        .collect()
}

pub(super) fn volume_name(compose_project: &str, role: VolumeRole) -> String {
    format!("{compose_project}-{}", role.name())
}

fn volume_labels(
    installation: &Installation,
    epoch_fingerprint: Sha256Digest,
    role: VolumeRole,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("io.automata.local.managed".to_owned(), "true".to_owned()),
        (
            "io.automata.local.material-schema".to_owned(),
            MATERIAL_SCHEMA.to_owned(),
        ),
        (
            "io.automata.local.generation".to_owned(),
            MATERIAL_GENERATION.to_owned(),
        ),
        (
            "io.automata.local.installation-id".to_owned(),
            installation.id().to_string(),
        ),
        (
            "io.automata.local.installation-key".to_owned(),
            installation.selector_key().to_string(),
        ),
        (
            "io.automata.local.compose-project".to_owned(),
            installation.compose_project().to_string(),
        ),
        (
            "io.automata.local.epoch-fingerprint".to_owned(),
            epoch_fingerprint.to_string(),
        ),
        (
            "io.automata.local.resource-kind".to_owned(),
            "persistent-volume".to_owned(),
        ),
        (
            "io.automata.local.volume-role".to_owned(),
            role.name().to_owned(),
        ),
    ])
}

fn expected_volume_labels(
    installation: &Installation,
    epoch_fingerprint: Sha256Digest,
) -> BTreeMap<VolumeRole, BTreeMap<String, String>> {
    VolumeRole::ALL
        .into_iter()
        .map(|role| (role, volume_labels(installation, epoch_fingerprint, role)))
        .collect()
}

fn validate_volume(
    volume: &bollard::models::Volume,
    name: &str,
    labels: &BTreeMap<String, String>,
) -> Result<(), LocalInitError> {
    let actual_labels = volume
        .labels
        .iter()
        .filter(|(key, _)| key.starts_with(MANAGED_PREFIX))
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect::<BTreeMap<_, _>>();
    let expected_labels = labels
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect::<BTreeMap<_, _>>();
    let expected_project = labels
        .get(MANAGED_PROJECT_LABEL)
        .ok_or_else(engine_resource_mismatch)?;
    if volume.name != name
        || volume.driver != "local"
        || volume.scope.as_ref().map(ToString::to_string).as_deref() != Some("local")
        || !volume.options.is_empty()
        || actual_labels != expected_labels
        || volume
            .labels
            .get(COMPOSE_PROJECT_LABEL)
            .is_some_and(|project| project != expected_project)
    {
        return Err(engine_resource_mismatch());
    }
    Ok(())
}

fn helper_name(installation: &Installation) -> String {
    format!("{}-init-materializer", installation.compose_project())
}

fn helper_labels(
    installation: &Installation,
    epoch_fingerprint: Sha256Digest,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("io.automata.local.managed".to_owned(), "true".to_owned()),
        (
            "io.automata.local.installation-id".to_owned(),
            installation.id().to_string(),
        ),
        (
            "io.automata.local.installation-key".to_owned(),
            installation.selector_key().to_string(),
        ),
        (
            "io.automata.local.compose-project".to_owned(),
            installation.compose_project().to_string(),
        ),
        (
            "io.automata.local.epoch-fingerprint".to_owned(),
            epoch_fingerprint.to_string(),
        ),
        (
            "io.automata.local.resource-kind".to_owned(),
            HELPER_KIND.to_owned(),
        ),
    ])
}

fn helper_body(
    image: &str,
    volumes: &BTreeMap<VolumeRole, String>,
    labels: &BTreeMap<String, String>,
) -> ContainerCreateBody {
    let mounts = helper_mounts(volumes);
    ContainerCreateBody {
        user: Some("0:0".to_owned()),
        attach_stdin: Some(true),
        attach_stdout: Some(false),
        attach_stderr: Some(false),
        tty: Some(false),
        open_stdin: Some(true),
        stdin_once: Some(true),
        env: Some(Vec::new()),
        cmd: Some(vec![
            "internal".to_owned(),
            "local".to_owned(),
            "materialize".to_owned(),
        ]),
        image: Some(image.to_owned()),
        working_dir: Some("/".to_owned()),
        entrypoint: Some(vec!["/usr/local/bin/automata".to_owned()]),
        network_disabled: Some(true),
        labels: Some(labels.clone().into_iter().collect()),
        stop_signal: Some("SIGKILL".to_owned()),
        stop_timeout: Some(0),
        host_config: Some(HostConfig {
            memory: Some(HELPER_MEMORY_BYTES),
            memory_swap: Some(HELPER_MEMORY_BYTES),
            nano_cpus: Some(HELPER_NANO_CPUS),
            pids_limit: Some(HELPER_PIDS),
            init: Some(false),
            mounts: Some(mounts),
            cap_add: Some(vec!["CHOWN".to_owned(), "DAC_OVERRIDE".to_owned()]),
            cap_drop: Some(vec!["ALL".to_owned()]),
            network_mode: Some("none".to_owned()),
            restart_policy: Some(RestartPolicy {
                name: Some(RestartPolicyNameEnum::NO),
                maximum_retry_count: Some(0),
            }),
            auto_remove: Some(false),
            cgroupns_mode: Some(HostConfigCgroupnsModeEnum::PRIVATE),
            ipc_mode: Some("private".to_owned()),
            readonly_rootfs: Some(true),
            security_opt: Some(helper_security_options()),
            masked_paths: Some(helper_masked_paths()),
            readonly_paths: Some(helper_readonly_paths()),
            log_config: Some(helper_log_config()),
            runtime: Some("runc".to_owned()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn helper_mounts(volumes: &BTreeMap<VolumeRole, String>) -> Vec<Mount> {
    volumes
        .iter()
        .map(|(role, name)| Mount {
            target: Some(role.mount_target()),
            source: Some(name.clone()),
            typ: Some(MountType::VOLUME),
            read_only: Some(false),
            volume_options: Some(MountVolumeOptions {
                no_copy: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        })
        .collect()
}

fn helper_security_options() -> Vec<String> {
    vec![
        "no-new-privileges=true".to_owned(),
        "seccomp=builtin".to_owned(),
    ]
}

fn helper_masked_paths() -> Vec<String> {
    [
        "/proc/acpi",
        "/proc/asound",
        "/proc/interrupts",
        "/proc/kcore",
        "/proc/keys",
        "/proc/latency_stats",
        "/proc/sched_debug",
        "/proc/scsi",
        "/proc/timer_list",
        "/proc/timer_stats",
        "/sys/devices/virtual/powercap",
        "/sys/firmware",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn helper_readonly_paths() -> Vec<String> {
    [
        "/proc/bus",
        "/proc/fs",
        "/proc/irq",
        "/proc/sys",
        "/proc/sysrq-trigger",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn helper_log_config() -> HostConfigLogConfig {
    HostConfigLogConfig {
        typ: Some("json-file".to_owned()),
        config: Some(HashMap::from([
            ("compress".to_owned(), "false".to_owned()),
            ("max-file".to_owned(), "1".to_owned()),
            ("max-size".to_owned(), "16k".to_owned()),
        ])),
    }
}

#[allow(clippy::too_many_lines)]
fn validate_helper(
    container: &bollard::models::ContainerInspectResponse,
    container_id: &str,
    name: &str,
    image: &str,
    image_id: &str,
    volumes: &BTreeMap<VolumeRole, String>,
    labels: &BTreeMap<String, String>,
) -> Result<(), LocalInitError> {
    let config = container
        .config
        .as_ref()
        .ok_or_else(materialization_failed)?;
    let host = container
        .host_config
        .as_ref()
        .ok_or_else(materialization_failed)?;
    let network = container
        .network_settings
        .as_ref()
        .ok_or_else(materialization_failed)?;
    let managed_labels = config
        .labels
        .as_ref()
        .into_iter()
        .flat_map(|labels| labels.iter())
        .filter(|(key, _)| key.starts_with(MANAGED_PREFIX))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let expected_project = labels
        .get(MANAGED_PROJECT_LABEL)
        .ok_or_else(materialization_failed)?;
    if container.id.as_deref() != Some(container_id)
        || !exact_container_id_text(container_id)
        || container.name.as_deref() != Some(format!("/{name}").as_str())
        || container.image.as_deref() != Some(image_id)
        || container.platform.as_deref() != Some("linux")
        || config.image.as_deref() != Some(image)
        || config
            .labels
            .as_ref()
            .and_then(|labels| labels.get(COMPOSE_PROJECT_LABEL))
            .is_some_and(|project| project != expected_project)
        || config.user.as_deref() != Some("0:0")
        || config.attach_stdout != Some(false)
        || config.attach_stderr != Some(false)
        || config.attach_stdin != Some(true)
        || config.tty != Some(false)
        || config.open_stdin != Some(true)
        || config.stdin_once != Some(true)
        || config.exposed_ports.as_deref() != Some([HELPER_EXPOSED_PORT.to_owned()].as_slice())
        || config.healthcheck.is_some()
        || config
            .volumes
            .as_ref()
            .is_some_and(|volumes| !volumes.is_empty())
        || config
            .on_build
            .as_ref()
            .is_some_and(|steps| !steps.is_empty())
        || config.shell.as_ref().is_some_and(|shell| !shell.is_empty())
        || config.entrypoint.as_deref() != Some(["/usr/local/bin/automata".to_owned()].as_slice())
        || config.cmd.as_deref()
            != Some(
                [
                    "internal".to_owned(),
                    "local".to_owned(),
                    "materialize".to_owned(),
                ]
                .as_slice(),
            )
        || config.env.as_ref().is_some_and(|env| !env.is_empty())
        || config.working_dir.as_deref() != Some("/")
        || config.network_disabled != Some(true)
        || config.stop_signal.as_deref() != Some("SIGKILL")
        || config.stop_timeout != Some(0)
        || managed_labels != *labels
        || host.network_mode.as_deref() != Some("none")
        || host.readonly_rootfs != Some(true)
        || host.privileged.unwrap_or(false)
        || host.auto_remove != Some(false)
        || helper_has_ambient_authority(host)
        || host.cap_drop.as_deref() != Some(["ALL".to_owned()].as_slice())
        || host.cap_add.as_deref()
            != Some(["CHOWN".to_owned(), "DAC_OVERRIDE".to_owned()].as_slice())
        || host.memory != Some(HELPER_MEMORY_BYTES)
        || host.memory_swap != Some(HELPER_MEMORY_BYTES)
        || host.nano_cpus != Some(HELPER_NANO_CPUS)
        || host.pids_limit != Some(HELPER_PIDS)
        || host.binds.as_ref().is_some_and(|binds| !binds.is_empty())
        || host.mounts.as_deref() != Some(helper_mounts(volumes).as_slice())
        || host.security_opt.as_deref() != Some(helper_security_options().as_slice())
        || host.masked_paths.as_deref() != Some(helper_masked_paths().as_slice())
        || host.readonly_paths.as_deref() != Some(helper_readonly_paths().as_slice())
        || host.tmpfs.as_ref().is_some_and(|tmpfs| !tmpfs.is_empty())
        || host.log_config.as_ref() != Some(&helper_log_config())
        || network.sandbox_id.as_deref() != Some("")
        || network.sandbox_key.as_deref() != Some("")
        || network.ports.as_ref().is_none_or(|ports| !ports.is_empty())
        || network.ports.is_none()
        || network
            .networks
            .as_ref()
            .is_none_or(|networks| !networks.is_empty())
        || network.networks.is_none()
    {
        return Err(materialization_failed());
    }
    let expected = volumes
        .iter()
        .map(|(role, name)| (name.clone(), role.mount_target()))
        .collect::<BTreeSet<_>>();
    let realized = container
        .mounts
        .as_deref()
        .ok_or_else(materialization_failed)?;
    let mut actual = BTreeSet::new();
    for mount in realized {
        match mount.typ.as_deref() {
            Some("volume") => {
                if mount.rw != Some(true) || mount.driver.as_deref() != Some("local") {
                    return Err(materialization_failed());
                }
                let pair = (
                    mount.name.clone().ok_or_else(materialization_failed)?,
                    mount
                        .destination
                        .clone()
                        .ok_or_else(materialization_failed)?,
                );
                if !actual.insert(pair) {
                    return Err(materialization_failed());
                }
            }
            _ => return Err(materialization_failed()),
        }
    }
    if actual != expected || actual.len() != volumes.len() {
        return Err(materialization_failed());
    }
    Ok(())
}

fn helper_has_ambient_authority(host: &HostConfig) -> bool {
    host.cgroup_parent
        .as_ref()
        .is_some_and(|value| !value.is_empty())
        || host.devices.as_ref().is_some_and(|value| !value.is_empty())
        || host
            .device_cgroup_rules
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || host
            .device_requests
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || host.init.unwrap_or(false)
        || host
            .container_id_file
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || host
            .port_bindings
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || host.publish_all_ports.unwrap_or(false)
        || host
            .volume_driver
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || host
            .volumes_from
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || host
            .annotations
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || host.cgroupns_mode != Some(HostConfigCgroupnsModeEnum::PRIVATE)
        || host.dns.as_ref().is_some_and(|value| !value.is_empty())
        || host
            .dns_options
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || host
            .dns_search
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || host
            .extra_hosts
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || host
            .group_add
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || host.ipc_mode.as_deref() != Some("private")
        || host.cgroup.as_ref().is_some_and(|value| !value.is_empty())
        || host.links.as_ref().is_some_and(|value| !value.is_empty())
        || host
            .pid_mode
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || host
            .storage_opt
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || host
            .uts_mode
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || host
            .userns_mode
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || host.sysctls.as_ref().is_some_and(|value| !value.is_empty())
        || host.runtime.as_deref() != Some("runc")
        || host.restart_policy.as_ref().is_none_or(|policy| {
            policy.name != Some(RestartPolicyNameEnum::NO) || policy.maximum_retry_count != Some(0)
        })
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MaterializeResponse {
    schema: String,
    epoch_fingerprint: Sha256Digest,
    sealed_static_volumes: u8,
}

fn validate_response(
    stdout: &[u8],
    stderr: &[u8],
    epoch_fingerprint: Sha256Digest,
) -> Result<(), LocalInitError> {
    let response: MaterializeResponse =
        serde_json::from_slice(stdout).map_err(|_| materialization_failed())?;
    let mut canonical = serde_json::to_vec(&response).map_err(|_| materialization_failed())?;
    canonical.push(b'\n');
    if !stderr.is_empty()
        || stdout != canonical
        || response.schema != RESPONSE_SCHEMA
        || response.epoch_fingerprint != epoch_fingerprint
        || response.sealed_static_volumes != 4
    {
        return Err(materialization_failed());
    }
    Ok(())
}

fn not_found(error: &BollardError) -> bool {
    matches!(
        error,
        BollardError::DockerResponseServerError {
            status_code: 404,
            ..
        }
    )
}

fn engine_unavailable() -> LocalInitError {
    LocalInitError::new(LocalInitErrorCode::EngineUnavailable)
}

fn engine_resource_mismatch() -> LocalInitError {
    LocalInitError::new(LocalInitErrorCode::EngineResourceMismatch)
}

fn materialization_failed() -> LocalInitError {
    LocalInitError::new(LocalInitErrorCode::MaterializationFailed)
}

#[cfg(test)]
mod tests;
