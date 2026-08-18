use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Cursor, Read as _},
    str::FromStr as _,
};

use automata_ci_core::Sha256Digest;
use automata_ci_execution::ImmutableImage;
use flate2::read::MultiGzDecoder;
use serde::{Deserialize, Serialize, de};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{LocalInitError, LocalInitErrorCode};

const CATALOG_SCHEMA: &str = "automata.local/release-catalog/v1";
const SOURCE_SCHEMA: &str = "automata.local/release-catalog-source/v1";
const SOURCE_SHA256: &str = "9c490bed48e90a18e7161a31ab7b1f085f7fabc609fe3f04127d5ea5d867d5eb";
const CANDIDATE_BASENAME: &str = "automata-service-proxy-candidate-x86_64-unknown-linux-musl.tar";
const CANDIDATE_PATH: &str = concat!(
    "target/service-proxy-publication/",
    "automata-service-proxy-candidate-x86_64-unknown-linux-musl.tar"
);
const CANDIDATE_IDENTITY: &str = "candidate-provenance.json";
const CANDIDATE_IMAGE: &str = "automata-service-proxy.oci.tar";
const CANDIDATE_IMAGE_NAME: &str = "ghcr.io/automata-ci/automata-service-proxy";
const CANDIDATE_SBOM: &str = "automata-ci-service-proxy.cdx.json";
const CANDIDATE_SOURCE: &str = "source-provenance.json";
const MAX_CATALOG_BYTES: usize = 1024 * 1024;
const MAX_CANDIDATE_BYTES: usize = 128 * 1024 * 1024;
const MAX_CANDIDATE_MEMBER_BYTES: usize = 128 * 1024 * 1024;
const MAX_DOCKER_LOAD_ARCHIVE_BYTES: usize = 128 * 1024 * 1024;
const MAX_OCI_MEMBERS: usize = 64;
const MAX_EXPANDED_LAYER_BYTES: usize = 64 * 1024 * 1024;
const MAX_EXPANDED_LAYER_MEMBER_BYTES: usize = 64 * 1024 * 1024;
const MAX_LAYER_ENTRIES: usize = 64;
const MAX_TAR_EPOCH: u64 = 8_589_934_591;
const MAX_TEXT_BYTES: usize = 512;
const OCI_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
const OCI_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
const OCI_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";
const OCI_GZIP_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const OCI_REFERENCE_ANNOTATION: &str = "org.opencontainers.image.ref.name";
const REGISTRY_ROLES: [&str; 6] = [
    "automata",
    "postgres",
    "profile",
    "runner",
    "rustfs",
    "sandbox-guest",
];
const RELEASE_REGISTRY_ROLES: [&str; 3] = ["automata", "runner", "sandbox-guest"];
const ALL_ROLES: [&str; 7] = [
    "automata",
    "postgres",
    "profile",
    "runner",
    "rustfs",
    "sandbox-guest",
    "service-proxy",
];

pub(super) fn current_source_contract_sha256() -> Sha256Digest {
    Sha256Digest::from_str(SOURCE_SHA256).expect("the compiled source-contract digest is valid")
}

#[derive(Clone, Debug)]
pub(super) struct VerifiedCatalog {
    bytes_sha256: Sha256Digest,
    source_contract_sha256: Sha256Digest,
    release: Release,
    profile: ProfileBinding,
    images: BTreeMap<String, VerifiedImage>,
    maximum_parallel_jobs: u16,
    human_port: u16,
    results_port: u16,
    runner_control_port: u16,
}

impl VerifiedCatalog {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, LocalInitError> {
        if bytes.is_empty() || bytes.len() > MAX_CATALOG_BYTES {
            return Err(invalid_catalog());
        }
        let value = parse_canonical_json(bytes)?;
        let raw: RawCatalog = serde_json::from_value(value).map_err(|_| invalid_catalog())?;
        if raw.schema != CATALOG_SCHEMA || raw.source_contract_sha256 != SOURCE_SHA256 {
            return Err(invalid_catalog());
        }
        validate_release(&raw.release)?;

        let source_bytes = include_bytes!("catalog-v1.source.json");
        if digest_hex(source_bytes) != SOURCE_SHA256 {
            return Err(invalid_catalog());
        }
        let source_value = parse_canonical_json(source_bytes)?;
        let source: RawSourceCatalog =
            serde_json::from_value(source_value).map_err(|_| invalid_catalog())?;
        if source.schema != SOURCE_SCHEMA
            || raw.lifecycle_runtime != source.lifecycle_runtime
            || raw.platform != source.platform
            || raw.scope != source.scope
            || raw.services != source.services
            || raw.platform
                != Value::Object(serde_json::Map::from_iter([
                    ("architecture".to_owned(), Value::String("amd64".to_owned())),
                    ("os".to_owned(), Value::String("linux".to_owned())),
                ]))
        {
            return Err(invalid_catalog());
        }
        validate_lifecycle_runtime(&source.lifecycle_runtime)?;
        validate_renderer_service_contracts(&source.images)?;
        validate_scope_and_services(&raw.scope, &raw.services)?;
        let profile = validate_profile(&raw.profile, &source.profile)?;

        if raw.images.len() != ALL_ROLES.len()
            || source.images.len() != ALL_ROLES.len()
            || raw.images.keys().map(String::as_str).collect::<Vec<_>>() != ALL_ROLES
            || source.images.keys().map(String::as_str).collect::<Vec<_>>() != ALL_ROLES
        {
            return Err(invalid_catalog());
        }

        let mut images = BTreeMap::new();
        for role in ALL_ROLES {
            let image = raw.images.get(role).ok_or_else(invalid_catalog)?;
            let expected = source.images.get(role).ok_or_else(invalid_catalog)?;
            if image.canonical_repository != expected.canonical_repository
                || image.config != expected.config
                || image.runtime != expected.runtime
                || !canonical_repository(&image.canonical_repository)
            {
                return Err(invalid_catalog());
            }
            let source = if role == "service-proxy" {
                validate_candidate_source(&image.source)?
            } else {
                validate_registry_source(role, &image.source, &expected.source)?
            };
            images.insert(
                role.to_owned(),
                VerifiedImage {
                    canonical_repository: image.canonical_repository.clone(),
                    config: image.config.clone(),
                    runtime: image.runtime.clone(),
                    source,
                },
            );
        }

        let runner = object(raw.services.get("runner").ok_or_else(invalid_catalog)?)?;
        let maximum_parallel_jobs = exact_u16(
            runner
                .get("maximum_parallel_jobs")
                .ok_or_else(invalid_catalog)?,
        )?;
        let ports = object(raw.services.get("ports").ok_or_else(invalid_catalog)?)?;
        Ok(Self {
            bytes_sha256: digest(bytes),
            source_contract_sha256: current_source_contract_sha256(),
            release: raw.release,
            profile,
            images,
            maximum_parallel_jobs,
            human_port: exact_u16(ports.get("human").ok_or_else(invalid_catalog)?)?,
            results_port: exact_u16(ports.get("results").ok_or_else(invalid_catalog)?)?,
            runner_control_port: exact_u16(
                ports.get("runner_control").ok_or_else(invalid_catalog)?,
            )?,
        })
    }

    pub(super) const fn digest(&self) -> Sha256Digest {
        self.bytes_sha256
    }

    pub(super) const fn source_contract_sha256(&self) -> Sha256Digest {
        self.source_contract_sha256
    }

    pub(super) const fn maximum_parallel_jobs(&self) -> u16 {
        self.maximum_parallel_jobs
    }

    pub(super) const fn human_port(&self) -> u16 {
        self.human_port
    }

    pub(super) const fn results_port(&self) -> u16 {
        self.results_port
    }

    pub(super) const fn runner_control_port(&self) -> u16 {
        self.runner_control_port
    }

    pub(super) const fn release(&self) -> &Release {
        &self.release
    }

    pub(super) const fn profile(&self) -> &ProfileBinding {
        &self.profile
    }

    pub(super) fn image(&self, role: &str) -> &VerifiedImage {
        self.images
            .get(role)
            .expect("the closed catalog always contains every role")
    }

    pub(super) fn immutable_image(&self, role: &str) -> ImmutableImage {
        assert!(
            self.is_registry_role(role),
            "only registry roles are immutable references"
        );
        ImmutableImage::new(self.image(role).inspection_reference())
            .expect("verified catalog references are canonical immutable images")
    }

    pub(super) fn imported_service_proxy(&self) -> crate::LocalImportedImage {
        let ImageSource::Candidate(binding) = &self.image("service-proxy").source else {
            unreachable!("the verified service-proxy role is always a local candidate")
        };
        crate::LocalImportedImage::new(binding.config_digest.clone(), binding.image_digest.clone())
            .expect("verified candidate identities form the closed local import contract")
    }

    pub(super) fn roles() -> impl Iterator<Item = &'static str> {
        ALL_ROLES.into_iter()
    }

    pub(super) fn is_registry_role(&self, role: &str) -> bool {
        matches!(self.image(role).source, ImageSource::Registry(_))
    }

    pub(super) fn validate_live_image(
        &self,
        role: &str,
        evidence: &LiveImageEvidence<'_>,
    ) -> Result<(), LocalInitError> {
        let image = self.image(role);
        if !image.accepts_live_id(evidence.image_id)
            || evidence.operating_system != "linux"
            || evidence.architecture != "amd64"
            || !image.accepts_live_references(
                evidence.image_id,
                evidence.repository_tags,
                evidence.repository_digests,
            )
        {
            return Err(invalid_catalog_payload());
        }
        let release = (RELEASE_REGISTRY_ROLES.contains(&role) || role == "service-proxy")
            .then_some(&self.release);
        validate_image_process(evidence.config, &image.config, release)
    }

    pub(super) fn validate_partial_local_import(
        &self,
        role: &str,
        evidence: &LiveImageEvidence<'_>,
    ) -> Result<(), LocalInitError> {
        let image = self.image(role);
        let ImageSource::Candidate(binding) = &image.source else {
            return Err(invalid_catalog_payload());
        };
        let expected_digest = format!("{}@{}", image.canonical_repository, binding.image_digest);
        let exact_references = evidence.repository_tags == Some(&[])
            && if evidence.image_id == binding.config_digest {
                evidence.repository_digests == Some(&[])
            } else if evidence.image_id == binding.image_digest {
                evidence.repository_digests == Some(std::slice::from_ref(&expected_digest))
            } else {
                false
            };
        if !exact_references
            || evidence.operating_system != "linux"
            || evidence.architecture != "amd64"
        {
            return Err(invalid_catalog_payload());
        }
        validate_image_process(evidence.config, &image.config, Some(&self.release))
    }

    pub(super) const fn candidate_basename() -> &'static str {
        CANDIDATE_BASENAME
    }

    pub(super) fn verify_candidate(&self, bytes: &[u8]) -> Result<Vec<u8>, LocalInitError> {
        if bytes.is_empty() || bytes.len() > MAX_CANDIDATE_BYTES {
            return Err(invalid_catalog_payload());
        }
        let ImageSource::Candidate(binding) = &self.image("service-proxy").source else {
            return Err(invalid_catalog());
        };
        if digest_hex(bytes) != binding.sha256 {
            return Err(invalid_catalog_payload());
        }
        let mut members = exact_tar_members(
            bytes,
            &[
                CANDIDATE_IDENTITY,
                CANDIDATE_IMAGE,
                CANDIDATE_SBOM,
                CANDIDATE_SOURCE,
            ],
            4,
        )?;
        let identity = members
            .remove(CANDIDATE_IDENTITY)
            .ok_or_else(invalid_catalog_payload)?;
        let oci = members
            .remove(CANDIDATE_IMAGE)
            .ok_or_else(invalid_catalog_payload)?;
        let sbom = members
            .remove(CANDIDATE_SBOM)
            .ok_or_else(invalid_catalog_payload)?;
        let source = members
            .remove(CANDIDATE_SOURCE)
            .ok_or_else(invalid_catalog_payload)?;
        if digest_hex(&identity) != binding.candidate_provenance_sha256
            || digest_hex(&oci) != binding.oci_archive_sha256
            || digest_hex(&source) != binding.source_provenance_sha256
        {
            return Err(invalid_catalog_payload());
        }
        let source_descriptor =
            validate_candidate_identity(&identity, &source, &sbom, binding, &self.release)?;
        validate_candidate_archive_metadata(bytes, source_descriptor.release.source_date_epoch)?;
        let load_archive = validate_candidate_oci(
            &oci,
            binding,
            self.image("service-proxy"),
            &self.release,
            &source_descriptor,
            &source,
            &sbom,
        )?;
        Ok(load_archive)
    }
}

fn validate_lifecycle_runtime(value: &Value) -> Result<(), LocalInitError> {
    let runtime = object(value)?;
    let commands = object(
        runtime
            .get("automata_commands")
            .ok_or_else(invalid_catalog)?,
    )?;
    let materialize = object(commands.get("materialize").ok_or_else(invalid_catalog)?)?;
    let control_ready = object(commands.get("check_ready").ok_or_else(invalid_catalog)?)?;
    let hold_lock = object(commands.get("hold_lock").ok_or_else(invalid_catalog)?)?;
    let read_cas_digest = object(
        commands
            .get("read_cas_digest")
            .ok_or_else(invalid_catalog)?,
    )?;
    let read_desired = object(commands.get("read_desired").ok_or_else(invalid_catalog)?)?;
    let write_cas = object(commands.get("write_cas").ok_or_else(invalid_catalog)?)?;
    let compose = object(runtime.get("compose").ok_or_else(invalid_catalog)?)?;
    let runner_commands = object(runtime.get("runner_commands").ok_or_else(invalid_catalog)?)?;
    let runner_ready = object(
        runner_commands
            .get("local_check_ready")
            .ok_or_else(invalid_catalog)?,
    )?;
    let minimum_compose = format!(
        "{}.{}.{}",
        crate::MIN_COMPOSE_VERSION.0,
        crate::MIN_COMPOSE_VERSION.1,
        crate::MIN_COMPOSE_VERSION.2
    );
    let results = object(runtime.get("results_transit").ok_or_else(invalid_catalog)?)?;
    if runtime.get("engine_relay") != Some(&crate::engine_relay::lifecycle_contract())
        || materialize.get("request_schema").and_then(Value::as_str)
            != Some(super::materializer::REQUEST_SCHEMA)
        || materialize
            .get("maximum_request_bytes")
            .and_then(Value::as_u64)
            != u64::try_from(super::materializer::MAX_REQUEST_BYTES).ok()
        || materialize.get("response_schema").and_then(Value::as_str)
            != Some(super::materializer::RESPONSE_SCHEMA)
        || read_desired.get("response_schema").and_then(Value::as_str)
            != Some(crate::desired_spec::DESIRED_SPEC_SCHEMA)
        || read_desired.get("maximum_bytes").and_then(Value::as_u64)
            != u64::try_from(crate::MAX_LOCAL_DESIRED_SPEC_BYTES).ok()
        || write_cas.get("request_schema").and_then(Value::as_str)
            != Some(crate::lifecycle_helper::CAS_SCHEMA)
        || write_cas
            .get("maximum_request_bytes")
            .and_then(Value::as_u64)
            != u64::try_from(crate::lifecycle_helper::MAX_CAS_REQUEST_BYTES).ok()
        || write_cas
            .get("maximum_content_bytes")
            .and_then(Value::as_u64)
            != u64::try_from(crate::lifecycle_helper::MAX_CAS_CONTENT_BYTES).ok()
        || control_ready.get("argv") != Some(&serde_json::json!(crate::LOCAL_CONTROL_READY_COMMAND))
        || control_ready.get("listen").and_then(Value::as_str)
            != Some(crate::LOCAL_CONTROL_READY_LISTEN)
        || control_ready
            .get("maximum_response_bytes")
            .and_then(Value::as_u64)
            != u64::try_from(crate::LOCAL_CONTROL_READY_MAXIMUM_RESPONSE_BYTES).ok()
        || control_ready.get("request").and_then(Value::as_str)
            != Some(crate::LOCAL_CONTROL_READY_REQUEST)
        || control_ready.get("response_prefix").and_then(Value::as_str)
            != Some(crate::LOCAL_CONTROL_READY_RESPONSE_PREFIX)
        || control_ready.get("response_suffix").and_then(Value::as_str)
            != Some(crate::LOCAL_CONTROL_READY_RESPONSE_SUFFIX)
        || control_ready.get("timeout_seconds").and_then(Value::as_u64)
            != Some(crate::LOCAL_CONTROL_READY_TIMEOUT_SECONDS)
        || hold_lock.get("argv")
            != Some(&serde_json::json!(
                crate::LOCAL_LIFECYCLE_LOCK_HOLDER_COMMAND
            ))
        || hold_lock.get("release").and_then(Value::as_str) != Some("stdin-eof")
        || read_cas_digest.get("argv")
            != Some(&serde_json::json!(["internal", "local", "read-cas-digest"]))
        || read_cas_digest.get("purpose").and_then(Value::as_str) != Some("expected-old-sha256")
        || compose.get("minimum_version").and_then(Value::as_str) != Some(&minimum_compose)
        || compose.get("named_volume_nocopy").and_then(Value::as_bool) != Some(true)
        || compose.get("project_directory").and_then(Value::as_str)
            != Some(super::compose::COMPOSE_PROJECT_DIRECTORY)
        || runner_ready.get("argv") != Some(&serde_json::json!([crate::LOCAL_RUNNER_READY_COMMAND]))
        || runner_ready.get("healthcheck_argv")
            != Some(&serde_json::json!([
                super::renderer::RUNNER_BINARY,
                crate::LOCAL_RUNNER_READY_COMMAND
            ]))
        || runner_ready.get("listen").and_then(Value::as_str)
            != Some(crate::LOCAL_RUNNER_READY_LISTEN)
        || runner_ready
            .get("maximum_response_bytes")
            .and_then(Value::as_u64)
            != u64::try_from(crate::LOCAL_RUNNER_READY_MAXIMUM_RESPONSE_BYTES).ok()
        || runner_ready.get("path").and_then(Value::as_str) != Some(crate::LOCAL_RUNNER_READY_PATH)
        || runner_ready.get("protocol").and_then(Value::as_str)
            != Some(crate::LOCAL_RUNNER_READY_PROTOCOL)
        || runner_ready.get("required_metrics")
            != Some(&serde_json::json!([
                crate::LOCAL_RUNNER_READY_METRIC,
                crate::LOCAL_RUNNER_SESSION_CONNECTED_METRIC
            ]))
        || runner_ready.get("timeout_seconds").and_then(Value::as_u64)
            != Some(crate::LOCAL_RUNNER_READY_TIMEOUT_SECONDS)
        || results.get("schema").and_then(Value::as_u64)
            != crate::local_docker::RESULTS_TRANSPORT_SCHEMA.parse().ok()
        || results.get("ownership").and_then(Value::as_str)
            != Some(crate::results_transport::RESULTS_TRANSPORT_OWNERSHIP)
    {
        return Err(invalid_catalog());
    }
    Ok(())
}

fn validate_renderer_service_contracts(
    images: &BTreeMap<String, RawImage>,
) -> Result<(), LocalInitError> {
    let runner = images.get("runner").ok_or_else(invalid_catalog)?;
    let runner_runtime = object(&runner.runtime)?;
    if runner_runtime.get("binary").and_then(Value::as_str) != Some(super::renderer::RUNNER_BINARY)
        || runner_runtime.get("commands")
            != Some(&serde_json::json!([
                crate::LOCAL_RUNNER_READY_COMMAND,
                "enroll",
                "run"
            ]))
    {
        return Err(invalid_catalog());
    }
    let postgres = images.get("postgres").ok_or_else(invalid_catalog)?;
    let runtime = object(&postgres.runtime)?;
    let config = object(&postgres.config)?;
    let environment = object(
        config
            .get("required_environment")
            .ok_or_else(invalid_catalog)?,
    )?;
    let command = config
        .get("command")
        .and_then(Value::as_array)
        .ok_or_else(invalid_catalog)?;
    let postgres_user = format!(
        "{}:{}",
        runtime
            .get("container_uid")
            .and_then(Value::as_u64)
            .ok_or_else(invalid_catalog)?,
        runtime
            .get("container_gid")
            .and_then(Value::as_u64)
            .ok_or_else(invalid_catalog)?
    );
    if runtime.get("data_mount").and_then(Value::as_str)
        != Some(super::renderer::POSTGRES_DATA_MOUNT)
        || runtime.get("postgres").and_then(Value::as_str) != Some(super::renderer::POSTGRES_BINARY)
        || command.as_slice()
            != [Value::String(
                super::renderer::POSTGRES_LAUNCH_COMMAND.to_owned(),
            )]
        || runtime.get("container_uid").and_then(Value::as_u64) != Some(999)
        || runtime.get("container_gid").and_then(Value::as_u64) != Some(999)
        || runtime.get("preowned_uid").and_then(Value::as_u64) != Some(999)
        || runtime.get("preowned_gid").and_then(Value::as_u64) != Some(999)
        || postgres_user != super::renderer::POSTGRES_USER
        || runtime.get("read_only_root").and_then(Value::as_bool) != Some(true)
        || runtime.get("cap_drop") != Some(&serde_json::json!(["ALL"]))
        || runtime.get("security_opt") != Some(&serde_json::json!(["no-new-privileges:true"]))
        || runtime.get("tmpfs") != Some(&serde_json::json!(super::renderer::POSTGRES_TMPFS))
        || runtime.get("pg_isready").and_then(Value::as_str)
            != Some(super::renderer::POSTGRES_READY_BINARY)
        || runtime.get("server_certificate").and_then(Value::as_str)
            != Some(super::renderer::POSTGRES_SERVER_CERTIFICATE)
        || runtime.get("server_private_key").and_then(Value::as_str)
            != Some(super::renderer::POSTGRES_SERVER_PRIVATE_KEY)
        || runtime
            .get("server_private_key_mode")
            .and_then(Value::as_str)
            != Some(format!("{:04o}", super::materializer::STATIC_FILE_MODE).as_str())
        || environment.get("PGDATA").and_then(Value::as_str)
            != Some(super::renderer::POSTGRES_PGDATA)
    {
        return Err(invalid_catalog());
    }
    let rustfs = images.get("rustfs").ok_or_else(invalid_catalog)?;
    let runtime = object(&rustfs.runtime)?;
    let rustfs_user = format!(
        "{}:{}",
        runtime
            .get("uid")
            .and_then(Value::as_u64)
            .ok_or_else(invalid_catalog)?,
        runtime
            .get("gid")
            .and_then(Value::as_u64)
            .ok_or_else(invalid_catalog)?
    );
    if runtime.get("entrypoint").and_then(Value::as_str) != Some(super::renderer::RUSTFS_ENTRYPOINT)
        || runtime.get("server").and_then(Value::as_str) != Some(super::renderer::RUSTFS_SERVER)
        || runtime.get("health_client").and_then(Value::as_str)
            != Some(super::renderer::RUSTFS_HEALTH_CLIENT)
        || runtime.get("shell").and_then(Value::as_str) != Some(super::renderer::RUSTFS_SHELL)
        || runtime.get("cat").and_then(Value::as_str) != Some(super::renderer::RUSTFS_CAT)
        || runtime.get("uid").and_then(Value::as_u64) != Some(10_001)
        || runtime.get("gid").and_then(Value::as_u64) != Some(10_001)
        || rustfs_user != super::renderer::RUSTFS_USER
        || runtime.get("read_only_root").and_then(Value::as_bool) != Some(true)
        || runtime.get("cap_drop") != Some(&serde_json::json!(["ALL"]))
        || runtime.get("security_opt") != Some(&serde_json::json!(["no-new-privileges:true"]))
        || runtime.get("tmpfs") != Some(&serde_json::json!(super::renderer::RUSTFS_TMPFS))
    {
        return Err(invalid_catalog());
    }
    Ok(())
}

pub(super) struct LiveImageEvidence<'a> {
    pub(super) image_id: &'a str,
    pub(super) operating_system: &'a str,
    pub(super) architecture: &'a str,
    pub(super) config: &'a Value,
    pub(super) repository_tags: Option<&'a [String]>,
    pub(super) repository_digests: Option<&'a [String]>,
}

#[derive(Clone, Debug)]
pub(super) struct ProfileBinding {
    pub(super) id: String,
    pub(super) manifest_sha256: Sha256Digest,
    pub(super) lock_sha256: Sha256Digest,
}

#[derive(Clone, Debug)]
pub(super) struct VerifiedImage {
    pub(super) canonical_repository: String,
    pub(super) config: Value,
    pub(super) runtime: Value,
    pub(super) source: ImageSource,
}

impl VerifiedImage {
    pub(super) fn source_reference(&self) -> &str {
        match &self.source {
            ImageSource::Registry(binding) => &binding.reference,
            ImageSource::Candidate(binding) => &binding.reference,
        }
    }

    pub(super) fn inspection_reference(&self) -> String {
        match &self.source {
            ImageSource::Registry(binding) => format!(
                "{}@{}",
                repository_from_reference(&binding.reference),
                binding.platform_manifest_digest
            ),
            ImageSource::Candidate(binding) => binding.local_reference(&self.canonical_repository),
        }
    }

    pub(super) fn local_import_collision_references(&self) -> Option<[String; 3]> {
        let ImageSource::Candidate(binding) = &self.source else {
            return None;
        };
        Some([
            format!("{}@{}", self.canonical_repository, binding.image_digest),
            binding.image_digest.clone(),
            binding.config_digest.clone(),
        ])
    }

    pub(super) fn accepts_live_id(&self, image_id: &str) -> bool {
        match &self.source {
            ImageSource::Registry(binding) => {
                image_id == binding.config_digest || image_id == binding.platform_manifest_digest
            }
            ImageSource::Candidate(binding) => {
                image_id == binding.config_digest || image_id == binding.image_digest
            }
        }
    }

    fn accepts_live_references(
        &self,
        image_id: &str,
        repository_tags: Option<&[String]>,
        repository_digests: Option<&[String]>,
    ) -> bool {
        let ImageSource::Candidate(binding) = &self.source else {
            return true;
        };
        let expected_tag = binding.local_reference(&self.canonical_repository);
        let expected_digest = format!("{}@{}", self.canonical_repository, binding.image_digest);
        if repository_tags != Some(std::slice::from_ref(&expected_tag)) {
            return false;
        }
        if image_id == binding.config_digest {
            repository_digests == Some(&[])
        } else if image_id == binding.image_digest {
            repository_digests == Some(std::slice::from_ref(&expected_digest))
        } else {
            false
        }
    }
}

impl CandidateBinding {
    pub(super) fn local_reference(&self, repository: &str) -> String {
        format!(
            "{repository}:manifest-{}",
            self.image_digest
                .strip_prefix("sha256:")
                .expect("verified candidate manifest digests are SHA-256")
        )
    }
}

#[derive(Clone, Debug)]
pub(super) enum ImageSource {
    Registry(RegistryBinding),
    Candidate(CandidateBinding),
}

#[derive(Clone, Debug)]
pub(super) struct RegistryBinding {
    pub(super) reference: String,
    pub(super) top_level_digest: String,
    pub(super) platform_manifest_digest: String,
    pub(super) config_digest: String,
}

#[derive(Clone, Debug)]
pub(super) struct CandidateBinding {
    pub(super) reference: String,
    pub(super) candidate_provenance_sha256: String,
    pub(super) config_digest: String,
    pub(super) image_digest: String,
    pub(super) image_name: String,
    pub(super) oci_archive_sha256: String,
    pub(super) sha256: String,
    pub(super) source_provenance_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Release {
    pub(super) commit: String,
    pub(super) created: String,
    pub(super) prerelease: bool,
    pub(super) source_date_epoch: u64,
    pub(super) tag: String,
    pub(super) tag_object: String,
    pub(super) version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCatalog {
    images: BTreeMap<String, RawImage>,
    lifecycle_runtime: Value,
    platform: Value,
    profile: Value,
    release: Release,
    schema: String,
    scope: Value,
    services: Value,
    source_contract_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSourceCatalog {
    images: BTreeMap<String, RawImage>,
    lifecycle_runtime: Value,
    platform: Value,
    profile: Value,
    schema: String,
    scope: Value,
    services: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawImage {
    canonical_repository: String,
    config: Value,
    runtime: Value,
    source: Value,
}

fn validate_release(release: &Release) -> Result<(), LocalInitError> {
    let canonical_created = canonical_rfc3339_seconds(&release.created);
    let created_epoch = OffsetDateTime::parse(&release.created, &Rfc3339)
        .ok()
        .and_then(|created| u64::try_from(created.unix_timestamp()).ok());
    if !git_object(&release.commit)
        || !git_object(&release.tag_object)
        || !canonical_created
        || created_epoch != Some(release.source_date_epoch)
        || release.source_date_epoch > MAX_TAR_EPOCH
        || !one_line(&release.tag)
        || !one_line(&release.version)
        || release.tag != format!("v{}", release.version)
    {
        return Err(invalid_catalog());
    }
    Ok(())
}

fn canonical_rfc3339_seconds(value: &str) -> bool {
    let bytes = value.as_bytes();
    let base = matches!(bytes.len(), 20 | 25)
        && bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && bytes.get(10) == Some(&b'T')
        && bytes.get(13) == Some(&b':')
        && bytes.get(16) == Some(&b':')
        && bytes[..19]
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7 | 10 | 13 | 16) || byte.is_ascii_digit());
    base && match bytes.len() {
        20 => bytes[19] == b'Z',
        25 => {
            matches!(bytes[19], b'+' | b'-')
                && bytes[22] == b':'
                && bytes[20..22].iter().all(u8::is_ascii_digit)
                && bytes[23..25].iter().all(u8::is_ascii_digit)
        }
        _ => false,
    }
}

fn validate_scope_and_services(scope: &Value, services: &Value) -> Result<(), LocalInitError> {
    if scope
        != &serde_json::json!({
            "engine": "linux/amd64",
            "host": "unix"
        })
    {
        return Err(invalid_catalog());
    }
    let services = object(services)?;
    let runner = object(services.get("runner").ok_or_else(invalid_catalog)?)?;
    let exact_runner = serde_json::json!({
        "executor": "github",
        "executor_contract": {
            "ephemeral_disk_bytes": 0,
            "minimum_cpu_millis": 1000,
            "minimum_memory_bytes": 268_435_456,
            "minimum_pids": 3,
            "network": "private_egress",
            "privilege": "administrator",
            "root_filesystem": "writable",
            "runner_root": "/__automata",
            "workspace": "/__w"
        },
        "maximum_parallel_jobs": 256,
        "profile_role": "profile",
        "provider": "local-docker",
        "provider_control_directory": "/automata-control",
        "sandbox_guest_role": "sandbox-guest",
        "service_proxy_role": "service-proxy"
    });
    if Value::Object(runner.clone()) != exact_runner {
        return Err(invalid_catalog());
    }
    Ok(())
}

fn validate_profile(value: &Value, source: &Value) -> Result<ProfileBinding, LocalInitError> {
    let value = object(value)?;
    let source = object(source)?;
    if value.len() != 5
        || value.get("compatibility_label") != source.get("compatibility_label")
        || value.get("id") != source.get("id")
        || value.get("image_role").and_then(Value::as_str) != Some("profile")
    {
        return Err(invalid_catalog());
    }
    let manifest = object(value.get("manifest").ok_or_else(invalid_catalog)?)?;
    let lock = object(value.get("lock").ok_or_else(invalid_catalog)?)?;
    let manifest_sha = source
        .get("manifest_sha256")
        .and_then(Value::as_str)
        .ok_or_else(invalid_catalog)?;
    let lock_sha = source
        .get("lock_sha256")
        .and_then(Value::as_str)
        .ok_or_else(invalid_catalog)?;
    if manifest.len() != 2
        || lock.len() != 2
        || manifest.get("path") != source.get("manifest_path")
        || lock.get("path") != source.get("lock_path")
        || manifest.get("sha256").and_then(Value::as_str) != Some(manifest_sha)
        || lock.get("sha256").and_then(Value::as_str) != Some(lock_sha)
    {
        return Err(invalid_catalog());
    }
    Ok(ProfileBinding {
        id: value
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(invalid_catalog)?
            .to_owned(),
        manifest_sha256: Sha256Digest::from_str(manifest_sha).map_err(|_| invalid_catalog())?,
        lock_sha256: Sha256Digest::from_str(lock_sha).map_err(|_| invalid_catalog())?,
    })
}

fn validate_registry_source(
    role: &str,
    value: &Value,
    source: &Value,
) -> Result<ImageSource, LocalInitError> {
    let value = object(value)?;
    let expected = BTreeSet::from([
        "config_digest",
        "kind",
        "platform_manifest_digest",
        "reference",
        "top_level_digest",
    ]);
    if value.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected
        || value.get("kind").and_then(Value::as_str) != Some("registry")
    {
        return Err(invalid_catalog());
    }
    let reference = line_field(value, "reference")?;
    let top_level_digest = line_field(value, "top_level_digest")?;
    let platform_manifest_digest = line_field(value, "platform_manifest_digest")?;
    let config_digest = line_field(value, "config_digest")?;
    if !canonical_registry_reference(reference, top_level_digest)
        || !oci_digest(top_level_digest)
        || !oci_digest(platform_manifest_digest)
        || !oci_digest(config_digest)
    {
        return Err(invalid_catalog());
    }
    let source = object(source)?;
    if RELEASE_REGISTRY_ROLES.contains(&role) {
        if source.get("kind").and_then(Value::as_str) != Some("release-registry")
            || source.get("repository").and_then(Value::as_str)
                != Some(repository_from_reference(reference))
        {
            return Err(invalid_catalog());
        }
    } else if !REGISTRY_ROLES.contains(&role)
        || source.get("kind").and_then(Value::as_str) != Some("registry")
        || source.get("reference").and_then(Value::as_str) != Some(reference)
        || source
            .get("platform_manifest_digest")
            .and_then(Value::as_str)
            != Some(platform_manifest_digest)
        || source.get("config_digest").and_then(Value::as_str) != Some(config_digest)
    {
        return Err(invalid_catalog());
    }
    Ok(ImageSource::Registry(RegistryBinding {
        reference: reference.to_owned(),
        top_level_digest: top_level_digest.to_owned(),
        platform_manifest_digest: platform_manifest_digest.to_owned(),
        config_digest: config_digest.to_owned(),
    }))
}

fn validate_candidate_source(value: &Value) -> Result<ImageSource, LocalInitError> {
    let value = object(value)?;
    let expected = BTreeSet::from([
        "candidate_provenance_sha256",
        "config_digest",
        "image_digest",
        "image_name",
        "kind",
        "oci_archive_sha256",
        "path",
        "sha256",
        "source_provenance_sha256",
    ]);
    if value.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected
        || value.get("kind").and_then(Value::as_str) != Some("release-candidate")
        || value.get("path").and_then(Value::as_str) != Some(CANDIDATE_PATH)
    {
        return Err(invalid_catalog());
    }
    let candidate_provenance_sha256 = line_field(value, "candidate_provenance_sha256")?;
    let config_digest = line_field(value, "config_digest")?;
    let image_digest = line_field(value, "image_digest")?;
    let image_name = line_field(value, "image_name")?;
    let oci_archive_sha256 = line_field(value, "oci_archive_sha256")?;
    let sha256 = line_field(value, "sha256")?;
    let source_provenance_sha256 = line_field(value, "source_provenance_sha256")?;
    if !sha256_hex(candidate_provenance_sha256)
        || !oci_digest(config_digest)
        || !oci_digest(image_digest)
        || image_name != CANDIDATE_IMAGE_NAME
        || !sha256_hex(oci_archive_sha256)
        || !sha256_hex(sha256)
        || !sha256_hex(source_provenance_sha256)
    {
        return Err(invalid_catalog());
    }
    let reference = format!("{image_name}@{image_digest}");
    if ImmutableImage::new(reference.clone()).is_err() {
        return Err(invalid_catalog());
    }
    Ok(ImageSource::Candidate(CandidateBinding {
        reference,
        candidate_provenance_sha256: candidate_provenance_sha256.to_owned(),
        config_digest: config_digest.to_owned(),
        image_digest: image_digest.to_owned(),
        image_name: image_name.to_owned(),
        oci_archive_sha256: oci_archive_sha256.to_owned(),
        sha256: sha256.to_owned(),
        source_provenance_sha256: source_provenance_sha256.to_owned(),
    }))
}

fn validate_candidate_identity(
    identity: &[u8],
    source: &[u8],
    sbom: &[u8],
    binding: &CandidateBinding,
    release: &Release,
) -> Result<CandidateSource, LocalInitError> {
    let identity: CandidateIdentity =
        serde_json::from_value(parse_canonical_payload_json(identity)?)
            .map_err(|_| invalid_catalog_payload())?;
    let source_descriptor: CandidateSource =
        serde_json::from_value(parse_canonical_payload_json(source)?)
            .map_err(|_| invalid_catalog_payload())?;
    if identity.schema_version != 1
        || source_descriptor.schema_version != 1
        || !sha256_hex(&source_descriptor.artifacts.binary_sha256)
        || !sha256_hex(&source_descriptor.artifacts.containerfile_sha256)
        || !sha256_hex(&source_descriptor.artifacts.sbom_sha256)
        || digest_hex(sbom) != source_descriptor.artifacts.sbom_sha256
        || identity.image.manifest_digest != binding.image_digest
        || identity.image.name != binding.image_name
        || identity.image.oci_archive_sha256 != binding.oci_archive_sha256
        || identity.image.source_provenance_sha256 != binding.source_provenance_sha256
        || identity.image.sbom_sha256 != source_descriptor.artifacts.sbom_sha256
        || identity.release != source_descriptor.release
        || source_descriptor.release.revision != release.commit
        || source_descriptor.release.created != release.created
        || source_descriptor.release.version != release.version
        || source_descriptor.release.source_date_epoch != release.source_date_epoch
    {
        return Err(invalid_catalog_payload());
    }
    validate_candidate_sbom(
        sbom,
        &source_descriptor.artifacts.binary_sha256,
        &source_descriptor.release.version,
    )?;
    Ok(source_descriptor)
}

#[derive(Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct CandidateRelease {
    created: String,
    revision: String,
    source_date_epoch: u64,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateSource {
    artifacts: CandidateArtifacts,
    release: CandidateRelease,
    schema_version: u8,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
struct CandidateArtifacts {
    binary_sha256: String,
    containerfile_sha256: String,
    sbom_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateIdentity {
    image: CandidateIdentityImage,
    release: CandidateRelease,
    schema_version: u8,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateIdentityImage {
    manifest_digest: String,
    name: String,
    oci_archive_sha256: String,
    sbom_sha256: String,
    source_provenance_sha256: String,
}

#[allow(clippy::too_many_lines)]
fn validate_candidate_oci(
    bytes: &[u8],
    binding: &CandidateBinding,
    image: &VerifiedImage,
    release: &Release,
    source: &CandidateSource,
    source_bytes: &[u8],
    sbom_bytes: &[u8],
) -> Result<Vec<u8>, LocalInitError> {
    let members = oci_tar_members(bytes, release.source_date_epoch)?;
    let layout = parse_json_member(&members, "oci-layout")?;
    let index = parse_canonical_payload_json(
        members
            .get("index.json")
            .ok_or_else(invalid_catalog_payload)?,
    )?;
    if layout
        != serde_json::json!({
            "imageLayoutVersion": "1.0.0"
        })
        || index
            .as_object()
            .map(|value| value.keys().map(String::as_str).collect::<BTreeSet<_>>())
            != Some(BTreeSet::from(["manifests", "mediaType", "schemaVersion"]))
        || index.get("schemaVersion").and_then(Value::as_u64) != Some(2)
        || index.get("mediaType").and_then(Value::as_str) != Some(OCI_INDEX_MEDIA_TYPE)
    {
        return Err(invalid_catalog_payload());
    }
    let manifests = index
        .get("manifests")
        .and_then(Value::as_array)
        .filter(|items| items.len() == 1)
        .ok_or_else(invalid_catalog_payload)?;
    let descriptor = manifests[0]
        .as_object()
        .ok_or_else(invalid_catalog_payload)?;
    let annotation = descriptor
        .get("annotations")
        .and_then(Value::as_object)
        .filter(|annotations| annotations.len() == 1)
        .and_then(|annotations| annotations.get(OCI_REFERENCE_ANNOTATION))
        .and_then(Value::as_str);
    let expected_annotation = format!(
        "{}:manifest-{}",
        image.canonical_repository,
        binding
            .image_digest
            .strip_prefix("sha256:")
            .ok_or_else(invalid_catalog_payload)?
    );
    if descriptor
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != BTreeSet::from(["annotations", "digest", "mediaType", "size"])
        || descriptor.get("digest").and_then(Value::as_str) != Some(binding.image_digest.as_str())
        || descriptor.get("mediaType").and_then(Value::as_str) != Some(OCI_MANIFEST_MEDIA_TYPE)
        || annotation != Some(expected_annotation.as_str())
    {
        return Err(invalid_catalog_payload());
    }
    let mut referenced = BTreeSet::from(["index.json".to_owned(), "oci-layout".to_owned()]);
    let manifest_bytes = descriptor_blob(&members, descriptor, &mut referenced)?;
    let manifest = parse_payload_json(manifest_bytes)?;
    let manifest = manifest.as_object().ok_or_else(invalid_catalog_payload)?;
    if manifest.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != BTreeSet::from(["config", "layers", "mediaType", "schemaVersion"])
        || manifest.get("schemaVersion").and_then(Value::as_u64) != Some(2)
        || manifest.get("mediaType").and_then(Value::as_str) != Some(OCI_MANIFEST_MEDIA_TYPE)
    {
        return Err(invalid_catalog_payload());
    }
    let config_descriptor = manifest
        .get("config")
        .and_then(Value::as_object)
        .ok_or_else(invalid_catalog_payload)?;
    if exact_descriptor_keys(config_descriptor)
        || config_descriptor.get("digest").and_then(Value::as_str)
            != Some(binding.config_digest.as_str())
        || config_descriptor.get("mediaType").and_then(Value::as_str) != Some(OCI_CONFIG_MEDIA_TYPE)
    {
        return Err(invalid_catalog_payload());
    }
    let config_bytes = descriptor_blob(&members, config_descriptor, &mut referenced)?;
    let layers = manifest
        .get("layers")
        .and_then(Value::as_array)
        .filter(|layers| !layers.is_empty() && layers.len() <= 32)
        .ok_or_else(invalid_catalog_payload)?;
    let mut layer_blobs = Vec::with_capacity(layers.len());
    for layer in layers {
        let descriptor = layer.as_object().ok_or_else(invalid_catalog_payload)?;
        let media_type = descriptor
            .get("mediaType")
            .and_then(Value::as_str)
            .ok_or_else(invalid_catalog_payload)?;
        if exact_descriptor_keys(descriptor)
            || !matches!(media_type, OCI_LAYER_MEDIA_TYPE | OCI_GZIP_LAYER_MEDIA_TYPE)
        {
            return Err(invalid_catalog_payload());
        }
        layer_blobs.push((
            media_type,
            descriptor_blob(&members, descriptor, &mut referenced)?,
        ));
    }
    if members.keys().cloned().collect::<BTreeSet<_>>() != referenced {
        return Err(invalid_catalog_payload());
    }
    let config = parse_payload_json(config_bytes)?;
    if config.get("architecture").and_then(Value::as_str) != Some("amd64")
        || config.get("os").and_then(Value::as_str) != Some("linux")
    {
        return Err(invalid_catalog_payload());
    }
    validate_candidate_process(
        config.get("config").ok_or_else(invalid_catalog_payload)?,
        image,
        source,
        source_bytes,
    )?;
    let rootfs = config
        .get("rootfs")
        .and_then(Value::as_object)
        .ok_or_else(invalid_catalog_payload)?;
    let diff_ids = rootfs
        .get("diff_ids")
        .and_then(Value::as_array)
        .filter(|items| items.len() == layer_blobs.len())
        .ok_or_else(invalid_catalog_payload)?;
    if rootfs.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != BTreeSet::from(["diff_ids", "type"])
        || rootfs.get("type").and_then(Value::as_str) != Some("layers")
    {
        return Err(invalid_catalog_payload());
    }
    let layers = validate_candidate_layers(&layer_blobs, diff_ids, release.source_date_epoch)?;
    validate_candidate_payload(&layers.payload, source, source_bytes, sbom_bytes)?;
    build_docker_load_archive(
        members,
        layers,
        binding,
        &expected_annotation,
        release.source_date_epoch,
        bytes.len(),
    )
}

fn exact_descriptor_keys(descriptor: &serde_json::Map<String, Value>) -> bool {
    descriptor
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != BTreeSet::from(["digest", "mediaType", "size"])
}

fn descriptor_blob<'a>(
    members: &'a BTreeMap<String, Vec<u8>>,
    descriptor: &serde_json::Map<String, Value>,
    referenced: &mut BTreeSet<String>,
) -> Result<&'a [u8], LocalInitError> {
    let digest = descriptor
        .get("digest")
        .and_then(Value::as_str)
        .filter(|digest| oci_digest(digest))
        .ok_or_else(invalid_catalog_payload)?;
    let expected_size = descriptor
        .get("size")
        .and_then(Value::as_u64)
        .and_then(|size| usize::try_from(size).ok())
        .ok_or_else(invalid_catalog_payload)?;
    let name = format!(
        "blobs/sha256/{}",
        digest
            .strip_prefix("sha256:")
            .ok_or_else(invalid_catalog_payload)?
    );
    let bytes = members.get(&name).ok_or_else(invalid_catalog_payload)?;
    if bytes.len() != expected_size || format!("sha256:{}", digest_hex(bytes)) != digest {
        return Err(invalid_catalog_payload());
    }
    if !referenced.insert(name) {
        return Err(invalid_catalog_payload());
    }
    Ok(bytes)
}

fn validate_candidate_process(
    actual: &Value,
    image: &VerifiedImage,
    source: &CandidateSource,
    source_bytes: &[u8],
) -> Result<(), LocalInitError> {
    validate_image_process(actual, &image.config, None)?;
    let expected_labels = serde_json::json!({
        "io.automata.service-proxy.binary.sha256": source.artifacts.binary_sha256,
        "io.automata.service-proxy.protocol-version": "2",
        "io.automata.service-proxy.sbom.sha256": source.artifacts.sbom_sha256,
        "io.automata.service-proxy.source.sha256": digest_hex(source_bytes),
        "org.opencontainers.image.created": source.release.created,
        "org.opencontainers.image.description": "Closed bounded service and Results proxy for Automata job sandboxes",
        "org.opencontainers.image.licenses": "MIT",
        "org.opencontainers.image.revision": source.release.revision,
        "org.opencontainers.image.source": "https://github.com/automata-ci/automata",
        "org.opencontainers.image.title": "Automata CI service proxy",
        "org.opencontainers.image.version": source.release.version,
    });
    let expected = serde_json::json!({
        "Entrypoint": ["/usr/libexec/automata-ci-service-proxy"],
        "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
        "Labels": expected_labels,
        "User": "65532:65532",
        "WorkingDir": "/",
    });
    if actual != &expected {
        return Err(invalid_catalog_payload());
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_candidate_layers(
    layers: &[(&str, &[u8])],
    diff_ids: &[Value],
    source_date_epoch: u64,
) -> Result<ValidatedCandidateLayers, LocalInitError> {
    let expected_directories = [
        "usr",
        "usr/libexec",
        "usr/share",
        "usr/share/doc",
        "usr/share/doc/automata-ci-service-proxy",
        "usr/share/licenses",
        "usr/share/licenses/automata-ci-service-proxy",
        "usr/share/sbom",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    let expected_files = BTreeMap::from([
        ("usr/libexec/automata-ci-service-proxy", 0o555),
        ("usr/share/doc/automata-ci-service-proxy/VERSION", 0o444),
        (
            "usr/share/doc/automata-ci-service-proxy/source-provenance.json",
            0o444,
        ),
        (
            "usr/share/licenses/automata-ci-service-proxy/LICENSE",
            0o444,
        ),
        (
            "usr/share/licenses/automata-ci-service-proxy/THIRD_PARTY_LICENSES.txt",
            0o444,
        ),
        (
            "usr/share/licenses/automata-ci-service-proxy/THIRD_PARTY_NOTICES.txt",
            0o444,
        ),
        ("usr/share/sbom/automata-ci-service-proxy.cdx.json", 0o444),
    ]);
    let mut directories = BTreeSet::new();
    let mut files = BTreeMap::new();
    let mut modes = BTreeMap::new();
    let mut expanded_total = 0_usize;
    let mut docker_layer_names = Vec::with_capacity(layers.len());
    let mut expanded_blobs = BTreeMap::new();
    for (index, (media_type, compressed)) in layers.iter().enumerate() {
        let expanded = expand_candidate_layer(compressed, media_type)?;
        expanded_total = expanded_total
            .checked_add(expanded.len())
            .filter(|total| *total <= MAX_EXPANDED_LAYER_BYTES)
            .ok_or_else(invalid_catalog_payload)?;
        let expected_diff = diff_ids[index]
            .as_str()
            .filter(|digest| oci_digest(digest))
            .ok_or_else(invalid_catalog_payload)?;
        if format!("sha256:{}", digest_hex(&expanded)) != expected_diff {
            return Err(invalid_catalog_payload());
        }
        let layer_name = format!(
            "blobs/sha256/{}",
            expected_diff
                .strip_prefix("sha256:")
                .expect("validated OCI digests have a SHA-256 prefix")
        );
        docker_layer_names.push(layer_name.clone());
        let mut archive = tar::Archive::new(Cursor::new(expanded.as_slice()));
        let mut count = 0_usize;
        for entry in archive.entries().map_err(|_| invalid_catalog_payload())? {
            count += 1;
            if count > MAX_LAYER_ENTRIES {
                return Err(invalid_catalog_payload());
            }
            let mut entry = entry.map_err(|_| invalid_catalog_payload())?;
            let name = canonical_tar_path(&entry)?;
            validate_tar_header(&mut entry, source_date_epoch, None)?;
            if entry.header().entry_type().is_dir() {
                if entry
                    .header()
                    .mode()
                    .map_err(|_| invalid_catalog_payload())?
                    != 0o755
                {
                    return Err(invalid_catalog_payload());
                }
                directories.insert(name);
                continue;
            }
            if !entry.header().entry_type().is_file() || files.contains_key(&name) {
                return Err(invalid_catalog_payload());
            }
            let size = usize::try_from(entry.size()).map_err(|_| invalid_catalog_payload())?;
            if size > MAX_EXPANDED_LAYER_MEMBER_BYTES {
                return Err(invalid_catalog_payload());
            }
            let mode = entry
                .header()
                .mode()
                .map_err(|_| invalid_catalog_payload())?;
            let mut contents = Vec::with_capacity(size);
            std::io::Read::by_ref(&mut entry)
                .take(
                    u64::try_from(MAX_EXPANDED_LAYER_MEMBER_BYTES + 1)
                        .expect("expanded layer bound fits u64"),
                )
                .read_to_end(&mut contents)
                .map_err(|_| invalid_catalog_payload())?;
            if contents.len() != size {
                return Err(invalid_catalog_payload());
            }
            modes.insert(name.clone(), mode);
            files.insert(name, contents);
        }
        match expanded_blobs.entry(layer_name) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(expanded);
            }
            std::collections::btree_map::Entry::Occupied(entry) => {
                if entry.get() != &expanded {
                    return Err(invalid_catalog_payload());
                }
            }
        }
    }
    if directories != expected_directories
        || modes
            != expected_files
                .into_iter()
                .map(|(path, mode)| (path.to_owned(), mode))
                .collect()
    {
        return Err(invalid_catalog_payload());
    }
    Ok(ValidatedCandidateLayers {
        payload: files,
        docker_layer_names,
        expanded_blobs,
    })
}

struct ValidatedCandidateLayers {
    payload: BTreeMap<String, Vec<u8>>,
    docker_layer_names: Vec<String>,
    expanded_blobs: BTreeMap<String, Vec<u8>>,
}

#[derive(Serialize)]
struct DockerLoadManifest<'a> {
    #[serde(rename = "Config")]
    config: String,
    #[serde(rename = "Layers")]
    layers: &'a [String],
    #[serde(rename = "RepoTags")]
    repo_tags: [&'a str; 1],
}

fn build_docker_load_archive(
    mut members: BTreeMap<String, Vec<u8>>,
    layers: ValidatedCandidateLayers,
    binding: &CandidateBinding,
    reference: &str,
    source_date_epoch: u64,
    oci_archive_size: usize,
) -> Result<Vec<u8>, LocalInitError> {
    let ValidatedCandidateLayers {
        payload: _,
        docker_layer_names,
        expanded_blobs,
    } = layers;
    let mut expanded_size = oci_archive_size;
    for (name, expanded) in expanded_blobs {
        if let Some(existing) = members.get(&name) {
            if existing != &expanded {
                return Err(invalid_catalog_payload());
            }
            continue;
        }
        expanded_size = expanded_size
            .checked_add(expanded.len())
            .filter(|size| *size <= MAX_DOCKER_LOAD_ARCHIVE_BYTES)
            .ok_or_else(invalid_catalog_payload)?;
        members.insert(name, expanded);
    }
    let config = format!(
        "blobs/sha256/{}",
        binding
            .config_digest
            .strip_prefix("sha256:")
            .expect("verified candidate config digests are SHA-256")
    );
    let mut manifest = serde_json::to_vec(&[DockerLoadManifest {
        config,
        layers: &docker_layer_names,
        repo_tags: [reference],
    }])
    .map_err(|_| invalid_catalog_payload())?;
    manifest.push(b'\n');
    expanded_size
        .checked_add(manifest.len())
        .filter(|size| *size <= MAX_DOCKER_LOAD_ARCHIVE_BYTES)
        .ok_or_else(invalid_catalog_payload)?;
    if members
        .insert("manifest.json".to_owned(), manifest)
        .is_some()
    {
        return Err(invalid_catalog_payload());
    }

    let mut output = Vec::new();
    append_python_tar_member(
        &mut output,
        "blobs",
        &[],
        0o755,
        source_date_epoch,
        tar::EntryType::Directory,
    )?;
    append_python_tar_member(
        &mut output,
        "blobs/sha256",
        &[],
        0o755,
        source_date_epoch,
        tar::EntryType::Directory,
    )?;
    for (name, contents) in members {
        append_python_tar_member(
            &mut output,
            &name,
            &contents,
            0o444,
            source_date_epoch,
            tar::EntryType::Regular,
        )?;
    }
    let terminated = output
        .len()
        .checked_add(1024)
        .ok_or_else(invalid_catalog_payload)?;
    let canonical_length = terminated
        .checked_add(10_239)
        .map(|length| length / 10_240 * 10_240)
        .filter(|length| *length <= MAX_DOCKER_LOAD_ARCHIVE_BYTES)
        .ok_or_else(invalid_catalog_payload)?;
    output.resize(canonical_length, 0);
    Ok(output)
}

fn append_python_tar_member(
    output: &mut Vec<u8>,
    name: &str,
    contents: &[u8],
    mode: u32,
    source_date_epoch: u64,
    entry_type: tar::EntryType,
) -> Result<(), LocalInitError> {
    let header = python_ustar_header(
        name,
        u64::try_from(contents.len()).map_err(|_| invalid_catalog_payload())?,
        mode,
        source_date_epoch,
        entry_type,
    )?;
    let padded = contents
        .len()
        .checked_add(511)
        .map(|length| length / 512 * 512)
        .ok_or_else(invalid_catalog_payload)?;
    let next = output
        .len()
        .checked_add(512)
        .and_then(|length| length.checked_add(padded))
        .filter(|length| *length <= MAX_DOCKER_LOAD_ARCHIVE_BYTES)
        .ok_or_else(invalid_catalog_payload)?;
    output.extend_from_slice(header.as_bytes());
    output.extend_from_slice(contents);
    output.resize(next, 0);
    Ok(())
}

fn expand_candidate_layer(bytes: &[u8], media_type: &str) -> Result<Vec<u8>, LocalInitError> {
    let mut expanded = Vec::new();
    match media_type {
        OCI_LAYER_MEDIA_TYPE => {
            if bytes.len() > MAX_EXPANDED_LAYER_MEMBER_BYTES {
                return Err(invalid_catalog_payload());
            }
            expanded.extend_from_slice(bytes);
        }
        OCI_GZIP_LAYER_MEDIA_TYPE => {
            std::io::Read::by_ref(&mut MultiGzDecoder::new(bytes))
                .take(
                    u64::try_from(MAX_EXPANDED_LAYER_MEMBER_BYTES + 1)
                        .expect("expanded layer bound fits u64"),
                )
                .read_to_end(&mut expanded)
                .map_err(|_| invalid_catalog_payload())?;
            if expanded.len() > MAX_EXPANDED_LAYER_MEMBER_BYTES {
                return Err(invalid_catalog_payload());
            }
        }
        _ => return Err(invalid_catalog_payload()),
    }
    Ok(expanded)
}

fn validate_candidate_payload(
    files: &BTreeMap<String, Vec<u8>>,
    source: &CandidateSource,
    source_bytes: &[u8],
    sbom_bytes: &[u8],
) -> Result<(), LocalInitError> {
    let binary = files
        .get("usr/libexec/automata-ci-service-proxy")
        .ok_or_else(invalid_catalog_payload)?;
    let embedded_source = files
        .get("usr/share/doc/automata-ci-service-proxy/source-provenance.json")
        .ok_or_else(invalid_catalog_payload)?;
    let embedded_sbom = files
        .get("usr/share/sbom/automata-ci-service-proxy.cdx.json")
        .ok_or_else(invalid_catalog_payload)?;
    let version = files
        .get("usr/share/doc/automata-ci-service-proxy/VERSION")
        .ok_or_else(invalid_catalog_payload)?;
    if digest_hex(binary) != source.artifacts.binary_sha256
        || embedded_source != source_bytes
        || embedded_sbom != sbom_bytes
        || version != format!("{}\n", source.release.version).as_bytes()
    {
        return Err(invalid_catalog_payload());
    }
    Ok(())
}

fn validate_candidate_sbom(
    bytes: &[u8],
    binary_sha256: &str,
    version: &str,
) -> Result<(), LocalInitError> {
    let value = parse_canonical_payload_json(bytes)?;
    let document_version = value.get("version").and_then(Value::as_u64);
    let components = value.get("components").and_then(Value::as_array);
    let dependencies = value.get("dependencies").and_then(Value::as_array);
    let component = value
        .get("metadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("component"))
        .and_then(Value::as_object)
        .ok_or_else(invalid_catalog_payload)?;
    let hashes = component
        .get("hashes")
        .and_then(Value::as_array)
        .ok_or_else(invalid_catalog_payload)?;
    let sha256_hashes = hashes
        .iter()
        .filter(|entry| {
            entry
                .as_object()
                .and_then(|entry| entry.get("alg"))
                .and_then(Value::as_str)
                == Some("SHA-256")
        })
        .map(|entry| entry.get("content").and_then(Value::as_str))
        .collect::<Vec<_>>();
    if value.get("bomFormat").and_then(Value::as_str) != Some("CycloneDX")
        || value.get("specVersion").and_then(Value::as_str) != Some("1.5")
        || document_version.is_none_or(|version| version < 1)
        || components.is_none_or(|items| items.iter().any(|item| !item.is_object()))
        || dependencies.is_none_or(|items| items.iter().any(|item| !item.is_object()))
        || hashes.iter().any(|entry| !entry.is_object())
        || component.get("name").and_then(Value::as_str) != Some("automata-ci-service-proxy")
        || component.get("version").and_then(Value::as_str) != Some(version)
        || component.get("type").and_then(Value::as_str) != Some("application")
        || sha256_hashes != [Some(binary_sha256)]
    {
        return Err(invalid_catalog_payload());
    }
    Ok(())
}

pub(super) fn validate_image_process(
    actual: &Value,
    expected: &Value,
    release: Option<&Release>,
) -> Result<(), LocalInitError> {
    let actual = object(actual).map_err(|_| invalid_catalog_payload())?;
    let expected = object(expected).map_err(|_| invalid_catalog())?;
    let actual_env = string_map_from_environment(actual.get("Env"))?;
    let required_env = object(
        expected
            .get("required_environment")
            .ok_or_else(invalid_catalog)?,
    )?;
    for (name, value) in required_env {
        if actual_env.get(name).map(String::as_str) != value.as_str() {
            return Err(invalid_catalog_payload());
        }
    }
    if string_array(actual.get("Entrypoint"))? != string_array(expected.get("entrypoint"))?
        || string_array(actual.get("Cmd"))? != string_array(expected.get("command"))?
        || string_or_empty(actual.get("User"))? != string_or_empty(expected.get("user"))?
        || string_or_empty(actual.get("WorkingDir"))?
            != string_or_empty(expected.get("working_directory"))?
    {
        return Err(invalid_catalog_payload());
    }
    let labels = actual
        .get("Labels")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let required_labels = object(
        expected
            .get("required_labels")
            .ok_or_else(invalid_catalog)?,
    )?;
    for (name, value) in required_labels {
        if labels.get(name) != Some(value) {
            return Err(invalid_catalog_payload());
        }
    }
    if let Some(release) = release {
        for (name, value) in [
            ("org.opencontainers.image.created", release.created.as_str()),
            ("org.opencontainers.image.revision", release.commit.as_str()),
            ("org.opencontainers.image.version", release.version.as_str()),
        ] {
            if labels.get(name).and_then(Value::as_str) != Some(value) {
                return Err(invalid_catalog_payload());
            }
        }
    }
    Ok(())
}

fn exact_tar_members(
    bytes: &[u8],
    expected_names: &[&str],
    maximum_members: usize,
) -> Result<BTreeMap<String, Vec<u8>>, LocalInitError> {
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    let mut result = BTreeMap::new();
    let expected = expected_names.iter().copied().collect::<BTreeSet<_>>();
    for entry in archive.entries().map_err(|_| invalid_catalog_payload())? {
        if result.len() >= maximum_members {
            return Err(invalid_catalog_payload());
        }
        let mut entry = entry.map_err(|_| invalid_catalog_payload())?;
        if !entry.header().entry_type().is_file() {
            return Err(invalid_catalog_payload());
        }
        let path = entry
            .path()
            .map_err(|_| invalid_catalog_payload())?
            .into_owned();
        let name = path.to_str().ok_or_else(invalid_catalog_payload)?;
        if !expected.contains(name) || result.contains_key(name) {
            return Err(invalid_catalog_payload());
        }
        let size = usize::try_from(entry.size()).map_err(|_| invalid_catalog_payload())?;
        if size > MAX_CANDIDATE_MEMBER_BYTES {
            return Err(invalid_catalog_payload());
        }
        let mut contents = Vec::with_capacity(size);
        std::io::Read::by_ref(&mut entry)
            .take(u64::try_from(MAX_CANDIDATE_MEMBER_BYTES + 1).expect("bound fits u64"))
            .read_to_end(&mut contents)
            .map_err(|_| invalid_catalog_payload())?;
        if contents.len() != size {
            return Err(invalid_catalog_payload());
        }
        result.insert(name.to_owned(), contents);
    }
    if result.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err(invalid_catalog_payload());
    }
    Ok(result)
}

fn validate_candidate_archive_metadata(
    bytes: &[u8],
    source_date_epoch: u64,
) -> Result<(), LocalInitError> {
    let expected = [
        CANDIDATE_SBOM,
        CANDIDATE_IMAGE,
        CANDIDATE_IDENTITY,
        CANDIDATE_SOURCE,
    ];
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    let mut actual = Vec::with_capacity(expected.len());
    let mut payload_end = 0_usize;
    for entry in archive.entries().map_err(|_| invalid_catalog_payload())? {
        if actual.len() >= expected.len() {
            return Err(invalid_catalog_payload());
        }
        let mut entry = entry.map_err(|_| invalid_catalog_payload())?;
        let name = canonical_tar_path(&entry)?;
        if !entry.header().entry_type().is_file() || name != expected[actual.len()] {
            return Err(invalid_catalog_payload());
        }
        validate_tar_header(&mut entry, source_date_epoch, Some(0o444))?;
        validate_python_ustar_header(
            entry.header(),
            &name,
            entry.size(),
            0o444,
            source_date_epoch,
            tar::EntryType::Regular,
        )?;
        let maximum = if name == CANDIDATE_IMAGE {
            MAX_CANDIDATE_MEMBER_BYTES
        } else {
            16 * 1024 * 1024
        };
        let size = usize::try_from(entry.size()).map_err(|_| invalid_catalog_payload())?;
        if size > maximum {
            return Err(invalid_catalog_payload());
        }
        payload_end = add_tar_entry_span(payload_end, size)?;
        std::io::copy(
            &mut std::io::Read::by_ref(&mut entry)
                .take(u64::try_from(maximum + 1).expect("candidate member bound fits u64")),
            &mut std::io::sink(),
        )
        .map_err(|_| invalid_catalog_payload())?;
        actual.push(name);
    }
    if actual != expected || !canonical_python_tar_termination(bytes, payload_end) {
        return Err(invalid_catalog_payload());
    }
    Ok(())
}

fn oci_tar_members(
    bytes: &[u8],
    source_date_epoch: u64,
) -> Result<BTreeMap<String, Vec<u8>>, LocalInitError> {
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    let mut result = BTreeMap::new();
    let mut entry_count = 0_usize;
    let mut last_file = None;
    let mut payload_end = 0_usize;
    for entry in archive.entries().map_err(|_| invalid_catalog_payload())? {
        entry_count += 1;
        if entry_count > MAX_OCI_MEMBERS {
            return Err(invalid_catalog_payload());
        }
        let mut entry = entry.map_err(|_| invalid_catalog_payload())?;
        let name = canonical_tar_path(&entry)?;
        if entry.header().entry_type().is_dir()
            && ((entry_count == 1 && name == "blobs")
                || (entry_count == 2 && name == "blobs/sha256"))
        {
            validate_tar_header(&mut entry, source_date_epoch, Some(0o755))?;
            validate_python_ustar_header(
                entry.header(),
                &name,
                0,
                0o755,
                source_date_epoch,
                tar::EntryType::Directory,
            )?;
            payload_end = add_tar_entry_span(payload_end, 0)?;
            continue;
        }
        if entry_count <= 2
            || !entry.header().entry_type().is_file()
            || result.contains_key(&name)
            || last_file
                .as_deref()
                .is_some_and(|previous| previous >= name.as_str())
        {
            return Err(invalid_catalog_payload());
        }
        validate_tar_header(&mut entry, source_date_epoch, Some(0o444))?;
        validate_python_ustar_header(
            entry.header(),
            &name,
            entry.size(),
            0o444,
            source_date_epoch,
            tar::EntryType::Regular,
        )?;
        let size = usize::try_from(entry.size()).map_err(|_| invalid_catalog_payload())?;
        if size > MAX_CANDIDATE_MEMBER_BYTES {
            return Err(invalid_catalog_payload());
        }
        payload_end = add_tar_entry_span(payload_end, size)?;
        let mut contents = Vec::with_capacity(size);
        entry
            .read_to_end(&mut contents)
            .map_err(|_| invalid_catalog_payload())?;
        if contents.len() != size {
            return Err(invalid_catalog_payload());
        }
        last_file = Some(name.clone());
        result.insert(name, contents);
    }
    if entry_count < 4 || !canonical_python_tar_termination(bytes, payload_end) {
        return Err(invalid_catalog_payload());
    }
    Ok(result)
}

fn canonical_tar_path<R: std::io::Read>(
    entry: &tar::Entry<'_, R>,
) -> Result<String, LocalInitError> {
    let bytes = entry.path_bytes();
    let name = std::str::from_utf8(bytes.as_ref()).map_err(|_| invalid_catalog_payload())?;
    if name.is_empty()
        || name.starts_with('/')
        || name.contains('\\')
        || name
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(invalid_catalog_payload());
    }
    Ok(name.to_owned())
}

fn validate_tar_header<R: std::io::Read>(
    entry: &mut tar::Entry<'_, R>,
    source_date_epoch: u64,
    expected_mode: Option<u32>,
) -> Result<(), LocalInitError> {
    let header = entry.header();
    if header.as_ustar().is_none()
        || header.uid().map_err(|_| invalid_catalog_payload())? != 0
        || header.gid().map_err(|_| invalid_catalog_payload())? != 0
        || header.mtime().map_err(|_| invalid_catalog_payload())? != source_date_epoch
        || header
            .username_bytes()
            .is_none_or(|value| !value.is_empty())
        || header
            .groupname_bytes()
            .is_none_or(|value| !value.is_empty())
        || expected_mode.is_some_and(|mode| header.mode().map_or(true, |actual| actual != mode))
    {
        return Err(invalid_catalog_payload());
    }
    if entry
        .pax_extensions()
        .map_err(|_| invalid_catalog_payload())?
        .is_some()
    {
        return Err(invalid_catalog_payload());
    }
    Ok(())
}

fn validate_python_ustar_header(
    actual: &tar::Header,
    name: &str,
    size: u64,
    mode: u32,
    source_date_epoch: u64,
    entry_type: tar::EntryType,
) -> Result<(), LocalInitError> {
    let expected = python_ustar_header(name, size, mode, source_date_epoch, entry_type)?;
    if actual.as_bytes() != expected.as_bytes() {
        return Err(invalid_catalog_payload());
    }
    Ok(())
}

fn python_ustar_header(
    name: &str,
    size: u64,
    mode: u32,
    source_date_epoch: u64,
    entry_type: tar::EntryType,
) -> Result<tar::Header, LocalInitError> {
    let mut expected = tar::Header::new_ustar();
    expected
        .set_path(name)
        .map_err(|_| invalid_catalog_payload())?;
    expected.set_size(size);
    expected.set_mode(mode);
    expected.set_uid(0);
    expected.set_gid(0);
    expected.set_mtime(source_date_epoch);
    expected.set_entry_type(entry_type);
    expected
        .set_username("")
        .map_err(|_| invalid_catalog_payload())?;
    expected
        .set_groupname("")
        .map_err(|_| invalid_catalog_payload())?;
    expected.set_cksum();
    let checksum = expected.cksum().map_err(|_| invalid_catalog_payload())?;
    let checksum = format!("{checksum:06o}\0 ");
    expected.as_mut_bytes()[148..156].copy_from_slice(checksum.as_bytes());
    Ok(expected)
}

fn add_tar_entry_span(offset: usize, size: usize) -> Result<usize, LocalInitError> {
    let padded = size
        .checked_add(511)
        .map(|value| value / 512 * 512)
        .ok_or_else(invalid_catalog_payload)?;
    offset
        .checked_add(512)
        .and_then(|value| value.checked_add(padded))
        .ok_or_else(invalid_catalog_payload)
}

fn canonical_python_tar_termination(bytes: &[u8], payload_end: usize) -> bool {
    let Some(terminated) = payload_end.checked_add(1024) else {
        return false;
    };
    let Some(canonical_length) = terminated
        .checked_add(10_239)
        .map(|value| value / 10_240 * 10_240)
    else {
        return false;
    };
    bytes.len() == canonical_length
        && bytes
            .get(payload_end..)
            .is_some_and(|padding| padding.iter().all(|byte| *byte == 0))
}

fn parse_json_member(
    members: &BTreeMap<String, Vec<u8>>,
    name: &str,
) -> Result<Value, LocalInitError> {
    parse_payload_json(members.get(name).ok_or_else(invalid_catalog_payload)?)
}

fn parse_canonical_json(bytes: &[u8]) -> Result<Value, LocalInitError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = UniqueValue::deserialize(&mut deserializer)
        .map_err(|_| invalid_catalog())?
        .0;
    deserializer.end().map_err(|_| invalid_catalog())?;
    let mut canonical = serde_json::to_vec_pretty(&value).map_err(|_| invalid_catalog())?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err(invalid_catalog());
    }
    Ok(value)
}

fn parse_canonical_payload_json(bytes: &[u8]) -> Result<Value, LocalInitError> {
    let value = parse_payload_json(bytes)?;
    let mut canonical = serde_json::to_vec_pretty(&value).map_err(|_| invalid_catalog_payload())?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err(invalid_catalog_payload());
    }
    Ok(value)
}

fn parse_payload_json(bytes: &[u8]) -> Result<Value, LocalInitError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = UniqueValue::deserialize(&mut deserializer)
        .map_err(|_| invalid_catalog_payload())?
        .0;
    deserializer.end().map_err(|_| invalid_catalog_payload())?;
    Ok(value)
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

struct UniqueValueVisitor;

impl<'de> de::Visitor<'de> for UniqueValueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("one finite JSON value without duplicate keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueValue)
            .ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueValue>()? {
            values.push(value.0);
        }
        Ok(UniqueValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some((name, value)) = map.next_entry::<String, UniqueValue>()? {
            if values.insert(name, value.0).is_some() {
                return Err(de::Error::custom("duplicate JSON key"));
            }
        }
        Ok(UniqueValue(Value::Object(values)))
    }
}

fn object(value: &Value) -> Result<&serde_json::Map<String, Value>, LocalInitError> {
    value.as_object().ok_or_else(invalid_catalog)
}

fn line_field<'a>(
    value: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<&'a str, LocalInitError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| one_line(value))
        .ok_or_else(invalid_catalog)
}

fn exact_u16(value: &Value) -> Result<u16, LocalInitError> {
    value
        .as_u64()
        .and_then(|value| u16::try_from(value).ok())
        .filter(|value| *value != 0)
        .ok_or_else(invalid_catalog)
}

fn string_array(value: Option<&Value>) -> Result<Vec<&str>, LocalInitError> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .filter(|value| one_line(value))
                    .ok_or_else(invalid_catalog_payload)
            })
            .collect(),
        Some(_) => Err(invalid_catalog_payload()),
    }
}

fn string_or_empty(value: Option<&Value>) -> Result<&str, LocalInitError> {
    match value {
        None | Some(Value::Null) => Ok(""),
        Some(Value::String(value))
            if value.len() <= MAX_TEXT_BYTES && !value.contains(['\n', '\r']) =>
        {
            Ok(value)
        }
        Some(_) => Err(invalid_catalog_payload()),
    }
}

fn string_map_from_environment(
    value: Option<&Value>,
) -> Result<BTreeMap<String, String>, LocalInitError> {
    let mut result = BTreeMap::new();
    for entry in string_array(value)? {
        let (name, value) = entry.split_once('=').ok_or_else(invalid_catalog_payload)?;
        if name.is_empty() || result.insert(name.to_owned(), value.to_owned()).is_some() {
            return Err(invalid_catalog_payload());
        }
    }
    Ok(result)
}

fn one_line(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT_BYTES
        && !value.as_bytes().contains(&b'\n')
        && !value.as_bytes().contains(&b'\r')
}

fn sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn oci_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(sha256_hex)
}

fn git_object(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_repository(value: &str) -> bool {
    one_line(value)
        && !value.contains('@')
        && !value.contains(':')
        && value.contains('/')
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"./_-".contains(&byte)
        })
}

fn repository_from_reference(reference: &str) -> &str {
    let name = reference.rsplit_once('@').map_or(reference, |pair| pair.0);
    let last_slash = name.rfind('/').unwrap_or(0);
    name[last_slash..]
        .find(':')
        .map_or(name, |offset| &name[..last_slash + offset])
}

fn canonical_registry_reference(reference: &str, expected_digest: &str) -> bool {
    let Some((name, digest)) = reference.rsplit_once('@') else {
        return false;
    };
    if digest != expected_digest || !oci_digest(digest) {
        return false;
    }
    let repository = repository_from_reference(reference);
    if ImmutableImage::new(format!("{repository}@{digest}")).is_err() {
        return false;
    }
    match name.strip_prefix(repository) {
        Some("") => true,
        Some(tag) => tag.strip_prefix(':').is_some_and(|tag| {
            !tag.is_empty()
                && tag.len() <= 128
                && tag.bytes().enumerate().all(|(index, byte)| {
                    byte.is_ascii_alphanumeric()
                        || byte == b'_'
                        || (index != 0 && matches!(byte, b'.' | b'-'))
                })
        }),
        None => false,
    }
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn digest_hex(bytes: &[u8]) -> String {
    digest(bytes).to_string()
}

fn invalid_catalog() -> LocalInitError {
    LocalInitError::new(LocalInitErrorCode::InvalidCatalog)
}

fn invalid_catalog_payload() -> LocalInitError {
    LocalInitError::new(LocalInitErrorCode::InvalidCatalogPayload)
}

#[cfg(test)]
pub(super) fn candidate_replay_test_catalog(
    release: Release,
    binding: CandidateBinding,
    config: Value,
) -> VerifiedCatalog {
    VerifiedCatalog {
        bytes_sha256: Sha256Digest::from_bytes([0x71; 32]),
        source_contract_sha256: current_source_contract_sha256(),
        release,
        profile: ProfileBinding {
            id: "fixture".to_owned(),
            manifest_sha256: Sha256Digest::from_bytes([0x72; 32]),
            lock_sha256: Sha256Digest::from_bytes([0x73; 32]),
        },
        images: BTreeMap::from([(
            "service-proxy".to_owned(),
            VerifiedImage {
                canonical_repository: "automata.local/automata-ci-service-proxy".to_owned(),
                config,
                runtime: Value::Null,
                source: ImageSource::Candidate(binding),
            },
        )]),
        maximum_parallel_jobs: 1,
        human_port: 8080,
        results_port: 8081,
        runner_control_port: 9090,
    }
}

#[cfg(test)]
mod tests;
