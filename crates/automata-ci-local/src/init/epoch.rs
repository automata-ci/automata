use std::{collections::BTreeMap, num::NonZeroU16, str::FromStr as _};

use automata_ci_core::{EnvironmentProfile, EnvironmentProfileId, Sha256Digest};
use automata_ci_execution::ImmutableImage;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::{
    DesiredSpec, DesiredSpecImages, DesiredSpecInput, EngineArchitecture, Installation,
    InstallationId, InstallationName, LocalImportedImage, LocalProfile,
    MAXIMUM_LOCAL_DOCKER_JOB_SLOTS,
};

use super::{
    LocalInitError, LocalInitErrorCode,
    catalog::{ImageSource, VerifiedCatalog, validate_current_source_contract},
};

const EPOCH_SCHEMA_V2: &str = "automata.local/immutable-epoch/v2";
const MATERIAL_SCHEMA: &str = "automata.local/material/v1";
const EPOCH_FINGERPRINT_DOMAIN_V2: &[u8] = b"automata/local/immutable-epoch-fingerprint/v2\0";
const MATERIAL_KDF_DOMAIN: &[u8] = b"automata/local/material-kdf/v1\0";
const GENERATION: u32 = 1;
const MAX_EPOCH_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ImmutableEpoch {
    generation: u32,
    installation: EpochInstallation,
    catalog: EpochCatalog,
    platform: EpochPlatform,
    capacity: EpochCapacity,
    profile: EpochProfile,
    images: BTreeMap<String, EpochImage>,
    state_authority_sha256: Sha256Digest,
    material_root_sha256: Sha256Digest,
    epoch_fingerprint: Sha256Digest,
    initial_desired_sha256: Sha256Digest,
    desired_plan_sha256: Sha256Digest,
}

impl ImmutableEpoch {
    pub(super) fn new(
        catalog: &VerifiedCatalog,
        installation: &Installation,
        workers: u16,
        state_authority_sha256: Sha256Digest,
        material_root: &[u8; 32],
        desired_sha256: Sha256Digest,
        desired_plan_sha256: Sha256Digest,
    ) -> Self {
        let descriptor = EpochDescriptorV2::new(
            catalog,
            installation,
            workers,
            state_authority_sha256,
            material_root,
            desired_sha256,
            desired_plan_sha256,
        );
        let epoch_fingerprint = descriptor.fingerprint();
        Self {
            generation: GENERATION,
            installation: descriptor.installation,
            catalog: descriptor.catalog,
            platform: descriptor.platform,
            capacity: descriptor.capacity,
            profile: descriptor.profile,
            images: descriptor.images,
            state_authority_sha256: descriptor.state_authority_sha256,
            material_root_sha256: descriptor.material_root_sha256,
            epoch_fingerprint,
            initial_desired_sha256: desired_sha256,
            desired_plan_sha256: descriptor.desired_plan_sha256,
        }
    }

    pub(super) fn from_canonical_bytes(
        bytes: &[u8],
        expected: &Self,
    ) -> Result<Self, LocalInitError> {
        let actual = Self::decode_canonical(bytes)?;
        if actual != *expected || actual.recompute_fingerprint() != actual.epoch_fingerprint {
            return Err(reset_required());
        }
        Ok(actual)
    }

    pub(super) fn from_sealed_bytes(
        bytes: &[u8],
        state_authority_sha256: Sha256Digest,
        material_root: &[u8; 32],
    ) -> Result<Self, LocalInitError> {
        let actual = Self::from_authority_bound_bytes(bytes, state_authority_sha256)?;
        if actual.material_root_sha256 != digest(material_root) {
            return Err(reset_required());
        }
        Ok(actual)
    }

    pub(super) fn from_authority_bound_bytes(
        bytes: &[u8],
        state_authority_sha256: Sha256Digest,
    ) -> Result<Self, LocalInitError> {
        let actual = Self::decode_canonical(bytes)?;
        if actual.state_authority_sha256 != state_authority_sha256
            || actual.recompute_fingerprint() != actual.epoch_fingerprint
            || actual.platform.host != "linux/x86_64"
            || actual.platform.engine != "linux/amd64"
            || actual.capacity.workers == 0
            || actual.capacity.workers > MAXIMUM_LOCAL_DOCKER_JOB_SLOTS
            || !valid_catalog_identity(&actual.catalog)
            || !valid_profile(&actual.profile)
            || !valid_images(&actual.images)
        {
            return Err(reset_required());
        }
        actual.installation()?;
        Ok(actual)
    }

    pub(super) fn canonical_bytes(&self) -> Vec<u8> {
        canonical_bytes(&RawEpochV2::from(self)).expect("closed epoch document is serializable")
    }

    pub(super) const fn fingerprint(&self) -> Sha256Digest {
        self.epoch_fingerprint
    }

    pub(super) const fn generation(&self) -> u32 {
        self.generation
    }

    pub(super) const fn initial_desired_sha256(&self) -> Sha256Digest {
        self.initial_desired_sha256
    }

    pub(super) const fn material_root_sha256(&self) -> Sha256Digest {
        self.material_root_sha256
    }

    pub(super) const fn desired_plan_sha256(&self) -> Sha256Digest {
        self.desired_plan_sha256
    }

    pub(super) const fn workers(&self) -> u16 {
        self.capacity.workers
    }

    pub(super) fn require_current_lifecycle_contract(&self) -> Result<(), LocalInitError> {
        let current_source_contract = validate_current_source_contract()?;
        if self.catalog.source_contract_sha256 != current_source_contract {
            return Err(reset_required());
        }
        Ok(())
    }

    pub(super) fn installation(&self) -> Result<Installation, LocalInitError> {
        let name =
            InstallationName::new(self.installation.name.clone()).map_err(|_| reset_required())?;
        let id = InstallationId::from_str(&self.installation.id).map_err(|_| reset_required())?;
        let installation = Installation::verified(name, id);
        if self.installation.selector_key != installation.selector_key().to_string()
            || self.installation.compose_project != installation.compose_project().as_str()
        {
            return Err(reset_required());
        }
        Ok(installation)
    }

    /// Reconstructs the sole current Desired v1 document from immutable epoch
    /// evidence without reading or mutating a named volume.
    ///
    /// Desired v1 is entirely determined by the current source contract, the
    /// installation identity, and the worker count. Both the canonical-byte
    /// digest and plan digest are checked against the epoch before the result
    /// is usable for read-only live topology inspection.
    pub(super) fn desired_spec(&self) -> Result<DesiredSpec, LocalInitError> {
        self.require_current_lifecycle_contract()?;
        let installation = self.installation()?;
        let workers = NonZeroU16::new(self.capacity.workers).ok_or_else(reset_required)?;
        let image = |role: &str| {
            self.image_expectations()
                .find(|image| image.role == role)
                .ok_or_else(reset_required)
        };
        let immutable = |role: &str| -> Result<ImmutableImage, LocalInitError> {
            ImmutableImage::new(image(role)?.inspection_reference()?).map_err(|_| reset_required())
        };
        let profile = LocalProfile::new(
            EngineArchitecture::Amd64,
            EnvironmentProfile::new(
                EnvironmentProfileId::new(self.profile.id.clone()).map_err(|_| reset_required())?,
                self.profile.manifest_sha256,
            ),
            immutable("profile")?,
        )
        .map_err(|_| reset_required())?;
        let service_proxy = image("service-proxy")?;
        let service_proxy =
            LocalImportedImage::new(service_proxy.config_digest, service_proxy.manifest_digest)
                .map_err(|_| reset_required())?;
        let results = crate::desired_spec::results_transit_for_installation(&installation)
            .map_err(|_| reset_required())?;
        let input = DesiredSpecInput::new(
            workers,
            NonZeroU16::new(8080).expect("the fixed human port is nonzero"),
            profile,
            DesiredSpecImages::new(
                immutable("automata")?,
                immutable("runner")?,
                immutable("postgres")?,
                immutable("rustfs")?,
                immutable("sandbox-guest")?,
                service_proxy,
            ),
            results,
        )
        .map_err(|_| reset_required())?;
        let desired = DesiredSpec::new(&installation, input).map_err(|_| reset_required())?;
        if digest(&desired.canonical_bytes()) != self.initial_desired_sha256
            || desired.plan_digest() != self.desired_plan_sha256
        {
            return Err(reset_required());
        }
        Ok(desired)
    }

    pub(super) fn image_expectations(&self) -> impl Iterator<Item = EpochImageExpectation<'_>> {
        self.images
            .iter()
            .map(|(role, image)| EpochImageExpectation {
                role,
                reference: &image.reference,
                canonical_repository: &image.canonical_repository,
                source_kind: &image.source_kind,
                config_digest: &image.config_digest,
                manifest_digest: &image.manifest_digest,
                platform_manifest_digest: image.platform_manifest_digest.as_deref(),
            })
    }

    fn recompute_fingerprint(&self) -> Sha256Digest {
        EpochDescriptorV2::from(self).fingerprint()
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, LocalInitError> {
        validate_current_source_contract()?;
        if bytes.is_empty() || bytes.len() > MAX_EPOCH_BYTES {
            return Err(reset_required());
        }
        let raw: RawEpochV2 = serde_json::from_slice(bytes).map_err(|_| reset_required())?;
        if raw.schema != EPOCH_SCHEMA_V2
            || raw.material_schema != MATERIAL_SCHEMA
            || raw.generation != GENERATION
            || canonical_bytes(&raw)? != bytes
        {
            return Err(reset_required());
        }
        Ok(raw.into())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct EpochImageExpectation<'a> {
    pub(super) role: &'a str,
    pub(super) reference: &'a str,
    pub(super) canonical_repository: &'a str,
    pub(super) source_kind: &'a str,
    pub(super) config_digest: &'a str,
    pub(super) manifest_digest: &'a str,
    pub(super) platform_manifest_digest: Option<&'a str>,
}

impl EpochImageExpectation<'_> {
    pub(super) fn inspection_reference(self) -> Result<String, LocalInitError> {
        if self.source_kind == "release-candidate" {
            let digest = self
                .manifest_digest
                .strip_prefix("sha256:")
                .ok_or_else(reset_required)?;
            Ok(format!("{}:manifest-{digest}", self.canonical_repository))
        } else {
            let (repository, _) = self.reference.rsplit_once('@').ok_or_else(reset_required)?;
            Ok(format!(
                "{repository}@{}",
                self.platform_manifest_digest.ok_or_else(reset_required)?
            ))
        }
    }
}

#[derive(Serialize)]
struct EpochDescriptorV2 {
    schema: &'static str,
    material_schema: &'static str,
    generation: u32,
    installation: EpochInstallation,
    catalog: EpochCatalog,
    platform: EpochPlatform,
    capacity: EpochCapacity,
    profile: EpochProfile,
    images: BTreeMap<String, EpochImage>,
    state_authority_sha256: Sha256Digest,
    material_root_sha256: Sha256Digest,
    initial_desired_sha256: Sha256Digest,
    desired_plan_sha256: Sha256Digest,
}

impl EpochDescriptorV2 {
    fn new(
        catalog: &VerifiedCatalog,
        installation: &Installation,
        workers: u16,
        state_authority_sha256: Sha256Digest,
        material_root: &[u8; 32],
        initial_desired_sha256: Sha256Digest,
        desired_plan_sha256: Sha256Digest,
    ) -> Self {
        let images = [
            "automata",
            "postgres",
            "profile",
            "runner",
            "rustfs",
            "sandbox-guest",
            "service-proxy",
        ]
        .into_iter()
        .map(|role| {
            let image = catalog.image(role);
            let (kind, content_digest, manifest_digest, platform_manifest_digest) =
                match &image.source {
                    ImageSource::Registry(binding) => (
                        "registry",
                        binding.config_digest.clone(),
                        binding.top_level_digest.clone(),
                        Some(binding.platform_manifest_digest.clone()),
                    ),
                    ImageSource::Candidate(binding) => (
                        "release-candidate",
                        binding.config_digest.clone(),
                        binding.image_digest.clone(),
                        None,
                    ),
                };
            (
                role.to_owned(),
                EpochImage {
                    reference: image.source_reference().to_owned(),
                    canonical_repository: image.canonical_repository.clone(),
                    source_kind: kind.to_owned(),
                    config_digest: content_digest,
                    manifest_digest,
                    platform_manifest_digest,
                    runtime_contract_sha256: digest(
                        &serde_json::to_vec(&image.runtime)
                            .expect("verified catalog runtime is serializable"),
                    ),
                },
            )
        })
        .collect();
        Self {
            schema: EPOCH_SCHEMA_V2,
            material_schema: MATERIAL_SCHEMA,
            generation: GENERATION,
            installation: EpochInstallation {
                name: installation.name().as_str().to_owned(),
                id: installation.id().to_string(),
                selector_key: installation.selector_key().to_string(),
                compose_project: installation.compose_project().to_string(),
            },
            catalog: EpochCatalog {
                sha256: catalog.digest(),
                commit: catalog.release().commit.clone(),
                tag: catalog.release().tag.clone(),
                version: catalog.release().version.clone(),
                source_contract_sha256: catalog.source_contract_sha256(),
            },
            platform: EpochPlatform {
                host: "linux/x86_64".to_owned(),
                engine: "linux/amd64".to_owned(),
            },
            capacity: EpochCapacity { workers },
            profile: EpochProfile {
                id: catalog.profile().id.clone(),
                manifest_sha256: catalog.profile().manifest_sha256,
                lock_sha256: catalog.profile().lock_sha256,
            },
            images,
            state_authority_sha256,
            material_root_sha256: digest(material_root),
            initial_desired_sha256,
            desired_plan_sha256,
        }
    }

    fn fingerprint(&self) -> Sha256Digest {
        fingerprint(EPOCH_FINGERPRINT_DOMAIN_V2, self)
    }
}

impl From<&ImmutableEpoch> for EpochDescriptorV2 {
    fn from(epoch: &ImmutableEpoch) -> Self {
        Self {
            schema: EPOCH_SCHEMA_V2,
            material_schema: MATERIAL_SCHEMA,
            generation: epoch.generation,
            installation: epoch.installation.clone(),
            catalog: epoch.catalog.clone(),
            platform: epoch.platform.clone(),
            capacity: epoch.capacity.clone(),
            profile: epoch.profile.clone(),
            images: epoch.images.clone(),
            state_authority_sha256: epoch.state_authority_sha256,
            material_root_sha256: epoch.material_root_sha256,
            initial_desired_sha256: epoch.initial_desired_sha256,
            desired_plan_sha256: epoch.desired_plan_sha256,
        }
    }
}

fn valid_catalog_identity(catalog: &EpochCatalog) -> bool {
    catalog.commit.len() == 40
        && catalog
            .commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && !catalog.tag.is_empty()
        && catalog.tag.len() <= 128
        && !catalog.version.is_empty()
        && catalog.version.len() <= 128
        && catalog
            .tag
            .bytes()
            .chain(catalog.version.bytes())
            .all(|byte| byte.is_ascii_graphic())
}

fn valid_profile(profile: &EpochProfile) -> bool {
    !profile.id.is_empty()
        && profile.id.len() <= 256
        && profile.id.bytes().all(|byte| byte.is_ascii_graphic())
}

fn valid_images(images: &BTreeMap<String, EpochImage>) -> bool {
    const ROLES: [&str; 7] = [
        "automata",
        "postgres",
        "profile",
        "runner",
        "rustfs",
        "sandbox-guest",
        "service-proxy",
    ];
    if images.keys().map(String::as_str).collect::<Vec<_>>() != ROLES {
        return false;
    }
    images.iter().all(|(role, image)| {
        let candidate = role == "service-proxy";
        let expected_kind = if candidate {
            "release-candidate"
        } else {
            "registry"
        };
        let expected_platform = (!candidate).then_some(image.platform_manifest_digest.as_deref());
        image.source_kind == expected_kind
            && oci_digest(&image.config_digest)
            && oci_digest(&image.manifest_digest)
            && if candidate {
                image.platform_manifest_digest.is_none()
            } else {
                expected_platform.flatten().is_some_and(oci_digest)
            }
            && canonical_image_text(&image.reference)
            && canonical_image_text(&image.canonical_repository)
            && image
                .reference
                .rsplit_once('@')
                .is_some_and(|(_, digest)| digest == image.manifest_digest)
    })
}

fn canonical_image_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'\\' | b'\'' | b'\"'))
}

fn oci_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

pub(super) struct MaterialDeriver {
    root: Zeroizing<[u8; 32]>,
    installation_id: String,
    installation_key: String,
    generation: u32,
    epoch_fingerprint: Sha256Digest,
}

impl MaterialDeriver {
    pub(super) fn new(root: [u8; 32], installation: &Installation, epoch: &ImmutableEpoch) -> Self {
        Self {
            root: Zeroizing::new(root),
            installation_id: installation.id().to_string(),
            installation_key: installation.selector_key().to_string(),
            generation: epoch.generation(),
            epoch_fingerprint: epoch.fingerprint(),
        }
    }

    pub(super) fn bytes(&self, purpose: &'static [u8], length: usize) -> Zeroizing<Vec<u8>> {
        assert!((1..=64).contains(&length), "closed material length");
        let mut context = Vec::with_capacity(256);
        context.extend_from_slice(MATERIAL_KDF_DOMAIN);
        append_field(&mut context, self.installation_id.as_bytes());
        append_field(&mut context, self.installation_key.as_bytes());
        context.extend_from_slice(&self.generation.to_be_bytes());
        context.extend_from_slice(self.epoch_fingerprint.as_bytes());
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &context);
        let prk = salt.extract(self.root.as_ref());
        let info = [b"automata/local/material-purpose/v1\0".as_slice(), purpose];
        let okm = prk
            .expand(&info, ExactLength(length))
            .expect("closed HKDF output length is valid");
        let mut output = Zeroizing::new(vec![0_u8; length]);
        okm.fill(&mut output)
            .expect("closed HKDF output buffer has the exact length");
        output
    }

    pub(super) fn text(&self, purpose: &'static [u8], length: usize) -> Zeroizing<String> {
        Zeroizing::new(URL_SAFE_NO_PAD.encode(self.bytes(purpose, length).as_slice()))
    }

    pub(super) fn uuid(&self, purpose: &'static [u8]) -> uuid::Uuid {
        let material = self.bytes(purpose, 16);
        let mut bytes = <[u8; 16]>::try_from(material.as_slice())
            .expect("the closed UUID derivation length is exact");
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        uuid::Uuid::from_bytes(bytes)
    }
}

#[derive(Clone, Copy)]
struct ExactLength(usize);

impl hkdf::KeyType for ExactLength {
    fn len(&self) -> usize {
        self.0
    }
}

fn append_field(destination: &mut Vec<u8>, value: &[u8]) {
    destination.extend_from_slice(
        &u32::try_from(value.len())
            .expect("closed derivation field fits u32")
            .to_be_bytes(),
    );
    destination.extend_from_slice(value);
}

fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, LocalInitError> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| reset_required())?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn fingerprint(domain: &[u8], descriptor: &impl Serialize) -> Sha256Digest {
    let bytes = canonical_bytes(descriptor).expect("closed epoch descriptor is serializable");
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(
        u32::try_from(bytes.len())
            .expect("bounded epoch descriptor fits u32")
            .to_be_bytes(),
    );
    hasher.update(bytes);
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn reset_required() -> LocalInitError {
    LocalInitError::new(LocalInitErrorCode::ResetRequired)
}

#[cfg(test)]
pub(super) fn certificate_test_epoch(
    installation: &Installation,
    material_root: &[u8; 32],
) -> ImmutableEpoch {
    let mut epoch = ImmutableEpoch {
        generation: GENERATION,
        installation: EpochInstallation {
            name: installation.name().as_str().to_owned(),
            id: installation.id().to_string(),
            selector_key: installation.selector_key().to_string(),
            compose_project: installation.compose_project().to_string(),
        },
        catalog: EpochCatalog {
            sha256: Sha256Digest::from_bytes([1; 32]),
            commit: "1111111111111111111111111111111111111111".to_owned(),
            tag: "v1.0.0".to_owned(),
            version: "1.0.0".to_owned(),
            source_contract_sha256: super::catalog::current_source_contract_sha256(),
        },
        platform: EpochPlatform {
            host: "linux/x86_64".to_owned(),
            engine: "linux/amd64".to_owned(),
        },
        capacity: EpochCapacity { workers: 1 },
        profile: EpochProfile {
            id: "automata.dev/github-hosted-ubuntu-24-04-x64-v1".to_owned(),
            manifest_sha256: Sha256Digest::from_bytes([2; 32]),
            lock_sha256: Sha256Digest::from_bytes([3; 32]),
        },
        images: BTreeMap::new(),
        state_authority_sha256: Sha256Digest::from_bytes([5; 32]),
        material_root_sha256: digest(material_root),
        epoch_fingerprint: Sha256Digest::from_bytes([0; 32]),
        initial_desired_sha256: Sha256Digest::from_bytes([4; 32]),
        desired_plan_sha256: Sha256Digest::from_bytes([6; 32]),
    };
    epoch.epoch_fingerprint = epoch.recompute_fingerprint();
    epoch
}

#[cfg(test)]
pub(super) fn authority_test_epoch(
    installation: &Installation,
    material_root: &[u8; 32],
    state_authority_sha256: Sha256Digest,
) -> ImmutableEpoch {
    let mut epoch = certificate_test_epoch(installation, material_root);
    epoch.state_authority_sha256 = state_authority_sha256;
    epoch.images = [
        "automata",
        "postgres",
        "profile",
        "runner",
        "rustfs",
        "sandbox-guest",
        "service-proxy",
    ]
    .into_iter()
    .enumerate()
    .map(|(index, role)| {
        let config = format!("sha256:{}", format!("{:02x}", index + 1).repeat(32));
        let manifest = format!("sha256:{}", format!("{:02x}", index + 9).repeat(32));
        let candidate = role == "service-proxy";
        (
            role.to_owned(),
            EpochImage {
                reference: format!("registry.invalid/{role}@{manifest}"),
                canonical_repository: format!("automata.local/{role}"),
                source_kind: if candidate {
                    "release-candidate"
                } else {
                    "registry"
                }
                .to_owned(),
                config_digest: config,
                manifest_digest: manifest.clone(),
                platform_manifest_digest: (!candidate).then_some(manifest),
                runtime_contract_sha256: Sha256Digest::from_bytes(
                    [u8::try_from(index).expect("closed image index fits u8") + 1; 32],
                ),
            },
        )
    })
    .collect();
    epoch.epoch_fingerprint = epoch.recompute_fingerprint();
    epoch
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RawEpochV2 {
    schema: String,
    material_schema: String,
    generation: u32,
    installation: EpochInstallation,
    catalog: EpochCatalog,
    platform: EpochPlatform,
    capacity: EpochCapacity,
    profile: EpochProfile,
    images: BTreeMap<String, EpochImage>,
    state_authority_sha256: Sha256Digest,
    material_root_sha256: Sha256Digest,
    epoch_fingerprint: Sha256Digest,
    initial_desired_sha256: Sha256Digest,
    desired_plan_sha256: Sha256Digest,
}

impl From<&ImmutableEpoch> for RawEpochV2 {
    fn from(epoch: &ImmutableEpoch) -> Self {
        Self {
            schema: EPOCH_SCHEMA_V2.to_owned(),
            material_schema: MATERIAL_SCHEMA.to_owned(),
            generation: epoch.generation,
            installation: epoch.installation.clone(),
            catalog: epoch.catalog.clone(),
            platform: epoch.platform.clone(),
            capacity: epoch.capacity.clone(),
            profile: epoch.profile.clone(),
            images: epoch.images.clone(),
            state_authority_sha256: epoch.state_authority_sha256,
            material_root_sha256: epoch.material_root_sha256,
            epoch_fingerprint: epoch.epoch_fingerprint,
            initial_desired_sha256: epoch.initial_desired_sha256,
            desired_plan_sha256: epoch.desired_plan_sha256,
        }
    }
}

impl From<RawEpochV2> for ImmutableEpoch {
    fn from(raw: RawEpochV2) -> Self {
        Self {
            generation: raw.generation,
            installation: raw.installation,
            catalog: raw.catalog,
            platform: raw.platform,
            capacity: raw.capacity,
            profile: raw.profile,
            images: raw.images,
            state_authority_sha256: raw.state_authority_sha256,
            material_root_sha256: raw.material_root_sha256,
            epoch_fingerprint: raw.epoch_fingerprint,
            initial_desired_sha256: raw.initial_desired_sha256,
            desired_plan_sha256: raw.desired_plan_sha256,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EpochInstallation {
    name: String,
    id: String,
    selector_key: String,
    compose_project: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EpochCatalog {
    sha256: Sha256Digest,
    commit: String,
    tag: String,
    version: String,
    source_contract_sha256: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EpochPlatform {
    host: String,
    engine: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EpochCapacity {
    workers: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EpochProfile {
    id: String,
    manifest_sha256: Sha256Digest,
    lock_sha256: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EpochImage {
    reference: String,
    canonical_repository: String,
    source_kind: String,
    config_digest: String,
    manifest_digest: String,
    platform_manifest_digest: Option<String>,
    runtime_contract_sha256: Sha256Digest,
}

#[cfg(test)]
mod tests;
