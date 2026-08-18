use std::collections::BTreeMap;

use automata_ci_core::Sha256Digest;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::Installation;

use super::{
    LocalInitError, LocalInitErrorCode,
    catalog::{ImageSource, VerifiedCatalog},
};

const EPOCH_SCHEMA: &str = "automata.local/immutable-epoch/v1";
const MATERIAL_SCHEMA: &str = "automata.local/material/v1";
const EPOCH_FINGERPRINT_DOMAIN: &[u8] = b"automata/local/immutable-epoch-fingerprint/v1\0";
const MATERIAL_KDF_DOMAIN: &[u8] = b"automata/local/material-kdf/v1\0";
const GENERATION: u32 = 1;
const MAX_EPOCH_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(super) struct ImmutableEpoch {
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
    epoch_fingerprint: Sha256Digest,
    initial_desired_sha256: Sha256Digest,
}

impl ImmutableEpoch {
    pub(super) fn new(
        catalog: &VerifiedCatalog,
        installation: &Installation,
        workers: u16,
        state_authority_sha256: Sha256Digest,
        material_root: &[u8; 32],
        desired_sha256: Sha256Digest,
    ) -> Self {
        let descriptor = EpochDescriptor::new(
            catalog,
            installation,
            workers,
            state_authority_sha256,
            material_root,
            desired_sha256,
        );
        let epoch_fingerprint = descriptor.fingerprint();
        Self {
            schema: EPOCH_SCHEMA,
            material_schema: MATERIAL_SCHEMA,
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
        }
    }

    pub(super) fn from_canonical_bytes(
        bytes: &[u8],
        expected: &Self,
    ) -> Result<Self, LocalInitError> {
        if bytes.is_empty() || bytes.len() > MAX_EPOCH_BYTES {
            return Err(reset_required());
        }
        let raw: RawEpoch = serde_json::from_slice(bytes).map_err(|_| reset_required())?;
        if raw.schema != EPOCH_SCHEMA
            || raw.material_schema != MATERIAL_SCHEMA
            || raw.generation != GENERATION
        {
            return Err(reset_required());
        }
        let canonical = canonical_bytes(&raw)?;
        if canonical != bytes {
            return Err(reset_required());
        }
        let actual = Self {
            schema: EPOCH_SCHEMA,
            material_schema: MATERIAL_SCHEMA,
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
        };
        if actual.schema != expected.schema
            || actual.material_schema != expected.material_schema
            || actual.generation != expected.generation
            || actual.installation != expected.installation
            || actual.catalog != expected.catalog
            || actual.platform != expected.platform
            || actual.capacity != expected.capacity
            || actual.profile != expected.profile
            || actual.images != expected.images
            || actual.state_authority_sha256 != expected.state_authority_sha256
            || actual.material_root_sha256 != expected.material_root_sha256
            || actual.initial_desired_sha256 != expected.initial_desired_sha256
            || actual.recompute_fingerprint() != actual.epoch_fingerprint
        {
            return Err(reset_required());
        }
        Ok(actual)
    }

    pub(super) fn canonical_bytes(&self) -> Vec<u8> {
        canonical_bytes(self).expect("closed epoch document is serializable")
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

    fn recompute_fingerprint(&self) -> Sha256Digest {
        EpochDescriptor {
            schema: self.schema,
            material_schema: self.material_schema,
            generation: self.generation,
            installation: self.installation.clone(),
            catalog: self.catalog.clone(),
            platform: self.platform.clone(),
            capacity: self.capacity.clone(),
            profile: self.profile.clone(),
            images: self.images.clone(),
            state_authority_sha256: self.state_authority_sha256,
            material_root_sha256: self.material_root_sha256,
            initial_desired_sha256: self.initial_desired_sha256,
        }
        .fingerprint()
    }
}

#[derive(Serialize)]
struct EpochDescriptor {
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
}

impl EpochDescriptor {
    fn new(
        catalog: &VerifiedCatalog,
        installation: &Installation,
        workers: u16,
        state_authority_sha256: Sha256Digest,
        material_root: &[u8; 32],
        initial_desired_sha256: Sha256Digest,
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
            schema: EPOCH_SCHEMA,
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
        }
    }

    fn fingerprint(&self) -> Sha256Digest {
        let bytes = canonical_bytes(self).expect("closed epoch descriptor is serializable");
        let mut hasher = Sha256::new();
        hasher.update(EPOCH_FINGERPRINT_DOMAIN);
        hasher.update(
            u32::try_from(bytes.len())
                .expect("bounded epoch descriptor fits u32")
                .to_be_bytes(),
        );
        hasher.update(bytes);
        Sha256Digest::from_bytes(hasher.finalize().into())
    }
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
    let descriptor = EpochDescriptor {
        schema: EPOCH_SCHEMA,
        material_schema: MATERIAL_SCHEMA,
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
        initial_desired_sha256: Sha256Digest::from_bytes([4; 32]),
    };
    let fingerprint = descriptor.fingerprint();
    ImmutableEpoch {
        schema: EPOCH_SCHEMA,
        material_schema: MATERIAL_SCHEMA,
        generation: GENERATION,
        installation: descriptor.installation,
        catalog: descriptor.catalog,
        platform: descriptor.platform,
        capacity: descriptor.capacity,
        profile: descriptor.profile,
        images: descriptor.images,
        state_authority_sha256: descriptor.state_authority_sha256,
        material_root_sha256: descriptor.material_root_sha256,
        epoch_fingerprint: fingerprint,
        initial_desired_sha256: descriptor.initial_desired_sha256,
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RawEpoch {
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
