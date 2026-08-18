//! Canonical, credential-free desired intent for one local installation.

use std::{net::Ipv4Addr, num::NonZeroU16};

use automata_ci_core::{EnvironmentProfile, Sha256Digest};
use automata_ci_execution::ImmutableImage;
use automata_ci_runner_journal::MAX_JOURNALED_SLOTS;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    ComposeProjectName, EngineArchitecture, Installation, InstallationId, InstallationSelectorKey,
    LocalImportedImage,
};

const DESIRED_SPEC_SCHEMA: &str = "automata.local/desired-spec/v1";
const PLAN_DIGEST_DOMAIN: &[u8] = b"automata/local/desired-plan/v1\0";

const AMD64_PROFILE_ID: &str = "automata.dev/github-hosted-ubuntu-24-04-x64-v1";
const ARM64_PROFILE_ID: &str = "automata.local/ubuntu-24-04-arm64-container-v1";

/// Exact content-attested local job profile selected for one installation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalProfile {
    architecture: EngineArchitecture,
    attestation: EnvironmentProfile,
    image: ImmutableImage,
}

impl LocalProfile {
    /// Binds one current local profile identity to its architecture, manifest,
    /// and immutable image.
    ///
    /// # Errors
    ///
    /// Rejects an identity that does not name the sole current profile for the
    /// selected Engine architecture.
    pub fn new(
        architecture: EngineArchitecture,
        attestation: EnvironmentProfile,
        image: ImmutableImage,
    ) -> Result<Self, DesiredSpecError> {
        let expected = match architecture {
            EngineArchitecture::Amd64 => AMD64_PROFILE_ID,
            EngineArchitecture::Arm64 => ARM64_PROFILE_ID,
        };
        if attestation.id().as_str() != expected {
            return Err(DesiredSpecError::new(DesiredSpecErrorCode::Profile));
        }
        Ok(Self {
            architecture,
            attestation,
            image,
        })
    }
}

/// Closed image set retained by desired-spec version one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesiredSpecImages {
    automata: ImmutableImage,
    runner: ImmutableImage,
    postgres: ImmutableImage,
    rustfs: ImmutableImage,
    sandbox_guest: ImmutableImage,
    service_proxy: LocalImportedImage,
}

impl DesiredSpecImages {
    /// Creates the complete desired-spec-v1 image set.
    #[must_use]
    pub const fn new(
        automata: ImmutableImage,
        runner: ImmutableImage,
        postgres: ImmutableImage,
        rustfs: ImmutableImage,
        sandbox_guest: ImmutableImage,
        service_proxy: LocalImportedImage,
    ) -> Self {
        Self {
            automata,
            runner,
            postgres,
            rustfs,
            sandbox_guest,
            service_proxy,
        }
    }
}

/// Explicit desired choices not derived from installation identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesiredSpecInput {
    max_parallel_jobs: NonZeroU16,
    human_port: NonZeroU16,
    profile: LocalProfile,
    images: DesiredSpecImages,
    results_transit: ResultsTransit,
}

impl DesiredSpecInput {
    /// Creates the complete bounded desired-spec-v1 input set.
    ///
    /// # Errors
    ///
    /// Rejects capacity above the runner journal's current durable slot limit.
    pub fn new(
        max_parallel_jobs: NonZeroU16,
        human_port: NonZeroU16,
        profile: LocalProfile,
        images: DesiredSpecImages,
        results_transit: ResultsTransit,
    ) -> Result<Self, DesiredSpecError> {
        if usize::from(max_parallel_jobs.get()) > MAX_JOURNALED_SLOTS {
            return Err(DesiredSpecError::new(DesiredSpecErrorCode::Capacity));
        }
        Ok(Self {
            max_parallel_jobs,
            human_port,
            profile,
            images,
            results_transit,
        })
    }
}

/// Stable desired addressing for the future shared Results transit network.
///
/// Engine network and container IDs are deliberately absent: lifecycle code
/// discovers and attests those live facts after later convergence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResultsTransit {
    subnet: Ipv4Subnet,
    gateway: Ipv4Addr,
    results_address: Ipv4Addr,
}

impl ResultsTransit {
    /// Creates one canonical private transit network.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical or non-private subnets, prefixes narrower than the
    /// current 257-proxy capacity requires, a gateway other than the first
    /// usable address, and an unusable or gateway-equal Results address.
    pub fn new(
        subnet: impl AsRef<str>,
        gateway: Ipv4Addr,
        results_address: Ipv4Addr,
    ) -> Result<Self, DesiredSpecError> {
        let subnet = Ipv4Subnet::parse(subnet.as_ref())?;
        if subnet.prefix > 23
            || !subnet.is_private()
            || gateway != subnet.first_host()
            || !subnet.is_usable(results_address)
            || results_address == gateway
        {
            return Err(DesiredSpecError::new(DesiredSpecErrorCode::ResultsTransit));
        }
        Ok(Self {
            subnet,
            gateway,
            results_address,
        })
    }

    /// Returns the canonical subnet string.
    #[must_use]
    pub fn subnet(&self) -> String {
        self.subnet.to_string()
    }

    fn overlaps(&self, other: Ipv4Subnet) -> bool {
        self.subnet.overlaps(other)
    }
}

/// Validated current desired-spec document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesiredSpec {
    installation_id: InstallationId,
    installation_key: InstallationSelectorKey,
    compose_project: ComposeProjectName,
    max_parallel_jobs: NonZeroU16,
    human_port: NonZeroU16,
    profile: LocalProfile,
    images: DesiredSpecImages,
    results_transit: ResultsTransit,
    plan_digest: Sha256Digest,
}

impl DesiredSpec {
    /// Binds explicit desired inputs to a verified installation identity.
    ///
    /// # Errors
    ///
    /// Rejects a Results transit that overlaps either the provider's exact
    /// installation `/20` pool or the planned deterministic control subnet.
    pub fn new(
        installation: &Installation,
        input: DesiredSpecInput,
    ) -> Result<Self, DesiredSpecError> {
        if input
            .results_transit
            .overlaps(provider_front_pool(installation))
            || input.results_transit.overlaps(control_subnet(installation))
        {
            return Err(DesiredSpecError::new(DesiredSpecErrorCode::ResultsTransit));
        }
        let mut spec = Self {
            installation_id: installation.id(),
            installation_key: installation.selector_key(),
            compose_project: installation.compose_project().clone(),
            max_parallel_jobs: input.max_parallel_jobs,
            human_port: input.human_port,
            profile: input.profile,
            images: input.images,
            results_transit: input.results_transit,
            plan_digest: Sha256Digest::from_bytes([0; 32]),
        };
        spec.plan_digest = spec.recompute_plan_digest();
        Ok(spec)
    }

    /// Returns the sole accepted persisted encoding, including one final newline.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_json(&self.canonical_document(Some(self.plan_digest)))
    }

    #[cfg(test)]
    #[must_use]
    pub const fn plan_digest(&self) -> Sha256Digest {
        self.plan_digest
    }

    fn recompute_plan_digest(&self) -> Sha256Digest {
        let bytes = canonical_json(&self.canonical_document(None));
        let mut hasher = Sha256::new();
        hasher.update(PLAN_DIGEST_DOMAIN);
        hasher.update(
            u32::try_from(bytes.len())
                .expect("bounded desired specifications fit in u32")
                .to_be_bytes(),
        );
        hasher.update(bytes);
        Sha256Digest::from_bytes(hasher.finalize().into())
    }

    fn canonical_document(&self, plan_sha256: Option<Sha256Digest>) -> CanonicalDesiredSpec<'_> {
        CanonicalDesiredSpec {
            schema: DESIRED_SPEC_SCHEMA,
            installation: CanonicalInstallation {
                id: self.installation_id.to_string(),
                selector_key: self.installation_key.to_string(),
                compose_project: self.compose_project.as_str(),
            },
            platform: CanonicalPlatform {
                architecture: architecture_name(self.profile.architecture),
            },
            capacity: CanonicalCapacity {
                max_parallel_jobs: self.max_parallel_jobs.get(),
            },
            human: CanonicalHuman {
                host_port: self.human_port.get(),
            },
            profile: CanonicalProfile {
                id: self.profile.attestation.id().as_str(),
                manifest_sha256: self.profile.attestation.digest(),
                image: self.profile.image.reference(),
            },
            images: CanonicalImages {
                automata: self.images.automata.reference(),
                runner: self.images.runner.reference(),
                postgres: self.images.postgres.reference(),
                rustfs: self.images.rustfs.reference(),
                sandbox_guest: self.images.sandbox_guest.reference(),
                service_proxy: CanonicalImportedImage {
                    reference: self.images.service_proxy.reference(),
                    config_image_id: self.images.service_proxy.config_image_id(),
                    manifest_image_id: self.images.service_proxy.manifest_image_id(),
                },
            },
            results_transit: CanonicalResultsTransit {
                subnet: self.results_transit.subnet(),
                gateway: self.results_transit.gateway.to_string(),
                results_address: self.results_transit.results_address.to_string(),
            },
            plan_sha256,
        }
    }
}

fn control_subnet(installation: &Installation) -> Ipv4Subnet {
    control_subnet_from_key(installation.selector_key())
}

fn control_subnet_from_key(key: InstallationSelectorKey) -> Ipv4Subnet {
    let digest = key.digest();
    let bytes = digest.as_bytes();
    Ipv4Subnet {
        network: u32::from_be_bytes([172, 16 + (bytes[2] & 0x0f), bytes[3], 0]),
        prefix: 24,
    }
}

fn provider_front_pool(installation: &Installation) -> Ipv4Subnet {
    let digest = installation.selector_key().digest();
    let bytes = digest.as_bytes();
    let bucket = (u32::from(bytes[0]) << 4) | (u32::from(bytes[1]) >> 4);
    Ipv4Subnet {
        network: u32::from_be_bytes([10, 0, 0, 0]) | (bucket << 12),
        prefix: 20,
    }
}

fn parse_ipv4(value: &str) -> Result<Ipv4Addr, DesiredSpecError> {
    value
        .parse::<Ipv4Addr>()
        .ok()
        .filter(|address| address.to_string() == value)
        .ok_or_else(|| DesiredSpecError::new(DesiredSpecErrorCode::ResultsTransit))
}

const fn architecture_name(architecture: EngineArchitecture) -> &'static str {
    match architecture {
        EngineArchitecture::Amd64 => "linux/amd64",
        EngineArchitecture::Arm64 => "linux/arm64",
    }
}

fn canonical_json(value: &impl Serialize) -> Vec<u8> {
    let mut bytes =
        serde_json::to_vec(value).expect("canonical desired specification is serializable");
    bytes.push(b'\n');
    bytes
}

/// Stable reason for rejecting a desired specification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DesiredSpecErrorCode {
    /// Requested runner capacity was zero or exceeded durable slot capacity.
    Capacity,
    /// The profile identity did not match its architecture.
    Profile,
    /// Results transit addressing was not canonical, private, or usable.
    ResultsTransit,
}

impl DesiredSpecErrorCode {
    const fn message(self) -> &'static str {
        match self {
            Self::Capacity => "desired specification capacity is invalid",
            Self::Profile => "desired specification profile is invalid",
            Self::ResultsTransit => "desired specification Results transit network is invalid",
        }
    }
}

/// Sanitized desired-spec validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("{message}")]
pub struct DesiredSpecError {
    code: DesiredSpecErrorCode,
    message: &'static str,
}

impl DesiredSpecError {
    const fn new(code: DesiredSpecErrorCode) -> Self {
        Self {
            code,
            message: code.message(),
        }
    }

    /// Returns the stable machine-readable rejection category.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn code(self) -> DesiredSpecErrorCode {
        self.code
    }
}

#[derive(Serialize)]
struct CanonicalDesiredSpec<'a> {
    schema: &'static str,
    installation: CanonicalInstallation<'a>,
    platform: CanonicalPlatform,
    capacity: CanonicalCapacity,
    human: CanonicalHuman,
    profile: CanonicalProfile<'a>,
    images: CanonicalImages<'a>,
    results_transit: CanonicalResultsTransit,
    #[serde(skip_serializing_if = "Option::is_none")]
    plan_sha256: Option<Sha256Digest>,
}

#[derive(Serialize)]
struct CanonicalInstallation<'a> {
    id: String,
    selector_key: String,
    compose_project: &'a str,
}

#[derive(Serialize)]
struct CanonicalPlatform {
    architecture: &'static str,
}

#[derive(Serialize)]
struct CanonicalCapacity {
    max_parallel_jobs: u16,
}

#[derive(Serialize)]
struct CanonicalHuman {
    host_port: u16,
}

#[derive(Serialize)]
struct CanonicalProfile<'a> {
    id: &'a str,
    manifest_sha256: Sha256Digest,
    image: &'a str,
}

#[derive(Serialize)]
struct CanonicalImages<'a> {
    automata: &'a str,
    runner: &'a str,
    postgres: &'a str,
    rustfs: &'a str,
    sandbox_guest: &'a str,
    service_proxy: CanonicalImportedImage<'a>,
}

#[derive(Serialize)]
struct CanonicalImportedImage<'a> {
    reference: &'a str,
    config_image_id: &'a str,
    manifest_image_id: &'a str,
}

#[derive(Serialize)]
struct CanonicalResultsTransit {
    subnet: String,
    gateway: String,
    results_address: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Ipv4Subnet {
    network: u32,
    prefix: u8,
}

impl Ipv4Subnet {
    fn parse(value: &str) -> Result<Self, DesiredSpecError> {
        let (address, prefix_text) = value
            .split_once('/')
            .ok_or_else(|| DesiredSpecError::new(DesiredSpecErrorCode::ResultsTransit))?;
        let address = parse_ipv4(address)?;
        let prefix = prefix_text
            .parse::<u8>()
            .ok()
            .filter(|prefix| prefix.to_string() == prefix_text && *prefix <= 32)
            .ok_or_else(|| DesiredSpecError::new(DesiredSpecErrorCode::ResultsTransit))?;
        let mask = prefix_mask(prefix);
        let network = u32::from(address);
        if network & mask != network || format!("{address}/{prefix}") != value {
            return Err(DesiredSpecError::new(DesiredSpecErrorCode::ResultsTransit));
        }
        Ok(Self { network, prefix })
    }

    fn first_host(self) -> Ipv4Addr {
        Ipv4Addr::from(self.network + 1)
    }

    const fn broadcast(self) -> u32 {
        self.network | !prefix_mask(self.prefix)
    }

    const fn is_usable(self, address: Ipv4Addr) -> bool {
        let address = u32::from_be_bytes(address.octets());
        address > self.network && address < self.broadcast()
    }

    const fn overlaps(self, other: Self) -> bool {
        self.network <= other.broadcast() && other.network <= self.broadcast()
    }

    const fn is_private(self) -> bool {
        let last = self.broadcast();
        (self.network >= u32::from_be_bytes([10, 0, 0, 0])
            && last <= u32::from_be_bytes([10, 255, 255, 255]))
            || (self.network >= u32::from_be_bytes([172, 16, 0, 0])
                && last <= u32::from_be_bytes([172, 31, 255, 255]))
            || (self.network >= u32::from_be_bytes([192, 168, 0, 0])
                && last <= u32::from_be_bytes([192, 168, 255, 255]))
    }
}

impl std::fmt::Display for Ipv4Subnet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}/{}",
            Ipv4Addr::from(self.network),
            self.prefix
        )
    }
}

const fn prefix_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

#[cfg(test)]
pub(crate) mod tests;
