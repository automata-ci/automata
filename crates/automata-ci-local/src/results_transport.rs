use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::Ipv4Addr,
};

use automata_ci_core::Sha256Digest;

use crate::{LocalDockerError, LocalDockerErrorCode, LocalImportedImage};

pub(crate) const RESULTS_TRANSPORT_OWNERSHIP: &str = "lifecycle-created-compose-external";
pub(crate) const RESULTS_TRANSPORT_SCHEMA: &str = "2";
pub(crate) const RESULTS_TRANSIT_GATEWAY_MODE_KEY: &str =
    "com.docker.network.bridge.gateway_mode_ipv4";
pub(crate) const RESULTS_TRANSIT_GATEWAY_MODE_VALUE: &str = "isolated";
pub(crate) const MAX_RESULTS_TRANSIT_ENDPOINTS: usize =
    crate::MAXIMUM_LOCAL_DOCKER_JOB_SLOTS as usize + 2;

pub(crate) const LABEL_RESULTS_TRANSPORT_SCHEMA: &str =
    "io.automata.local.results-transport-schema";
pub(crate) const LABEL_PLAN_DIGEST: &str = "io.automata.local.plan-digest";
const LABEL_MANAGED: &str = "io.automata.local.managed";
const LABEL_INSTALLATION_ID: &str = "io.automata.local.installation-id";
const LABEL_INSTALLATION_KEY: &str = "io.automata.local.installation-key";
const LABEL_COMPOSE_PROJECT: &str = "io.automata.local.compose-project";
const LABEL_RESOURCE_KIND: &str = "io.automata.local.resource-kind";
const KIND_RESULTS_TRANSIT: &str = "results-transit-network";

/// Shared immutable shape of the lifecycle-owned Results transit.
///
/// Both lifecycle convergence and the Local Docker provider normalize their
/// Engine-specific inspection models into this shape before accepting the
/// shared network. Keeping one closed predicate prevents either consumer from
/// silently weakening the other one's custody contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResultsTransitNetworkShape {
    pub(crate) name: String,
    pub(crate) driver: String,
    pub(crate) scope: String,
    pub(crate) enable_ipv4: bool,
    pub(crate) enable_ipv6: bool,
    pub(crate) internal: bool,
    pub(crate) attachable: bool,
    pub(crate) ingress: bool,
    pub(crate) config_only: bool,
    pub(crate) config_from_empty: bool,
    pub(crate) ipam_driver: String,
    pub(crate) ipam_options: BTreeMap<String, String>,
    pub(crate) options: BTreeMap<String, String>,
    pub(crate) labels: BTreeMap<String, String>,
    pub(crate) endpoint_ids: BTreeSet<String>,
}

pub(crate) fn results_transit_name(installation: &crate::Installation) -> String {
    format!("{}-results-transit", installation.compose_project())
}

pub(crate) fn results_transit_labels(
    installation: &crate::Installation,
    plan_digest: Sha256Digest,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        (LABEL_MANAGED.to_owned(), "true".to_owned()),
        (
            LABEL_RESULTS_TRANSPORT_SCHEMA.to_owned(),
            RESULTS_TRANSPORT_SCHEMA.to_owned(),
        ),
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
        (LABEL_PLAN_DIGEST.to_owned(), plan_digest.to_string()),
        (
            LABEL_RESOURCE_KIND.to_owned(),
            KIND_RESULTS_TRANSIT.to_owned(),
        ),
    ])
}

pub(crate) fn exact_results_transit_base(
    shape: &ResultsTransitNetworkShape,
    installation: &crate::Installation,
    plan_digest: Sha256Digest,
) -> bool {
    shape.name == results_transit_name(installation)
        && shape.driver == "bridge"
        && shape.scope == "local"
        && shape.enable_ipv4
        && !shape.enable_ipv6
        && shape.internal
        && !shape.attachable
        && !shape.ingress
        && !shape.config_only
        && shape.config_from_empty
        && shape.ipam_driver == "default"
        && shape.ipam_options.is_empty()
        && shape.options
            == BTreeMap::from([(
                RESULTS_TRANSIT_GATEWAY_MODE_KEY.to_owned(),
                RESULTS_TRANSIT_GATEWAY_MODE_VALUE.to_owned(),
            )])
        && shape.labels == results_transit_labels(installation, plan_digest)
        && shape.endpoint_ids.len() <= MAX_RESULTS_TRANSIT_ENDPOINTS
        && shape.endpoint_ids.iter().all(|id| canonical_object_id(id))
}

/// Closed pre-provisioned Results transport consumed by the local Docker provider.
///
/// The installation lifecycle, not the per-sandbox provider, owns the shared
/// transit network and the control-plane Results interface. This value pins
/// their immutable Engine identities, desired plan, and credential-free
/// daemon-local imported relay image; it cannot describe an arbitrary network,
/// port, or target.
#[derive(Clone, Eq, PartialEq)]
pub struct LocalDockerResultsTransport {
    pub(crate) proxy_image: LocalImportedImage,
    pub(crate) plan_digest: Sha256Digest,
    pub(crate) transit_network_id: String,
    pub(crate) results_container_id: String,
    pub(crate) results_address: Ipv4Addr,
}

impl LocalDockerResultsTransport {
    /// Constructs one exact pre-provisioned local Results route.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical Engine object identities and non-private target
    /// addresses. The fixed listener and target port is always 8081.
    pub fn new(
        proxy_image: LocalImportedImage,
        plan_digest: Sha256Digest,
        transit_network_id: impl Into<String>,
        results_container_id: impl Into<String>,
        results_address: Ipv4Addr,
    ) -> Result<Self, LocalDockerError> {
        let transit_network_id = transit_network_id.into();
        let results_container_id = results_container_id.into();
        if !canonical_object_id(&transit_network_id)
            || !canonical_object_id(&results_container_id)
            || !results_address.is_private()
        {
            return Err(LocalDockerError::new(
                LocalDockerErrorCode::ResultsTransportMismatch,
            ));
        }
        Ok(Self {
            proxy_image,
            plan_digest,
            transit_network_id,
            results_container_id,
            results_address,
        })
    }

    /// Returns the exact daemon-local imported credential-free proxy identity.
    #[must_use]
    pub const fn proxy_image(&self) -> &LocalImportedImage {
        &self.proxy_image
    }

    /// Returns the canonical desired-plan digest that owns the shared route.
    #[must_use]
    pub const fn plan_digest(&self) -> Sha256Digest {
        self.plan_digest
    }

    /// Returns the exact pre-provisioned transit-network Engine identity.
    #[must_use]
    pub fn transit_network_id(&self) -> &str {
        &self.transit_network_id
    }

    /// Returns the exact Results-container Engine identity.
    #[must_use]
    pub fn results_container_id(&self) -> &str {
        &self.results_container_id
    }

    /// Returns the exact private numeric Results target address.
    #[must_use]
    pub const fn results_address(&self) -> Ipv4Addr {
        self.results_address
    }
}

impl fmt::Debug for LocalDockerResultsTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalDockerResultsTransport")
            .field("proxy_image", &self.proxy_image)
            .field("plan_digest", &self.plan_digest)
            .field("transit_network_id", &"[REDACTED]")
            .field("results_container_id", &"[REDACTED]")
            .field("results_address", &self.results_address)
            .finish()
    }
}

pub(crate) fn canonical_object_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
