use std::{fmt, net::Ipv4Addr};

use automata_ci_core::Sha256Digest;

use crate::{LocalDockerError, LocalDockerErrorCode, LocalImportedImage};

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

fn canonical_object_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
