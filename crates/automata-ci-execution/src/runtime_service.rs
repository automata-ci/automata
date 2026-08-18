use std::num::NonZeroU16;

use url::{Host, Url};

use crate::ValueError;

/// Maximum exact HTTP(S) origins exposed through a sandbox runtime-service proxy.
pub const MAX_RUNTIME_SERVICE_ROUTES: usize = 16;

/// Application protocol accepted for one exact runtime-service route.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RuntimeServiceProtocol {
    /// Plain HTTP, limited to deployments which separately trust that transport.
    Http,
    /// HTTP protected end to end by TLS.
    Https,
}

/// One credential-free HTTP(S) origin which a sandbox may reach through a
/// provider-controlled runtime-service proxy.
///
/// The route contains only the normalized scheme, host, and effective port.
/// URL paths, credentials, headers, and bearer values never enter the sandbox
/// provider contract.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RuntimeServiceRoute {
    protocol: RuntimeServiceProtocol,
    host: String,
    port: NonZeroU16,
}

impl RuntimeServiceRoute {
    /// Reduces a validated HTTP(S) URL to its exact network origin.
    ///
    /// # Errors
    ///
    /// Rejects non-HTTP schemes, missing hosts, URL credentials, and origins
    /// without a non-zero effective port.
    pub fn from_url(url: &Url) -> Result<Self, ValueError> {
        let protocol = match url.scheme() {
            "http" => RuntimeServiceProtocol::Http,
            "https" => RuntimeServiceProtocol::Https,
            _ => return Err(ValueError::InvalidRuntimeServiceRoute),
        };
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ValueError::InvalidRuntimeServiceRoute);
        }
        let host = match url.host().ok_or(ValueError::InvalidRuntimeServiceRoute)? {
            Host::Domain(host) => host.to_owned(),
            Host::Ipv4(address) => address.to_string(),
            Host::Ipv6(address) => address.to_string(),
        };
        let port = url
            .port_or_known_default()
            .and_then(NonZeroU16::new)
            .ok_or(ValueError::InvalidRuntimeServiceRoute)?;
        Ok(Self {
            protocol,
            host,
            port,
        })
    }

    /// Returns the exact application protocol accepted by the route.
    #[must_use]
    pub const fn protocol(&self) -> RuntimeServiceProtocol {
        self.protocol
    }

    /// Returns the normalized DNS name or unbracketed IP literal.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the exact non-zero destination port.
    #[must_use]
    pub const fn port(&self) -> NonZeroU16 {
        self.port
    }
}

/// Canonical bounded set of credential-free runtime-service origins.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimeServiceRoutes(Vec<RuntimeServiceRoute>);

impl RuntimeServiceRoutes {
    /// Creates a sorted, duplicate-free route set.
    ///
    /// # Errors
    ///
    /// Rejects input containing more than [`MAX_RUNTIME_SERVICE_ROUTES`]
    /// entries before canonicalization.
    pub fn new(routes: impl IntoIterator<Item = RuntimeServiceRoute>) -> Result<Self, ValueError> {
        let mut routes: Vec<_> = routes.into_iter().collect();
        if routes.len() > MAX_RUNTIME_SERVICE_ROUTES {
            return Err(ValueError::InvalidRuntimeServiceRoute);
        }
        routes.sort_unstable();
        routes.dedup();
        Ok(Self(routes))
    }

    /// Returns an empty route set.
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// Returns routes in canonical order.
    #[must_use]
    pub fn as_slice(&self) -> &[RuntimeServiceRoute] {
        &self.0
    }

    /// Returns whether no runtime-service origin is requested.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
