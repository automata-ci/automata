//! Closed daemon-local identity for the imported service-proxy image.

use thiserror::Error;

const LOCAL_SERVICE_PROXY_REPOSITORY: &str = "automata.local/automata-ci-service-proxy";

/// Exact daemon-local service-proxy import identity.
///
/// Unlike registry images, a classic Docker image imported from a portable
/// save archive has no repository digest. The deterministic tag is therefore
/// retained together with both acceptable content IDs and must be reattested
/// before every operation that consumes the image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalImportedImage {
    reference: String,
    config_image_id: String,
    manifest_image_id: String,
}

impl LocalImportedImage {
    /// Derives the sole current local import reference from its OCI identities.
    ///
    /// # Errors
    ///
    /// Rejects either identity unless it is one canonical lowercase SHA-256
    /// Docker image ID.
    pub fn new(
        config_image_id: impl Into<String>,
        manifest_image_id: impl Into<String>,
    ) -> Result<Self, LocalImportedImageError> {
        let config_image_id = config_image_id.into();
        let manifest_image_id = manifest_image_id.into();
        if !oci_image_id(&config_image_id) || !oci_image_id(&manifest_image_id) {
            return Err(LocalImportedImageError);
        }
        let Some(manifest_hex) = manifest_image_id.strip_prefix("sha256:") else {
            return Err(LocalImportedImageError);
        };
        Ok(Self {
            reference: format!("{LOCAL_SERVICE_PROXY_REPOSITORY}:manifest-{manifest_hex}"),
            config_image_id,
            manifest_image_id,
        })
    }

    /// Returns the deterministic daemon-local tag.
    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// Returns the canonical config identity produced by classic Docker.
    #[must_use]
    pub fn config_image_id(&self) -> &str {
        &self.config_image_id
    }

    /// Returns the canonical manifest identity produced by containerd storage.
    #[must_use]
    pub fn manifest_image_id(&self) -> &str {
        &self.manifest_image_id
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn accepts_live_representation(
        &self,
        image_id: &str,
        repository_tags: &[String],
        repository_digests: &[String],
    ) -> bool {
        if repository_tags != std::slice::from_ref(&self.reference) {
            return false;
        }
        if image_id == self.config_image_id {
            repository_digests.is_empty()
        } else if image_id == self.manifest_image_id {
            repository_digests
                == [format!(
                    "{LOCAL_SERVICE_PROXY_REPOSITORY}@{}",
                    self.manifest_image_id
                )]
        } else {
            false
        }
    }
}

/// A daemon-local imported image identity was not canonical.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("daemon-local imported image identity is invalid")]
pub struct LocalImportedImageError;

fn oci_image_id(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}
