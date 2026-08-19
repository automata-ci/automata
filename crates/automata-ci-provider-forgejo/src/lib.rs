//! Native Forgejo provider boundaries.
//!
//! This crate deliberately keeps Forgejo authentication, configuration, and
//! webhook verification provider-specific. Normalized delivery evidence is
//! emitted through the common provider traits in a later adapter slice.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod factory;
mod webhook;

pub use factory::{
    FORGEJO_ACCESS_TOKEN_SECRET_NAME, FORGEJO_WEBHOOK_SECRET_NAME, ForgejoConnectionPolicy,
    ForgejoFactoryError, ForgejoInstanceConfiguration, ForgejoProviderFactory,
};
pub use webhook::{
    FORGEJO_AUTHENTICATED_EVENT_MEDIA_TYPE, FORGEJO_WEBHOOK_BODY_LIMIT,
    FORGEJO_WEBHOOK_SECRET_LIMIT, ForgejoAuthenticatedWebhook, ForgejoWebhookBodyDigest,
    ForgejoWebhookError, ForgejoWebhookVerifier, ForgejoWebhookVerifierFingerprint,
    X_FORGEJO_EVENT, X_FORGEJO_SIGNATURE, X_GITEA_DELIVERY,
};
