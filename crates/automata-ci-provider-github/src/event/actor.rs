use std::{fmt, num::NonZeroU64};

use serde::{Deserialize, Serialize};

use crate::webhook::{GithubWebhookError, durable_provider_id};

const MAX_GITHUB_ACTOR_LOGIN_BYTES: usize = 255;

/// Closed GitHub account classification retained from an authenticated event.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubEventActorKind {
    /// A human or service user account.
    User,
    /// A GitHub App or other bot account.
    Bot,
    /// An organization account.
    Organization,
    /// A placeholder account used for an imported identity.
    Mannequin,
}

impl GithubEventActorKind {
    fn from_webhook(value: &str) -> Option<Self> {
        match value {
            "User" => Some(Self::User),
            "Bot" => Some(Self::Bot),
            "Organization" => Some(Self::Organization),
            "Mannequin" => Some(Self::Mannequin),
            _ => None,
        }
    }
}

/// Stable actor facts retained from an authenticated GitHub webhook body.
///
/// The bounded login and closed account kind are retained when GitHub supplies
/// them so authorization can fail closed without reparsing the raw JSON object.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GithubEventActor {
    id: NonZeroU64,
    login: Option<Box<str>>,
    kind: Option<GithubEventActorKind>,
}

impl GithubEventActor {
    pub(crate) fn from_webhook_fields(
        id: u64,
        login: Option<String>,
        kind: Option<&str>,
    ) -> Result<Self, GithubWebhookError> {
        let id = durable_provider_id(id)?;
        let login = login.map(normalize_login).transpose()?;
        // A future provider kind remains incomplete classification, allowing
        // authorization to deny trust without treating signed bytes as malformed.
        let kind = kind.and_then(GithubEventActorKind::from_webhook);
        Ok(Self { id, login, kind })
    }

    pub(crate) fn validate(&self) -> Result<(), GithubWebhookError> {
        durable_provider_id(self.id.get())?;
        if let Some(login) = &self.login {
            normalize_login(login.to_string())?;
        }
        Ok(())
    }

    /// Returns GitHub's stable positive actor identifier.
    #[must_use]
    pub const fn id(&self) -> NonZeroU64 {
        self.id
    }

    /// Returns the bounded provider login when it was present in the payload.
    #[must_use]
    pub fn login(&self) -> Option<&str> {
        self.login.as_deref()
    }

    /// Returns the closed provider account kind when it was present.
    #[must_use]
    pub const fn kind(&self) -> Option<GithubEventActorKind> {
        self.kind
    }

    /// Returns whether both classification facts needed for trust evaluation
    /// were present in the authenticated webhook body.
    #[must_use]
    pub const fn has_complete_classification(&self) -> bool {
        self.login.is_some() && self.kind.is_some()
    }
}

impl fmt::Debug for GithubEventActor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubEventActor")
            .field("id", &self.id)
            .field("login", &self.login.as_ref().map(|_| "[redacted]"))
            .field("kind", &self.kind)
            .finish()
    }
}

fn normalize_login(login: String) -> Result<Box<str>, GithubWebhookError> {
    if login.is_empty()
        || login.len() > MAX_GITHUB_ACTOR_LOGIN_BYTES
        || !login.is_ascii()
        || login.bytes().any(|byte| {
            byte.is_ascii_control() || byte.is_ascii_whitespace() || matches!(byte, b'/' | b'\\')
        })
    {
        return Err(GithubWebhookError::InvalidPayload);
    }
    Ok(login.into_boxed_str())
}
