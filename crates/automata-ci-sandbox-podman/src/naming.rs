use std::{fmt::Write as _, str::FromStr as _};

use automata_ci_execution::{
    EnvironmentProfile, EnvironmentProfileId, OperationId, ProviderId, SandboxGeneration,
    SandboxHandle, Sha256Digest,
};

use crate::{PODMAN_PROVIDER_ID, provider_error};
use sha2::{Digest as _, Sha256};

const HANDLE_VERSION: &str = "p1";
const OWNER_LABEL_KEY: &str = "io.automata.owner";
const OWNER_LABEL_VALUE: &str = "automata-runner";
const SANDBOX_LABEL_KEY: &str = "io.automata.sandbox";
const GENERATION_LABEL_KEY: &str = "io.automata.generation";
const PROFILE_LABEL_KEY: &str = "io.automata.profile";
const PROFILE_DIGEST_LABEL_KEY: &str = "io.automata.profile-sha256";
const SPEC_LABEL_KEY: &str = "io.automata.spec-sha256";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResourceNames {
    identifier: String,
    generation: SandboxGeneration,
}

impl ResourceNames {
    pub(crate) fn for_create(operation_id: OperationId, generation: SandboxGeneration) -> Self {
        Self {
            identifier: operation_id.as_uuid().simple().to_string(),
            generation,
        }
    }

    pub(crate) fn from_handle(
        handle: &SandboxHandle,
        provider_id: &ProviderId,
    ) -> Result<Self, automata_ci_execution::ProviderError> {
        if handle.provider() != provider_id {
            return Err(provider_error::ownership_mismatch(
                automata_ci_execution::ProviderStage::Validate,
            ));
        }
        let mut components = handle.opaque().split('_');
        let Some(version) = components.next() else {
            return Err(provider_error::invalid_state(
                automata_ci_execution::ProviderStage::Validate,
            ));
        };
        let Some(identifier) = components.next() else {
            return Err(provider_error::invalid_state(
                automata_ci_execution::ProviderStage::Validate,
            ));
        };
        let Some(generation) = components.next() else {
            return Err(provider_error::invalid_state(
                automata_ci_execution::ProviderStage::Validate,
            ));
        };
        if version != HANDLE_VERSION
            || identifier.len() != 32
            || !identifier.bytes().all(|byte| byte.is_ascii_hexdigit())
            || components.next().is_some()
        {
            return Err(provider_error::invalid_state(
                automata_ci_execution::ProviderStage::Validate,
            ));
        }
        let hyphenated = format!(
            "{}-{}-{}-{}-{}",
            &identifier[..8],
            &identifier[8..12],
            &identifier[12..16],
            &identifier[16..20],
            &identifier[20..]
        );
        OperationId::from_str(&hyphenated).map_err(|_| {
            provider_error::invalid_state(automata_ci_execution::ProviderStage::Validate)
        })?;
        let generation = generation
            .parse::<u64>()
            .ok()
            .and_then(|value| SandboxGeneration::new(value).ok())
            .ok_or_else(|| {
                provider_error::invalid_state(automata_ci_execution::ProviderStage::Validate)
            })?;
        Ok(Self {
            identifier: identifier.to_owned(),
            generation,
        })
    }

    pub(crate) fn handle(&self) -> SandboxHandle {
        let provider = ProviderId::new(PODMAN_PROVIDER_ID).expect("constant provider id is valid");
        SandboxHandle::new(
            provider,
            format!(
                "{HANDLE_VERSION}_{}_{}",
                self.identifier,
                self.generation.get()
            ),
        )
        .expect("internal handle components are validated")
    }

    pub(crate) const fn generation(&self) -> SandboxGeneration {
        self.generation
    }

    pub(crate) fn network(&self) -> String {
        format!("automata-job-network-{}", self.identifier)
    }

    pub(crate) fn pod(&self) -> String {
        format!("automata-job-pod-{}", self.identifier)
    }

    pub(crate) fn container(&self) -> String {
        format!("automata-job-container-{}", self.identifier)
    }

    pub(crate) fn service(&self, alias: &str) -> String {
        let digest = Sha256::digest(alias.as_bytes());
        let mut suffix = String::with_capacity(64);
        for byte in digest {
            write!(&mut suffix, "{byte:02x}").expect("writing to a string is infallible");
        }
        format!("automata-job-service-{}-{suffix}", self.identifier)
    }

    pub(crate) fn service_proxy(&self) -> String {
        format!("automata-job-service-proxy-{}", self.identifier)
    }

    pub(crate) fn workspace(&self) -> String {
        format!("job-{}", self.identifier)
    }

    pub(crate) fn labels(
        &self,
        profile: &EnvironmentProfile,
        spec_fingerprint: &str,
    ) -> Vec<String> {
        vec![
            format!("{OWNER_LABEL_KEY}={OWNER_LABEL_VALUE}"),
            format!("{SANDBOX_LABEL_KEY}={}", self.identifier),
            format!("{GENERATION_LABEL_KEY}={}", self.generation.get()),
            format!("{PROFILE_LABEL_KEY}={}", profile.id().as_str()),
            format!("{PROFILE_DIGEST_LABEL_KEY}={}", profile.digest()),
            format!("{SPEC_LABEL_KEY}={spec_fingerprint}"),
        ]
    }

    pub(crate) fn expected_ownership(&self) -> OwnershipLabels {
        OwnershipLabels {
            sandbox: self.identifier.clone(),
            generation: self.generation.get().to_string(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnershipLabels {
    sandbox: String,
    generation: String,
}

impl OwnershipLabels {
    pub(crate) fn matches(&self, inspection: &InspectedLabels) -> bool {
        inspection.owner == OWNER_LABEL_VALUE
            && inspection.sandbox == self.sandbox
            && inspection.generation == self.generation
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InspectedLabels {
    owner: String,
    sandbox: String,
    generation: String,
    profile: String,
    profile_digest: String,
    spec_fingerprint: String,
    state: Option<String>,
}

impl InspectedLabels {
    pub(crate) fn parse(bytes: &[u8], includes_state: bool) -> Option<Self> {
        let value = std::str::from_utf8(bytes).ok()?;
        let mut lines = value.lines();
        let owner = lines.next()?.to_owned();
        let sandbox = lines.next()?.to_owned();
        let generation = lines.next()?.to_owned();
        let profile = lines.next()?.to_owned();
        let profile_digest = lines.next()?.to_owned();
        let spec_fingerprint = lines.next()?.to_owned();
        let state = includes_state
            .then(|| lines.next().map(str::to_owned))
            .flatten();
        if lines.next().is_some()
            || owner.len() > 64
            || sandbox.len() > 64
            || generation.len() > 32
            || profile.len() > 128
            || profile_digest.len() != 64
            || !profile_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || spec_fingerprint.len() != 64
            || !spec_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || state.as_ref().is_some_and(|value| value.len() > 32)
        {
            return None;
        }
        Some(Self {
            owner,
            sandbox,
            generation,
            profile,
            profile_digest,
            spec_fingerprint,
            state,
        })
    }

    pub(crate) fn profile(&self) -> Option<EnvironmentProfile> {
        let id = EnvironmentProfileId::new(self.profile.clone()).ok()?;
        let digest = Sha256Digest::from_str(&self.profile_digest).ok()?;
        Some(EnvironmentProfile::new(id, digest))
    }

    pub(crate) fn state(&self) -> Option<&str> {
        self.state.as_deref()
    }

    pub(crate) fn spec_fingerprint(&self) -> &str {
        &self.spec_fingerprint
    }
}

pub(crate) fn label_format(container: bool, include_state: bool) -> String {
    let prefix = if container {
        ".Config.Labels"
    } else {
        ".Labels"
    };
    let mut format = format!(
        "{{{{ index {prefix} \"{OWNER_LABEL_KEY}\" }}}}\n\
         {{{{ index {prefix} \"{SANDBOX_LABEL_KEY}\" }}}}\n\
         {{{{ index {prefix} \"{GENERATION_LABEL_KEY}\" }}}}\n\
         {{{{ index {prefix} \"{PROFILE_LABEL_KEY}\" }}}}\n\
         {{{{ index {prefix} \"{PROFILE_DIGEST_LABEL_KEY}\" }}}}\n\
         {{{{ index {prefix} \"{SPEC_LABEL_KEY}\" }}}}"
    );
    if include_state {
        format.push_str("\n{{.State.Status}}");
    }
    format
}
