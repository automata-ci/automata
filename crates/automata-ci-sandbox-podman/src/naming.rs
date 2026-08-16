use std::{fmt::Write as _, num::NonZeroU16, str::FromStr as _};

use automata_ci_execution::{
    EnvironmentProfile, EnvironmentProfileId, OperationId, ProviderId, RunnerId, SandboxCustody,
    SandboxGeneration, SandboxHandle, Sha256Digest,
};

use crate::{PODMAN_PROVIDER_ID, provider_error};
use sha2::{Digest as _, Sha256};

const HANDLE_VERSION: &str = "p2";
const RESOURCE_SCHEMA_LABEL_KEY: &str = "io.automata.sandbox-schema";
const RESOURCE_SCHEMA: &str = "2";
const OWNER_LABEL_KEY: &str = "io.automata.owner";
const OWNER_LABEL_VALUE: &str = "automata-runner";
const SANDBOX_LABEL_KEY: &str = "io.automata.sandbox";
const GENERATION_LABEL_KEY: &str = "io.automata.generation";
const PROFILE_LABEL_KEY: &str = "io.automata.profile";
const PROFILE_DIGEST_LABEL_KEY: &str = "io.automata.profile-sha256";
const SPEC_LABEL_KEY: &str = "io.automata.spec-sha256";
const CUSTODY_KIND_LABEL_KEY: &str = "io.automata.custody-kind";
const CUSTODY_RUNNER_LABEL_KEY: &str = "io.automata.custody-runner";
const CUSTODY_SLOT_LABEL_KEY: &str = "io.automata.custody-slot";

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
        custody: SandboxCustody,
    ) -> Vec<String> {
        let (custody_kind, custody_runner, custody_slot) = match custody {
            SandboxCustody::ProfileAdmission { runner_id } => {
                ("profile-admission", runner_id.to_string(), "0".to_owned())
            }
            SandboxCustody::Job {
                runner_id,
                slot_ordinal,
            } => ("job", runner_id.to_string(), slot_ordinal.get().to_string()),
        };
        vec![
            format!("{OWNER_LABEL_KEY}={OWNER_LABEL_VALUE}"),
            format!("{RESOURCE_SCHEMA_LABEL_KEY}={RESOURCE_SCHEMA}"),
            format!("{SANDBOX_LABEL_KEY}={}", self.identifier),
            format!("{GENERATION_LABEL_KEY}={}", self.generation.get()),
            format!("{PROFILE_LABEL_KEY}={}", profile.id().as_str()),
            format!("{PROFILE_DIGEST_LABEL_KEY}={}", profile.digest()),
            format!("{SPEC_LABEL_KEY}={spec_fingerprint}"),
            format!("{CUSTODY_KIND_LABEL_KEY}={custody_kind}"),
            format!("{CUSTODY_RUNNER_LABEL_KEY}={custody_runner}"),
            format!("{CUSTODY_SLOT_LABEL_KEY}={custody_slot}"),
        ]
    }

    pub(crate) fn expected_ownership(&self, custody: SandboxCustody) -> OwnershipLabels {
        OwnershipLabels {
            sandbox: self.identifier.clone(),
            generation: self.generation.get().to_string(),
            custody,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnershipLabels {
    sandbox: String,
    generation: String,
    custody: SandboxCustody,
}

impl OwnershipLabels {
    pub(crate) fn matches(&self, inspection: &InspectedLabels) -> bool {
        inspection.owner == OWNER_LABEL_VALUE
            && inspection.schema == RESOURCE_SCHEMA
            && inspection.sandbox == self.sandbox
            && inspection.generation == self.generation
            && inspection.custody == self.custody
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InspectedLabels {
    owner: String,
    schema: String,
    sandbox: String,
    generation: String,
    profile: String,
    profile_digest: String,
    spec_fingerprint: String,
    custody: SandboxCustody,
    state: Option<String>,
}

impl InspectedLabels {
    pub(crate) fn parse(bytes: &[u8], includes_state: bool) -> Option<Self> {
        let value = std::str::from_utf8(bytes).ok()?;
        let mut lines = value.lines();
        let owner = lines.next()?.to_owned();
        let schema = lines.next()?.to_owned();
        let sandbox = lines.next()?.to_owned();
        let generation = lines.next()?.to_owned();
        let profile = lines.next()?.to_owned();
        let profile_digest = lines.next()?.to_owned();
        let spec_fingerprint = lines.next()?.to_owned();
        let custody_kind = lines.next()?;
        let custody_runner = lines.next()?;
        let custody_slot = lines.next()?;
        let state = includes_state
            .then(|| lines.next().map(str::to_owned))
            .flatten();
        if lines.next().is_some()
            || owner.len() > 64
            || schema != RESOURCE_SCHEMA
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
        let runner_id = RunnerId::from_str(custody_runner).ok()?;
        let slot = custody_slot.parse::<u16>().ok()?;
        let custody = match custody_kind {
            "profile-admission" if slot == 0 => SandboxCustody::ProfileAdmission { runner_id },
            "job" => SandboxCustody::Job {
                runner_id,
                slot_ordinal: NonZeroU16::new(slot)?,
            },
            _ => return None,
        };
        Some(Self {
            owner,
            schema,
            sandbox,
            generation,
            profile,
            profile_digest,
            spec_fingerprint,
            custody,
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

    pub(crate) const fn custody(&self) -> SandboxCustody {
        self.custody
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
         {{{{ index {prefix} \"{RESOURCE_SCHEMA_LABEL_KEY}\" }}}}\n\
         {{{{ index {prefix} \"{SANDBOX_LABEL_KEY}\" }}}}\n\
         {{{{ index {prefix} \"{GENERATION_LABEL_KEY}\" }}}}\n\
         {{{{ index {prefix} \"{PROFILE_LABEL_KEY}\" }}}}\n\
         {{{{ index {prefix} \"{PROFILE_DIGEST_LABEL_KEY}\" }}}}\n\
         {{{{ index {prefix} \"{SPEC_LABEL_KEY}\" }}}}\n\
         {{{{ index {prefix} \"{CUSTODY_KIND_LABEL_KEY}\" }}}}\n\
         {{{{ index {prefix} \"{CUSTODY_RUNNER_LABEL_KEY}\" }}}}\n\
         {{{{ index {prefix} \"{CUSTODY_SLOT_LABEL_KEY}\" }}}}"
    );
    if include_state {
        format.push_str("\n{{.State.Status}}");
    }
    format
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_handle_reader_rejects_noncurrent_versions() {
        let provider = ProviderId::new(PODMAN_PROVIDER_ID).expect("provider ID");
        let current = ResourceNames::for_create(
            OperationId::new(),
            SandboxGeneration::new(1).expect("generation"),
        )
        .handle();

        for version in ["p0", "p1", "p3"] {
            let opaque = current.opaque().replacen(HANDLE_VERSION, version, 1);
            let handle = SandboxHandle::new(provider.clone(), opaque).expect("well-formed handle");
            assert!(
                ResourceNames::from_handle(&handle, &provider).is_err(),
                "accepted handle version {version}"
            );
        }
    }
}
