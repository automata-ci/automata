use std::str::FromStr as _;

use automata_ci_execution::{
    OperationId, ProviderError, ProviderErrorKind, ProviderId, ProviderStage, SandboxGeneration,
    SandboxHandle,
};

use crate::{WINDOWS_HYPERV_PROVIDER_ID, error};

const HANDLE_VERSION: &str = "wh1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResourceName {
    identifier: String,
    generation: SandboxGeneration,
}

impl ResourceName {
    pub(crate) fn for_create(operation_id: OperationId, generation: SandboxGeneration) -> Self {
        Self {
            identifier: operation_id.as_uuid().simple().to_string(),
            generation,
        }
    }

    pub(crate) fn from_handle(
        handle: &SandboxHandle,
        provider_id: &ProviderId,
    ) -> Result<Self, ProviderError> {
        if handle.provider() != provider_id {
            return Err(error::known(
                ProviderErrorKind::OwnershipMismatch,
                ProviderStage::Validate,
            ));
        }
        let mut parts = handle.opaque().split('_');
        let version = parts.next();
        let identifier = parts.next();
        let generation = parts.next();
        if version != Some(HANDLE_VERSION)
            || parts.next().is_some()
            || identifier.is_none_or(|value| {
                value.len() != 32
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
        {
            return Err(error::known(
                ProviderErrorKind::InvalidState,
                ProviderStage::Validate,
            ));
        }
        let generation = generation
            .and_then(|value| value.parse::<u64>().ok())
            .and_then(|value| SandboxGeneration::new(value).ok())
            .ok_or_else(|| {
                error::known(ProviderErrorKind::InvalidState, ProviderStage::Validate)
            })?;
        let identifier = identifier.unwrap_or_default().to_owned();
        let hyphenated = format!(
            "{}-{}-{}-{}-{}",
            &identifier[..8],
            &identifier[8..12],
            &identifier[12..16],
            &identifier[16..20],
            &identifier[20..]
        );
        OperationId::from_str(&hyphenated)
            .map_err(|_| error::known(ProviderErrorKind::InvalidState, ProviderStage::Validate))?;
        Ok(Self {
            identifier,
            generation,
        })
    }

    pub(crate) fn handle(&self) -> SandboxHandle {
        SandboxHandle::new(
            ProviderId::new(WINDOWS_HYPERV_PROVIDER_ID).expect("constant provider ID"),
            format!(
                "{HANDLE_VERSION}_{}_{}",
                self.identifier,
                self.generation.get()
            ),
        )
        .expect("internal handle components are valid")
    }

    pub(crate) fn container(&self) -> String {
        format!("automata-windows-hyperv-{}", self.identifier)
    }

    pub(crate) const fn generation(&self) -> SandboxGeneration {
        self.generation
    }

    pub(crate) fn identifier(&self) -> &str {
        &self.identifier
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_round_trip_exact_identity_and_generation() {
        let operation = OperationId::new();
        let generation = SandboxGeneration::new(41).expect("generation");
        let names = ResourceName::for_create(operation, generation);
        let provider = ProviderId::new(WINDOWS_HYPERV_PROVIDER_ID).expect("provider");
        assert_eq!(
            ResourceName::from_handle(&names.handle(), &provider).expect("round trip"),
            names
        );

        let stale = SandboxHandle::new(
            provider.clone(),
            format!("{HANDLE_VERSION}_{}_40", names.identifier()),
        )
        .expect("stale handle syntax");
        assert_ne!(
            ResourceName::from_handle(&stale, &provider)
                .expect("stale generation remains parseable")
                .generation(),
            generation
        );
        let noncurrent =
            SandboxHandle::new(provider.clone(), format!("wh0_{}_41", names.identifier()))
                .expect("noncurrent handle syntax");
        assert_eq!(
            ResourceName::from_handle(&noncurrent, &provider)
                .expect_err("noncurrent handle version must fail closed")
                .kind(),
            ProviderErrorKind::InvalidState
        );
        let foreign = ProviderId::new("foreign-provider").expect("foreign provider");
        assert_eq!(
            ResourceName::from_handle(&names.handle(), &foreign)
                .expect_err("provider identity mismatch")
                .kind(),
            ProviderErrorKind::OwnershipMismatch
        );
    }
}
