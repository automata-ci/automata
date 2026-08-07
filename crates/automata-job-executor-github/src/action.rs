use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_action::{
    ActionBundleLimits, ActionResolveErrorKind, ActionResolver, ActionSubpath,
    RepositoryActionRequest,
};
use automata_action_github::{
    ActionMetadataDecoder, GithubActionMetadata, MetadataScalar, MetadataScalarKind,
};
use automata_blob::ImmutableBlobStore;
use automata_core::ActionReference;
use automata_scm::{RepositoryId, RevisionSpec};
use automata_workflow_github::{GithubConditionCompiler, GithubConditionPhase};

use crate::{
    ActionPreparationError, ActionPreparationPort, ActionPreparationRequest, PreparedAction,
    PreparedInput, PreparedJavascriptAction, PreparedValue, RepositoryCredentialPort,
    error::{ActionPreparationErrorKind, PortErrorKind},
};

/// Concrete composition of immutable action resolution, blob reads, credential
/// lookup, GitHub metadata decoding, and condition compilation.
pub struct ResolvedBundleActionPreparer {
    resolver: Arc<dyn ActionResolver>,
    blobs: Arc<dyn ImmutableBlobStore>,
    credentials: Arc<dyn RepositoryCredentialPort>,
    decoder: Arc<dyn ActionMetadataDecoder>,
    conditions: GithubConditionCompiler,
    bundle_limits: ActionBundleLimits,
    maximum_archive_bytes: u64,
}

impl ResolvedBundleActionPreparer {
    /// Creates a repository-action preparation adapter.
    ///
    /// `maximum_archive_bytes` must not exceed the provider-neutral endpoint
    /// copy ceiling; larger bundles require a future streaming copy capability.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero or excessive archive read bound.
    pub fn new(
        resolver: Arc<dyn ActionResolver>,
        blobs: Arc<dyn ImmutableBlobStore>,
        credentials: Arc<dyn RepositoryCredentialPort>,
        decoder: Arc<dyn ActionMetadataDecoder>,
        conditions: GithubConditionCompiler,
        bundle_limits: ActionBundleLimits,
        maximum_archive_bytes: u64,
    ) -> Result<Self, ActionPreparationError> {
        if maximum_archive_bytes == 0
            || maximum_archive_bytes > automata_execution::MAX_COPY_BYTES as u64
        {
            return Err(ActionPreparationError::new(
                ActionPreparationErrorKind::ResourceExhausted,
            ));
        }
        Ok(Self {
            resolver,
            blobs,
            credentials,
            decoder,
            conditions,
            bundle_limits,
            maximum_archive_bytes,
        })
    }
}

impl fmt::Debug for ResolvedBundleActionPreparer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedBundleActionPreparer")
            .field("resolver", &self.resolver)
            .field("blobs", &self.blobs)
            .field("credentials", &self.credentials)
            .field("decoder", &self.decoder)
            .field("conditions", &self.conditions)
            .field("bundle_limits", &self.bundle_limits)
            .field("maximum_archive_bytes", &self.maximum_archive_bytes)
            .finish()
    }
}

#[async_trait]
impl ActionPreparationPort for ResolvedBundleActionPreparer {
    async fn prepare(
        &self,
        request: ActionPreparationRequest<'_>,
    ) -> Result<PreparedAction, ActionPreparationError> {
        let ActionReference::Repository {
            repository,
            revision,
            subpath,
        } = request.reference()
        else {
            return Err(ActionPreparationError::new(
                ActionPreparationErrorKind::UnsupportedReference,
            ));
        };
        let repository = RepositoryId::new(repository.clone()).map_err(|_| internal())?;
        let revision = RevisionSpec::new(revision.clone()).map_err(|_| internal())?;
        let subpath = match subpath {
            Some(value) => ActionSubpath::new(value.clone()).map_err(|_| internal())?,
            None => ActionSubpath::root(),
        };
        let credential = self.credentials.credential(&repository).map_err(|error| {
            let kind = match error.kind() {
                PortErrorKind::PermissionDenied => ActionPreparationErrorKind::PermissionDenied,
                PortErrorKind::ResourceExhausted => ActionPreparationErrorKind::ResourceExhausted,
                PortErrorKind::NotFound
                | PortErrorKind::Unavailable
                | PortErrorKind::InvalidData
                | PortErrorKind::Unsupported
                | PortErrorKind::Internal => ActionPreparationErrorKind::Resolution,
            };
            ActionPreparationError::new(kind)
        })?;
        let action_request = credential.as_ref().map_or_else(
            || {
                RepositoryActionRequest::public(
                    &repository,
                    &revision,
                    &subpath,
                    self.bundle_limits,
                )
            },
            |credential| {
                RepositoryActionRequest::authenticated(
                    &repository,
                    &revision,
                    &subpath,
                    credential,
                    self.bundle_limits,
                )
            },
        );
        let bundle = self
            .resolver
            .resolve(action_request)
            .await
            .map_err(|error| {
                let kind = match error.kind() {
                    ActionResolveErrorKind::Scm | ActionResolveErrorKind::ReferenceCache => {
                        ActionPreparationErrorKind::Resolution
                    }
                    ActionResolveErrorKind::Archive | ActionResolveErrorKind::BlobStore => {
                        ActionPreparationErrorKind::Content
                    }
                    ActionResolveErrorKind::Internal => ActionPreparationErrorKind::Internal,
                };
                ActionPreparationError::new(kind)
            })?;
        let metadata = self
            .decoder
            .decode(bundle.definition())
            .map_err(|_| ActionPreparationError::new(ActionPreparationErrorKind::Metadata))?;
        let archive = self
            .blobs
            .get_verified(bundle.archive(), self.maximum_archive_bytes)
            .await
            .map_err(|_| ActionPreparationError::new(ActionPreparationErrorKind::Content))?;
        prepare_metadata(
            &metadata,
            bundle.archive().digest(),
            archive.into_bytes(),
            bundle.subpath().as_str(),
            &self.conditions,
        )
    }
}

fn prepare_metadata(
    metadata: &GithubActionMetadata,
    archive_digest: automata_core::Sha256Digest,
    archive: bytes::Bytes,
    subpath: &str,
    conditions: &GithubConditionCompiler,
) -> Result<PreparedAction, ActionPreparationError> {
    let javascript = metadata.javascript().ok_or_else(|| {
        ActionPreparationError::new(ActionPreparationErrorKind::UnsupportedExecution)
    })?;
    let pre_condition = conditions
        .compile_condition(
            Some(javascript.pre_condition().text()),
            GithubConditionPhase::Step,
        )
        .map_err(|_| ActionPreparationError::new(ActionPreparationErrorKind::Metadata))?;
    let post_condition = conditions
        .compile_condition(
            Some(javascript.post_condition().text()),
            GithubConditionPhase::Step,
        )
        .map_err(|_| ActionPreparationError::new(ActionPreparationErrorKind::Metadata))?;
    let javascript = PreparedJavascriptAction::new(
        javascript.runtime(),
        javascript.main().as_str(),
        javascript.pre().map(|path| path.as_str().to_owned()),
        pre_condition,
        javascript.post().map(|path| path.as_str().to_owned()),
        post_condition,
    )
    .map_err(|_| internal())?;
    let inputs = metadata
        .inputs()
        .iter()
        .map(|input| {
            let default = input
                .default()
                .map(|value| prepared_default(value, conditions))
                .transpose()?;
            PreparedInput::new(input.name(), default).map_err(|_| internal())
        })
        .collect::<Result<Vec<_>, _>>()?;
    PreparedAction::new(archive_digest, archive, subpath, inputs, javascript)
        .map_err(|_| internal())
}

fn prepared_default(
    value: &MetadataScalar,
    conditions: &GithubConditionCompiler,
) -> Result<PreparedValue, ActionPreparationError> {
    if value.kind() == MetadataScalarKind::Null {
        return Ok(PreparedValue::Literal(String::new()));
    }
    let source = value.text();
    let trimmed = source.trim();
    if trimmed.starts_with("${{") && trimmed.ends_with("}}") {
        return conditions
            .compile_value_expression(source, GithubConditionPhase::Step)
            .map(PreparedValue::Expression)
            .map_err(|_| ActionPreparationError::new(ActionPreparationErrorKind::Metadata));
    }
    Ok(PreparedValue::Literal(source.to_owned()))
}

const fn internal() -> ActionPreparationError {
    ActionPreparationError::new(ActionPreparationErrorKind::Internal)
}
