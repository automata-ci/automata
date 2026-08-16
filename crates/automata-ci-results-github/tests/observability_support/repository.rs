use std::sync::Arc;

use async_trait::async_trait;
use automata_ci_results_github::{
    ArtifactBlockReservation, ArtifactFinalizationReservation, ArtifactFinalizationWork,
    ArtifactRepository, ArtifactRepositoryError, ArtifactRepositoryErrorKind,
    BeginArtifactFinalization, CommitArtifactBlocks, CommittedArtifact, CompleteArtifactBlock,
    CompleteArtifactFinalization, CreateArtifact, CreateArtifactOutcome, FinalizeArtifactOutcome,
    ListArtifacts, LoadArtifactFinalization, PublishedArtifactMetadata, RecordArtifactVerification,
    RenewArtifactFinalization, ReserveArtifactBlock, ResolveArtifactDownload,
};
use tokio::sync::Notify;

#[derive(Debug, Default)]
pub(crate) enum ReserveBlockBehavior {
    #[default]
    Unavailable,
    Ready,
    Pending {
        entered: Arc<Notify>,
        release: Arc<Notify>,
    },
}

#[derive(Debug, Default)]
pub(crate) enum ListArtifactsBehavior {
    #[default]
    Unavailable,
    Success,
    Conflict,
    Pending {
        entered: Arc<Notify>,
        release: Arc<Notify>,
    },
}

#[derive(Debug, Default)]
pub(crate) struct TestArtifactRepository {
    pub(crate) reserve_block: ReserveBlockBehavior,
    pub(crate) list_artifacts: ListArtifactsBehavior,
    pub(crate) download: Option<PublishedArtifactMetadata>,
}

fn unavailable() -> ArtifactRepositoryError {
    ArtifactRepositoryError::new(ArtifactRepositoryErrorKind::Unavailable)
}

#[async_trait]
impl ArtifactRepository for TestArtifactRepository {
    async fn create(
        &self,
        _request: CreateArtifact,
    ) -> Result<CreateArtifactOutcome, ArtifactRepositoryError> {
        Err(unavailable())
    }

    async fn reserve_block(
        &self,
        _request: ReserveArtifactBlock,
    ) -> Result<ArtifactBlockReservation, ArtifactRepositoryError> {
        match &self.reserve_block {
            ReserveBlockBehavior::Unavailable => Err(unavailable()),
            ReserveBlockBehavior::Ready => Ok(ArtifactBlockReservation::Ready),
            ReserveBlockBehavior::Pending { entered, release } => {
                entered.notify_one();
                release.notified().await;
                Err(unavailable())
            }
        }
    }

    async fn complete_block(
        &self,
        _request: CompleteArtifactBlock,
    ) -> Result<(), ArtifactRepositoryError> {
        Err(unavailable())
    }

    async fn commit_blocks(
        &self,
        _request: CommitArtifactBlocks,
    ) -> Result<CommittedArtifact, ArtifactRepositoryError> {
        Err(unavailable())
    }

    async fn begin_finalization(
        &self,
        _request: BeginArtifactFinalization,
    ) -> Result<ArtifactFinalizationReservation, ArtifactRepositoryError> {
        Err(unavailable())
    }

    async fn load_finalization(
        &self,
        _request: LoadArtifactFinalization,
    ) -> Result<ArtifactFinalizationWork, ArtifactRepositoryError> {
        Err(unavailable())
    }

    async fn renew_finalization(
        &self,
        _request: RenewArtifactFinalization,
    ) -> Result<(), ArtifactRepositoryError> {
        Err(unavailable())
    }

    async fn record_verification(
        &self,
        _request: RecordArtifactVerification,
    ) -> Result<(), ArtifactRepositoryError> {
        Err(unavailable())
    }

    async fn complete_finalization(
        &self,
        _request: CompleteArtifactFinalization,
    ) -> Result<FinalizeArtifactOutcome, ArtifactRepositoryError> {
        Err(unavailable())
    }

    async fn list(
        &self,
        _request: ListArtifacts,
    ) -> Result<Vec<PublishedArtifactMetadata>, ArtifactRepositoryError> {
        match &self.list_artifacts {
            ListArtifactsBehavior::Unavailable => Err(unavailable()),
            ListArtifactsBehavior::Success => Ok(Vec::new()),
            ListArtifactsBehavior::Conflict => Err(ArtifactRepositoryError::new(
                ArtifactRepositoryErrorKind::Conflict,
            )),
            ListArtifactsBehavior::Pending { entered, release } => {
                entered.notify_one();
                release.notified().await;
                Err(unavailable())
            }
        }
    }

    async fn resolve_download(
        &self,
        _request: ResolveArtifactDownload,
    ) -> Result<PublishedArtifactMetadata, ArtifactRepositoryError> {
        self.download.clone().ok_or_else(unavailable)
    }
}
