mod support;

use std::{env, sync::Arc, time::Duration};

use automata_ci_blob::ImmutableBlobStore as _;
use automata_ci_blob_s3::{S3BlobStore, S3BlobStoreConfig, StaticS3Credentials};
use automata_ci_core::{AttemptId, AttemptNumber, LeaseId, Sha256Digest, UnixMillis};
use automata_ci_results_github::{
    ArtifactRepository as _, ArtifactService, ExecutionAuthority, PostgresArtifactRepository,
    ResolveArtifactDownload, ResultsClock, ResultsIdGenerator, ResultsLimits, UploadId,
};
use automata_ci_store::{
    AcquireLease, InternalAttemptRepository as _, QueuedAttempt, StableRunnerSlot,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use support::postgres::{TestDatabase, TestResult, run_with_database, seed_control_plane};
use url::Url;
use uuid::Uuid;

#[derive(Debug)]
struct FixedClock;

impl ResultsClock for FixedClock {
    fn now_seconds(&self) -> u64 {
        1_000
    }
}

#[derive(Debug)]
struct FixedIds(UploadId);

impl ResultsIdGenerator for FixedIds {
    fn next_upload_id(&self) -> UploadId {
        self.0
    }
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and RustFS environment"]
async fn finalized_manifest_and_blocks_are_verified_in_rustfs() -> TestResult {
    let endpoint = env::var("AUTOMATA_TEST_S3_ENDPOINT")?;
    run_with_database(|database| async move {
        let authority = active_attempt(&database).await?;
        let endpoint = Url::parse(&endpoint)?;
        let bucket = env::var("AUTOMATA_TEST_S3_BUCKET")?;
        let access_key = env::var("AUTOMATA_TEST_S3_ACCESS_KEY")?;
        let secret_key = env::var("AUTOMATA_TEST_S3_SECRET_KEY")?;
        let config = S3BlobStoreConfig::loopback_development(
            endpoint,
            "us-east-1",
            bucket,
            Some(format!("results-contract/{}", Uuid::new_v4().simple())),
            Duration::from_secs(20),
        )?;
        let objects = Arc::new(S3BlobStore::new(
            config.client(StaticS3Credentials::new(access_key, secret_key, None)?),
            &config,
        ));
        let upload_id = UploadId::from_uuid(Uuid::new_v4());
        let repository = Arc::new(PostgresArtifactRepository::new(database.pool().clone()));
        let service = ArtifactService::new(
            repository.clone(),
            objects.clone(),
            Arc::new(FixedClock),
            Arc::new(FixedIds(upload_id)),
            ResultsLimits::default(),
        );
        let created = service
            .create(
                authority,
                "rustfs-dist".to_owned(),
                7,
                "application/zip".to_owned(),
                None,
            )
            .await?;
        assert_eq!(created.upload_id, upload_id);
        let content = Bytes::from_static(b"artifact bytes persisted as an immutable RustFS block");
        let block_id = STANDARD.encode([3_u8; 48]);
        service
            .stage_block(upload_id, block_id.clone(), content.clone())
            .await?;
        service.commit_blocks(upload_id, vec![block_id]).await?;
        let digest = Sha256Digest::from_bytes(Sha256::digest(&content).into());
        let finalized = service
            .finalize(
                authority,
                "rustfs-dist".to_owned(),
                u64::try_from(content.len())?,
                Some(digest),
            )
            .await?;
        let published = repository
            .resolve_download(ResolveArtifactDownload {
                artifact_id: finalized.artifact_id,
                content_digest: finalized.content_digest,
                observed_at_seconds: 1_000,
            })
            .await?;
        assert_eq!(published.artifact_id, finalized.artifact_id);
        let manifest = objects
            .get_verified(&published.manifest, 1024 * 1024)
            .await?;
        let manifest: serde_json::Value = serde_json::from_slice(manifest.bytes())?;
        assert_eq!(manifest["sha256"], digest.to_string());
        assert_eq!(manifest["size"], content.len());
        assert_eq!(manifest["blocks"].as_array().map(Vec::len), Some(1));
        Ok(())
    })
    .await
}

async fn active_attempt(database: &TestDatabase) -> TestResult<ExecutionAuthority> {
    let seed = seed_control_plane(database.pool()).await?;
    let attempt_id = AttemptId::new();
    database
        .store()
        .insert_queued(QueuedAttempt::new(
            attempt_id,
            seed.job_id,
            AttemptNumber::new(1)?,
            UnixMillis::new(3),
        ))
        .await?;
    let lease = database
        .store()
        .acquire_lease(
            AcquireLease::new(
                attempt_id,
                LeaseId::new(),
                seed.session_fence,
                StableRunnerSlot::new(1)?,
                UnixMillis::new(4),
                UnixMillis::new(100),
            )
            .expect("valid lease request"),
        )
        .await?;
    Ok(ExecutionAuthority::new(
        seed.run_id,
        seed.job_id,
        attempt_id,
        lease.fencing_token(),
    ))
}
