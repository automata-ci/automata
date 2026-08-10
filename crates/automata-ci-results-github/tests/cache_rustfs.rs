mod support;

use std::{env, sync::Arc, time::Duration};

use automata_ci_blob_s3::{S3BlobStore, S3BlobStoreConfig, StaticS3Credentials};
use automata_ci_core::{AttemptId, AttemptNumber, LeaseId, UnixMillis};
use automata_ci_results_github::{
    CacheAccessScope, CacheAuthority, CacheLimits, CachePermission, CacheRepository, CacheService,
    ExecutionAuthority, PostgresCacheRepository, ResultsClock, ResultsIdGenerator, UploadId,
};
use automata_ci_store::{
    AcquireLease, InternalAttemptRepository as _, QueuedAttempt, StableRunnerSlot,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
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
async fn finalized_cache_blocks_are_verified_and_ranged_from_rustfs() -> TestResult {
    let endpoint = env::var("AUTOMATA_TEST_S3_ENDPOINT")?;
    run_with_database(|database| async move {
        let execution = active_attempt(&database).await?;
        let cache = CacheAuthority::new(
            "automata/results-test",
            vec![CacheAccessScope::new(
                "refs/heads/main",
                CachePermission::ReadWrite,
            )?],
        )?;
        let endpoint = Url::parse(&endpoint)?;
        let bucket = env::var("AUTOMATA_TEST_S3_BUCKET")?;
        let access_key = env::var("AUTOMATA_TEST_S3_ACCESS_KEY")?;
        let secret_key = env::var("AUTOMATA_TEST_S3_SECRET_KEY")?;
        let config = S3BlobStoreConfig::loopback_development(
            endpoint,
            "us-east-1",
            bucket,
            Some(format!("cache-contract/{}", Uuid::new_v4().simple())),
            Duration::from_secs(20),
        )?;
        let objects = Arc::new(S3BlobStore::new(
            config.client(StaticS3Credentials::new(access_key, secret_key, None)?),
            &config,
        ));
        let upload_id = UploadId::from_uuid(Uuid::new_v4());
        let repository: Arc<dyn CacheRepository> =
            Arc::new(PostgresCacheRepository::new(database.pool().clone()));
        let service = CacheService::new(
            repository,
            objects,
            Arc::new(FixedClock),
            Arc::new(FixedIds(upload_id)),
            CacheLimits::default(),
        );
        let created = service
            .create(
                execution,
                cache.clone(),
                "rustfs-cache".to_owned(),
                "version-1".to_owned(),
            )
            .await?;
        let content = Bytes::from_static(b"cache bytes persisted as an immutable RustFS block");
        let block_id = STANDARD.encode([3_u8; 48]);
        service
            .stage_block(created.entry_id, block_id.clone(), content.clone())
            .await?;
        service
            .commit_blocks(created.entry_id, vec![block_id])
            .await?;
        let finalized = service
            .finalize(
                execution,
                cache.clone(),
                "rustfs-cache".to_owned(),
                "version-1".to_owned(),
                u64::try_from(content.len())?,
            )
            .await?;
        let matched = service
            .lookup(
                execution,
                cache,
                "rustfs-cache".to_owned(),
                Vec::new(),
                "version-1".to_owned(),
            )
            .await?
            .expect("exact cache match");
        assert_eq!(matched.entry_id, finalized.entry_id);
        let prepared = service
            .prepare_download(finalized.entry_id, finalized.digest, Some(6..17))
            .await?;
        assert_eq!(prepared.segments.len(), 1);
        let bytes = service.read_download_segment(&prepared.segments[0]).await?;
        assert_eq!(bytes, content.slice(6..17));
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
