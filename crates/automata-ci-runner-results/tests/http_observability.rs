mod observability_support;

use std::sync::Arc;

use automata_ci_blob::{BlobKey, BlobPayload, ImmutableBlobStore, MediaType, MemoryBlobStore};
use automata_ci_core::{AttemptId, FencingToken, JobId, RunId, Sha256Digest};
use automata_ci_runner_results::{
    ARTIFACT_MANIFEST_MEDIA_TYPE, ActionsResultsApi, ActionsResultsHttpLimits, ArtifactId,
    ArtifactManifest, ArtifactManifestBlock, ArtifactName, ArtifactRepository, ArtifactService,
    ExecutionAuthority, PublishedArtifactMetadata, ResultsHttpMethod, ResultsHttpRoute,
    ResultsHttpStatusClass, ResultsIdGenerator, ResultsLimits, ResultsObserver, ResultsOperation,
    ResultsOperationOutcome, ResultsTransferDirection, RuntimeTokenClaims, RuntimeTokenVerifier,
    SignedDownloadCapability, SignedUploadCapability, SystemResultsClock, SystemResultsIdGenerator,
    TokenError, UploadId,
};
use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http_body_util::BodyExt as _;
use observability_support::{
    observer::{HttpEvent, RecordingObserver},
    repository::{ReserveBlockBehavior, TestArtifactRepository},
};
use sha2::{Digest as _, Sha256};
use tokio::sync::Notify;
use tower::ServiceExt as _;
use url::Url;
use uuid::Uuid;

const CREATE_PATH: &str = "/twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact";

fn upload_path(upload_id: UploadId) -> String {
    let block_id = STANDARD.encode([7_u8; 48]);
    format!("/_apis/results/artifacts/{upload_id}/blob?se=100&sig=x&comp=block&blockid={block_id}")
}

#[derive(Debug, Default)]
struct TestAuthority {
    accept_upload: bool,
    accept_download: bool,
}

impl RuntimeTokenVerifier for TestAuthority {
    fn verify(&self, _token: &str) -> Result<RuntimeTokenClaims, TokenError> {
        Err(TokenError::Invalid)
    }
}

impl SignedUploadCapability for TestAuthority {
    fn issue_url(&self, _upload_id: UploadId, _expires_at_seconds: u64) -> Result<Url, TokenError> {
        Err(TokenError::Policy)
    }

    fn verify(
        &self,
        _upload_id: UploadId,
        _expires_at_seconds: u64,
        _signature: &str,
    ) -> Result<(), TokenError> {
        if self.accept_upload {
            Ok(())
        } else {
            Err(TokenError::Invalid)
        }
    }
}

impl SignedDownloadCapability for TestAuthority {
    fn issue_download_url(
        &self,
        _artifact_id: automata_ci_runner_results::ArtifactId,
        _content_digest: Sha256Digest,
        _expires_at_seconds: u64,
    ) -> Result<Url, TokenError> {
        Err(TokenError::Policy)
    }

    fn verify_download(
        &self,
        _artifact_id: automata_ci_runner_results::ArtifactId,
        _content_digest: Sha256Digest,
        _expires_at_seconds: u64,
        _signature: &str,
    ) -> Result<(), TokenError> {
        if self.accept_download {
            Ok(())
        } else {
            Err(TokenError::Invalid)
        }
    }
}

fn router(observer: Arc<dyn ResultsObserver>) -> axum::Router {
    router_with(
        Arc::new(TestArtifactRepository::default()),
        Arc::new(MemoryBlobStore::default()),
        Arc::new(TestAuthority::default()),
        observer,
    )
}

fn router_with(
    repository: Arc<dyn ArtifactRepository>,
    objects: Arc<dyn ImmutableBlobStore>,
    authority: Arc<TestAuthority>,
    observer: Arc<dyn ResultsObserver>,
) -> axum::Router {
    let ids: Arc<dyn ResultsIdGenerator> = Arc::new(SystemResultsIdGenerator);
    let service = Arc::new(
        ArtifactService::new(
            repository,
            objects,
            Arc::new(SystemResultsClock),
            ids,
            ResultsLimits::default(),
        )
        .with_observer(Arc::clone(&observer)),
    );
    ActionsResultsApi::new(
        service,
        authority.clone(),
        authority.clone(),
        authority,
        ActionsResultsHttpLimits::default(),
    )
    .with_observer(observer)
    .router()
}

#[tokio::test]
async fn matched_route_red_observation_is_finite_and_balanced() {
    let recorder = RecordingObserver::default();
    let response = router(Arc::new(recorder.clone()))
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(CREATE_PATH)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let observations = recorder.snapshot();
    assert!(matches!(
        observations.http_events.as_slice(),
        [
            HttpEvent::Started(ResultsHttpMethod::Post, ResultsHttpRoute::CreateArtifact),
            HttpEvent::Completed {
                method: ResultsHttpMethod::Post,
                route: ResultsHttpRoute::CreateArtifact,
                status: ResultsHttpStatusClass::ClientError,
                ..
            },
            HttpEvent::Finished(ResultsHttpMethod::Post, ResultsHttpRoute::CreateArtifact),
        ]
    ));
}

#[tokio::test]
async fn successful_upload_counts_only_the_accepted_body() {
    let recorder = RecordingObserver::default();
    let repository: Arc<dyn ArtifactRepository> = Arc::new(TestArtifactRepository {
        reserve_block: ReserveBlockBehavior::Ready,
        ..TestArtifactRepository::default()
    });
    let authority = Arc::new(TestAuthority {
        accept_upload: true,
        accept_download: false,
    });
    let upload_id = UploadId::from_uuid(Uuid::new_v4());
    let body = b"accepted immutable upload";
    let response = router_with(
        repository,
        Arc::new(MemoryBlobStore::default()),
        authority,
        Arc::new(recorder.clone()),
    )
    .oneshot(
        Request::builder()
            .method(Method::PUT)
            .uri(upload_path(upload_id))
            .header("content-length", body.len())
            .body(Body::from(body.as_slice()))
            .expect("request"),
    )
    .await
    .expect("response");

    assert_eq!(response.status(), StatusCode::CREATED);
    let observations = recorder.snapshot();
    assert_eq!(
        observations
            .operations
            .iter()
            .map(|(operation, outcome, _)| (*operation, *outcome))
            .collect::<Vec<_>>(),
        vec![(
            ResultsOperation::StageBlock,
            ResultsOperationOutcome::Success,
        )]
    );
    assert_eq!(
        observations.transfers,
        vec![(
            ResultsTransferDirection::Upload,
            u64::try_from(body.len()).expect("bounded body length"),
        )]
    );
}

#[tokio::test]
async fn dropped_request_records_cancelled_and_never_accepts_upload_bytes() {
    let recorder = RecordingObserver::default();
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let repository: Arc<dyn ArtifactRepository> = Arc::new(TestArtifactRepository {
        reserve_block: ReserveBlockBehavior::Pending {
            entered: Arc::clone(&entered),
            release,
        },
        ..TestArtifactRepository::default()
    });
    let authority = Arc::new(TestAuthority {
        accept_upload: true,
        accept_download: false,
    });
    let upload_id = UploadId::from_uuid(Uuid::new_v4());
    let body = b"never accepted private upload";
    let application = router_with(
        repository,
        Arc::new(MemoryBlobStore::default()),
        authority,
        Arc::new(recorder.clone()),
    );
    let request = Request::builder()
        .method(Method::PUT)
        .uri(upload_path(upload_id))
        .header("content-length", body.len())
        .body(Body::from(body.as_slice()))
        .expect("request");
    let request_task = tokio::spawn(application.oneshot(request));
    entered.notified().await;
    request_task.abort();
    assert!(
        request_task
            .await
            .expect_err("request task must be cancelled")
            .is_cancelled()
    );

    let observations = recorder.snapshot();
    assert!(matches!(
        observations.http_events.as_slice(),
        [
            HttpEvent::Started(ResultsHttpMethod::Put, ResultsHttpRoute::Upload),
            HttpEvent::Completed {
                method: ResultsHttpMethod::Put,
                route: ResultsHttpRoute::Upload,
                status: ResultsHttpStatusClass::Cancelled,
                ..
            },
            HttpEvent::Finished(ResultsHttpMethod::Put, ResultsHttpRoute::Upload),
        ]
    ));
    assert_eq!(
        observations
            .operations
            .iter()
            .map(|(operation, outcome, _)| (*operation, *outcome))
            .collect::<Vec<_>>(),
        vec![(
            ResultsOperation::StageBlock,
            ResultsOperationOutcome::Cancelled,
        )]
    );
    assert!(observations.transfers.is_empty());
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn download_bytes_count_only_frames_yielded_before_client_body_cancellation() {
    let recorder = RecordingObserver::default();
    let objects = Arc::new(MemoryBlobStore::default());
    let upload_id = UploadId::from_uuid(Uuid::new_v4());
    let artifact_id = ArtifactId::new(41).expect("artifact id");
    let authority = ExecutionAuthority::new(
        RunId::new(),
        JobId::new(),
        AttemptId::new(),
        FencingToken::new(7).expect("fencing token"),
    );
    let artifact_name = ArtifactName::new("download-observer", 255).expect("artifact name");
    let media_type = MediaType::new("application/octet-stream").expect("media type");
    let first = bytes::Bytes::from_static(b"first yielded block");
    let second = bytes::Bytes::from_static(b"second unpolled private block");
    let mut content_hasher = Sha256::new();
    content_hasher.update(&first);
    content_hasher.update(&second);
    let content_digest = Sha256Digest::from_bytes(content_hasher.finalize().into());

    let mut descriptors = Vec::new();
    for (block_id, bytes) in [
        (STANDARD.encode([1_u8; 48]), first.clone()),
        (STANDARD.encode([2_u8; 48]), second.clone()),
    ] {
        let digest = Sha256Digest::from_bytes(Sha256::digest(&bytes).into());
        let payload = BlobPayload::from_bytes(
            BlobKey::new(format!("artifact-staging/v1/{upload_id}/{digest}")).expect("block key"),
            media_type.clone(),
            bytes,
        );
        let descriptor = payload.descriptor().clone();
        objects
            .put_if_absent(payload)
            .await
            .expect("seed immutable block");
        descriptors.push((block_id, descriptor));
    }

    let size = descriptors.iter().map(|(_, block)| block.size()).sum();
    let manifest = ArtifactManifest {
        schema: 1,
        artifact_id: artifact_id.get(),
        upload_id: upload_id.to_string(),
        run_id: authority.run_id().to_string(),
        job_id: authority.job_id().to_string(),
        attempt_id: authority.attempt_id().to_string(),
        fencing_token: authority.fencing_token().get(),
        name: artifact_name.as_str().to_owned(),
        mime_type: media_type.as_str().to_owned(),
        size,
        sha256: content_digest.to_string(),
        blocks: descriptors
            .iter()
            .map(|(block_id, descriptor)| ArtifactManifestBlock {
                block_id: block_id.clone(),
                object_key: descriptor.key().as_str().to_owned(),
                size: descriptor.size(),
                sha256: descriptor.digest().to_string(),
                media_type: descriptor.media_type().as_str().to_owned(),
            })
            .collect(),
    };
    let manifest_payload = BlobPayload::from_bytes(
        BlobKey::new(format!(
            "artifacts/v1/{content_digest}/{artifact_id}/manifest.json"
        ))
        .expect("manifest key"),
        MediaType::new(ARTIFACT_MANIFEST_MEDIA_TYPE).expect("manifest media type"),
        bytes::Bytes::from(serde_json::to_vec(&manifest).expect("manifest JSON")),
    );
    let manifest_descriptor = manifest_payload.descriptor().clone();
    objects
        .put_if_absent(manifest_payload)
        .await
        .expect("seed immutable manifest");

    let metadata = PublishedArtifactMetadata {
        artifact_id,
        upload_id,
        authority,
        name: artifact_name,
        mime_type: media_type.as_str().to_owned(),
        content_digest,
        size,
        manifest: manifest_descriptor,
        created_at_seconds: 10,
        expires_at_seconds: None,
    };
    let repository: Arc<dyn ArtifactRepository> = Arc::new(TestArtifactRepository {
        download: Some(metadata),
        ..TestArtifactRepository::default()
    });
    let object_port: Arc<dyn ImmutableBlobStore> = objects;
    let authority = Arc::new(TestAuthority {
        accept_upload: false,
        accept_download: true,
    });
    let response = router_with(
        repository,
        object_port,
        authority,
        Arc::new(recorder.clone()),
    )
    .oneshot(
        Request::builder()
            .method(Method::GET)
            .uri(format!(
                "/_apis/results/artifacts/{artifact_id}/{content_digest}/download.zip?se=100&sig=x"
            ))
            .body(Body::empty())
            .expect("request"),
    )
    .await
    .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let observations = recorder.snapshot();
    assert_eq!(
        observations
            .operations
            .iter()
            .map(|(operation, outcome, _)| (*operation, *outcome))
            .collect::<Vec<_>>(),
        vec![(
            ResultsOperation::PrepareDownload,
            ResultsOperationOutcome::Success,
        )]
    );
    assert!(
        observations.transfers.is_empty(),
        "building a response must not count unpolled download bytes"
    );

    let mut response_body = response.into_body();
    let frame = response_body
        .frame()
        .await
        .expect("first body frame")
        .expect("successful first body frame");
    assert_eq!(
        frame.into_data().expect("data frame"),
        bytes::Bytes::from_static(b"first yielded block")
    );
    drop(response_body);
    let observations = recorder.snapshot();
    assert_eq!(
        observations
            .operations
            .iter()
            .map(|(operation, outcome, _)| (*operation, *outcome))
            .collect::<Vec<_>>(),
        vec![
            (
                ResultsOperation::PrepareDownload,
                ResultsOperationOutcome::Success,
            ),
            (
                ResultsOperation::ReadBlock,
                ResultsOperationOutcome::Success,
            ),
        ]
    );
    assert_eq!(
        observations.transfers,
        vec![(
            ResultsTransferDirection::Download,
            u64::try_from(first.len()).expect("bounded block length"),
        )]
    );
}

#[tokio::test]
async fn unknown_path_never_becomes_a_metric_label() {
    let recorder = RecordingObserver::default();
    let private_path = "/private/tenant-91/artifact-secret-digest";
    let response = router(Arc::new(recorder.clone()))
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(private_path)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let observations = recorder.snapshot();
    assert!(matches!(
        observations.http_events.as_slice(),
        [
            HttpEvent::Started(ResultsHttpMethod::Other, ResultsHttpRoute::Unknown),
            HttpEvent::Completed {
                method: ResultsHttpMethod::Other,
                route: ResultsHttpRoute::Unknown,
                status: ResultsHttpStatusClass::ClientError,
                ..
            },
            HttpEvent::Finished(ResultsHttpMethod::Other, ResultsHttpRoute::Unknown),
        ]
    ));
    assert!(!format!("{:?}", observations.http_events).contains(private_path));
}
