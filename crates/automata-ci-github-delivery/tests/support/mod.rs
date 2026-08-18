use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use automata_ci_blob::{
    BlobDescriptor, BlobPayload, BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore,
    PutBlobOutcome, VerifiedBlob,
};
use automata_ci_core::UnixMillis;
use automata_ci_github_delivery::GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE;
use automata_ci_provider_github::{
    GITHUB_EVENT_ENVELOPE_V1_MEDIA_TYPE,
    GithubRepositoryVisibility as GithubRepositoryVisibilityFact, GithubSealedEventEnvelopeV1,
    GithubWebhookBodyDigest, StoredAuthenticatedGithubWebhook,
    rehydrate_stored_authenticated_github_webhook,
};
use automata_ci_store::{
    CompleteProviderDelivery, ProviderDeliveryEventEnvelope, ProviderDeliveryId,
    ProviderDeliveryReceipt, ProviderDeliveryState, ProviderDeliveryStoreError,
    ProviderDeliveryWorkflowInventory, ProviderDeliveryWorkflowInventoryReceipt,
    ProviderDeliveryWorkflowOutcome, ProviderRepositoryVisibility,
    RecordProviderDeliveryWorkflowProgress, RegisterProviderDeliveryWorkflowInventory,
    RejectProviderDelivery, RetryProviderDelivery,
};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{HeaderMap, Request, Response, StatusCode},
    routing::any,
};
use bytes::Bytes;
use flate2::{Compression, write::GzEncoder};
use tar::{Builder, EntryType, Header};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use url::Url;

const MAX_FIXTURE_REQUEST_BYTES: usize = 1_048_576;

#[derive(Clone, Debug)]
pub(super) struct HttpResponse {
    status: StatusCode,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpResponse {
    pub(super) fn status(status: StatusCode) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub(super) fn json(status: StatusCode, body: impl Into<Vec<u8>>) -> Self {
        Self::status(status)
            .header("content-type", "application/json")
            .body(body)
    }

    pub(super) fn binary(status: StatusCode, media_type: &str, body: impl Into<Vec<u8>>) -> Self {
        Self::status(status)
            .header("content-type", media_type)
            .body(body)
    }

    pub(super) fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_owned(), value.into()));
        self
    }

    fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }
}

#[derive(Clone, Debug)]
pub(super) struct HttpRequest {
    pub(super) method: String,
    pub(super) uri: String,
    pub(super) headers: HeaderMap,
    pub(super) body: Vec<u8>,
}

#[derive(Clone, Debug)]
struct HttpState {
    responses: Arc<Mutex<VecDeque<HttpResponse>>>,
    requests: Arc<Mutex<Vec<HttpRequest>>>,
}

#[derive(Debug)]
pub(super) struct HttpServer {
    origin: Url,
    state: HttpState,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl HttpServer {
    pub(super) async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind HTTP fixture");
        let address = listener.local_addr().expect("HTTP fixture address");
        let state = HttpState {
            responses: Arc::new(Mutex::new(VecDeque::new())),
            requests: Arc::new(Mutex::new(Vec::new())),
        };
        let router = Router::new()
            .fallback(any(handle_http_request))
            .with_state(state.clone());
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = receiver.await;
                })
                .await
                .expect("serve HTTP fixture");
        });
        Self {
            origin: Url::parse(&format!("http://{address}/")).expect("HTTP fixture origin"),
            state,
            shutdown: Some(shutdown),
            task,
        }
    }

    pub(super) fn origin(&self) -> Url {
        self.origin.clone()
    }

    pub(super) fn url(&self, relative: &str) -> Url {
        self.origin.join(relative).expect("HTTP fixture URL")
    }

    pub(super) fn enqueue(&self, response: HttpResponse) {
        self.state
            .responses
            .lock()
            .expect("HTTP response lock")
            .push_back(response);
    }

    pub(super) fn requests(&self) -> Vec<HttpRequest> {
        self.state
            .requests
            .lock()
            .expect("HTTP request lock")
            .clone()
    }
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.abort();
    }
}

async fn handle_http_request(
    State(state): State<HttpState>,
    request: Request<Body>,
) -> Response<Body> {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, MAX_FIXTURE_REQUEST_BYTES)
        .await
        .expect("bounded HTTP fixture body");
    state
        .requests
        .lock()
        .expect("HTTP request lock")
        .push(HttpRequest {
            method: parts.method.to_string(),
            uri: parts.uri.to_string(),
            headers: parts.headers,
            body: body.to_vec(),
        });
    let response = state
        .responses
        .lock()
        .expect("HTTP response lock")
        .pop_front()
        .expect("queued HTTP fixture response");
    let mut builder = Response::builder().status(response.status);
    for (name, value) in response.headers {
        builder = builder.header(name, value);
    }
    builder
        .body(Body::from(response.body))
        .expect("HTTP fixture response")
}

pub(super) const BEFORE: &str = "fedcba9876543210fedcba9876543210fedcba98";
pub(super) const AFTER: &str = "0123456789abcdef0123456789abcdef01234567";
pub(super) const ZERO: &str = "0000000000000000000000000000000000000000";
pub(super) const OWNER: &str = "octo-private";
pub(super) const REPOSITORY: &str = "private-repository";
pub(super) const REPOSITORY_ID: u64 = 9_001;
pub(super) const REPOSITORY_OWNER_ID: u64 = 8_001;
pub(super) const INSTALLATION_ID: u64 = 4_242;

#[derive(Debug)]
pub(super) struct ProviderDeliveryLedger {
    attempts: u16,
    accepted_at: UnixMillis,
    completions: Mutex<Vec<CompleteProviderDelivery>>,
    retries: Mutex<Vec<RetryProviderDelivery>>,
    rejections: Mutex<Vec<RejectProviderDelivery>>,
    inventory: Mutex<Option<ProviderDeliveryWorkflowInventory>>,
    progress: Mutex<Vec<ProviderDeliveryWorkflowOutcome>>,
}

impl ProviderDeliveryLedger {
    pub(super) fn new(attempts: u16, accepted_at: UnixMillis) -> Self {
        Self {
            attempts,
            accepted_at,
            completions: Mutex::new(Vec::new()),
            retries: Mutex::new(Vec::new()),
            rejections: Mutex::new(Vec::new()),
            inventory: Mutex::new(None),
            progress: Mutex::new(Vec::new()),
        }
    }

    pub(super) fn receipt(
        &self,
        delivery_id: ProviderDeliveryId,
        state: ProviderDeliveryState,
    ) -> ProviderDeliveryReceipt {
        ProviderDeliveryReceipt::from_durable_parts(
            delivery_id,
            state,
            self.attempts,
            self.accepted_at,
        )
        .expect("transition receipt")
    }

    pub(super) fn record_completion(&self, request: CompleteProviderDelivery) {
        self.completions
            .lock()
            .expect("completions lock")
            .push(request);
    }

    pub(super) fn record_retry(&self, request: RetryProviderDelivery) {
        self.retries.lock().expect("retries lock").push(request);
    }

    pub(super) fn record_rejection(&self, request: RejectProviderDelivery) {
        self.rejections
            .lock()
            .expect("rejections lock")
            .push(request);
    }

    pub(super) fn completions(&self) -> Vec<CompleteProviderDelivery> {
        self.completions.lock().expect("completions lock").clone()
    }

    pub(super) fn retries(&self) -> Vec<RetryProviderDelivery> {
        self.retries.lock().expect("retries lock").clone()
    }

    pub(super) fn rejections(&self) -> Vec<RejectProviderDelivery> {
        self.rejections.lock().expect("rejections lock").clone()
    }

    pub(super) fn progress(&self) -> Vec<ProviderDeliveryWorkflowOutcome> {
        self.progress.lock().expect("progress lock").clone()
    }

    pub(super) fn transition_count(&self) -> usize {
        self.completions.lock().expect("completions lock").len()
            + self.retries.lock().expect("retries lock").len()
            + self.rejections.lock().expect("rejections lock").len()
    }

    pub(super) fn register_workflow_inventory(
        &self,
        request: &RegisterProviderDeliveryWorkflowInventory,
    ) -> Result<ProviderDeliveryWorkflowInventoryReceipt, ProviderDeliveryStoreError> {
        let mut inventory = self.inventory.lock().expect("inventory lock");
        match inventory.as_ref() {
            Some(existing) if existing != request.inventory() => {
                return Err(ProviderDeliveryStoreError::WorkflowProgressRejected);
            }
            Some(_) => {}
            None => *inventory = Some(request.inventory().clone()),
        }
        ProviderDeliveryWorkflowInventoryReceipt::new(
            inventory.as_ref().expect("inventory initialized").clone(),
            self.progress.lock().expect("progress lock").clone(),
        )
        .map_err(|_| ProviderDeliveryStoreError::WorkflowProgressRejected)
    }

    pub(super) fn record_workflow_progress(
        &self,
        request: &RecordProviderDeliveryWorkflowProgress,
    ) -> Result<ProviderDeliveryWorkflowOutcome, ProviderDeliveryStoreError> {
        let inventory = self.inventory.lock().expect("inventory lock");
        let Some(inventory) = inventory.as_ref() else {
            return Err(ProviderDeliveryStoreError::WorkflowProgressRejected);
        };
        if inventory.digest() != request.inventory_digest()
            || !inventory
                .entries()
                .iter()
                .any(|entry| entry.workflow_path() == request.outcome().workflow_path())
        {
            return Err(ProviderDeliveryStoreError::WorkflowProgressRejected);
        }
        let mut progress = self.progress.lock().expect("progress lock");
        if let Some(existing) = progress
            .iter()
            .find(|existing| existing.workflow_path() == request.outcome().workflow_path())
        {
            return if existing == request.outcome() {
                Ok(existing.clone())
            } else {
                Err(ProviderDeliveryStoreError::WorkflowProgressRejected)
            };
        }
        progress.push(request.outcome().clone());
        Ok(request.outcome().clone())
    }
}

#[derive(Debug)]
pub(super) struct VerifiedBlobStore {
    descriptor: BlobDescriptor,
    bytes: Bytes,
    failure: Option<BlobStoreErrorKind>,
    reads: AtomicUsize,
}

impl VerifiedBlobStore {
    pub(super) fn exact(descriptor: BlobDescriptor, bytes: Bytes) -> Self {
        Self {
            descriptor,
            bytes,
            failure: None,
            reads: AtomicUsize::new(0),
        }
    }

    pub(super) fn failing(
        descriptor: BlobDescriptor,
        bytes: Bytes,
        failure: BlobStoreErrorKind,
    ) -> Self {
        Self {
            descriptor,
            bytes,
            failure: Some(failure),
            reads: AtomicUsize::new(0),
        }
    }

    pub(super) fn read_count(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ImmutableBlobStore for VerifiedBlobStore {
    async fn put_if_absent(&self, _payload: BlobPayload) -> Result<PutBlobOutcome, BlobStoreError> {
        panic!("the verified blob fixture is read-only")
    }

    async fn get_verified(
        &self,
        descriptor: &BlobDescriptor,
        maximum_bytes: u64,
    ) -> Result<VerifiedBlob, BlobStoreError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if let Some(failure) = self.failure {
            return Err(BlobStoreError::new(failure));
        }
        if descriptor != &self.descriptor || descriptor.size() > maximum_bytes {
            return Err(BlobStoreError::new(BlobStoreErrorKind::Integrity));
        }
        let payload = BlobPayload::verify(descriptor.clone(), self.bytes.clone())
            .map_err(|_| BlobStoreError::new(BlobStoreErrorKind::Integrity))?;
        Ok(VerifiedBlob::from_payload(payload))
    }
}

pub(super) fn archive<T: AsRef<[u8]>>(files: BTreeMap<&str, T>) -> Bytes {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = Builder::new(encoder);
    append_archive_entry(&mut builder, "repository-root", EntryType::Directory, &[]);
    for (path, bytes) in files {
        append_archive_entry(
            &mut builder,
            &format!("repository-root/{path}"),
            EntryType::Regular,
            bytes.as_ref(),
        );
    }
    let encoder = builder.into_inner().expect("finish tar");
    Bytes::from(encoder.finish().expect("finish gzip"))
}

fn append_archive_entry(
    builder: &mut Builder<GzEncoder<Vec<u8>>>,
    path: &str,
    entry_type: EntryType,
    bytes: &[u8],
) {
    let mut header = Header::new_gnu();
    header.set_entry_type(entry_type);
    header.set_mode(if entry_type.is_dir() { 0o755 } else { 0o644 });
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(u64::try_from(bytes.len()).expect("entry size"));
    header.set_cksum();
    builder
        .append_data(&mut header, path, bytes)
        .expect("append archive entry");
}

pub(super) fn provider_event_envelope(
    body: &Bytes,
    descriptor: &BlobDescriptor,
    event_name: &str,
    delivery: &str,
    visibility: ProviderRepositoryVisibility,
) -> ProviderDeliveryEventEnvelope {
    let visibility = match visibility {
        ProviderRepositoryVisibility::Public => GithubRepositoryVisibilityFact::Public,
        ProviderRepositoryVisibility::Private => GithubRepositoryVisibilityFact::Private,
    };
    let stored = StoredAuthenticatedGithubWebhook::from_durable_coordinates(
        body.clone(),
        GithubWebhookBodyDigest::from_bytes(*descriptor.digest().as_bytes()),
        descriptor.size(),
        GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE,
        event_name,
        delivery,
        INSTALLATION_ID,
        REPOSITORY_ID,
        REPOSITORY_OWNER_ID,
        visibility,
        OWNER,
        REPOSITORY,
    );
    let event =
        rehydrate_stored_authenticated_github_webhook(stored).expect("verified webhook fixture");
    let sealed = GithubSealedEventEnvelopeV1::seal(&event, descriptor.clone())
        .expect("sealed event envelope fixture");
    ProviderDeliveryEventEnvelope::new(
        sealed.schema(),
        sealed.registry_schema(),
        sealed.digest(),
        sealed.canonical_bytes().to_vec(),
        GITHUB_EVENT_ENVELOPE_V1_MEDIA_TYPE,
    )
    .expect("durable event envelope fixture")
}

pub(super) fn push_body(
    git_ref: &str,
    after: &str,
    deleted: bool,
    commit_count: usize,
    visibility: ProviderRepositoryVisibility,
) -> Bytes {
    let commits = (1..=commit_count)
        .map(|value| format!(r#"{{"id":"{value:040x}"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let (private, visibility) = match visibility {
        ProviderRepositoryVisibility::Public => (false, "public"),
        ProviderRepositoryVisibility::Private => (true, "private"),
    };
    Bytes::from(format!(
        r#"{{"ref":"{git_ref}","before":"{BEFORE}","after":"{after}","created":false,"deleted":{deleted},"forced":false,"repository":{{"id":{REPOSITORY_ID},"private":{private},"visibility":"{visibility}","name":"{REPOSITORY}","full_name":"{OWNER}/{REPOSITORY}","owner":{{"id":{REPOSITORY_OWNER_ID},"login":"{OWNER}"}}}},"installation":{{"id":{INSTALLATION_ID}}},"commits":[{commits}]}}"#,
    ))
}
