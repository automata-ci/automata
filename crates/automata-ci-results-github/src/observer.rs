use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::http::{Method, StatusCode};

/// Closed Results application operations safe for metric labels.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResultsOperation {
    /// Creates or idempotently recovers one pending artifact.
    Create,
    /// Publishes and durably completes one immutable upload block.
    StageBlock,
    /// Commits one ordered list of staged blocks.
    Commit,
    /// Verifies and publishes one immutable artifact manifest.
    Finalize,
    /// Lists artifacts visible to one active attempt.
    List,
    /// Resolves and validates one published download manifest.
    PrepareDownload,
    /// Reads and verifies one immutable download block.
    ReadBlock,
}

/// Closed terminal outcome for one physical Results application operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResultsOperationOutcome {
    /// The operation returned successfully, including an exact idempotent replay.
    Success,
    /// The operation future was dropped before returning a result.
    Cancelled,
    /// Request values violated the protocol or a configured bound.
    InvalidArgument,
    /// Current durable authority did not permit the operation.
    PermissionDenied,
    /// Required durable or immutable data was absent.
    NotFound,
    /// Immutable request metadata contradicted an earlier request.
    Conflict,
    /// The requested lifecycle transition was not currently legal.
    FailedPrecondition,
    /// A configured byte or count ceiling would have been exceeded.
    ResourceExhausted,
    /// A mandatory provider was temporarily unavailable.
    Unavailable,
    /// A trusted invariant or provider response was invalid.
    Internal,
}

/// Direction of artifact payload bytes that crossed the application boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResultsTransferDirection {
    /// Upload bytes accepted by a successfully completed staged-block operation.
    Upload,
    /// Download bytes yielded by a successfully verified streaming block read.
    Download,
}

/// Closed HTTP method domain for the Results listener.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResultsHttpMethod {
    /// HTTP `GET` requests.
    Get,
    /// HTTP `POST` requests.
    Post,
    /// HTTP `PUT` requests.
    Put,
    /// Any method outside the finite supported Results method set.
    Other,
}

/// Closed matched-route domain for the Results listener.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResultsHttpRoute {
    /// Twirp artifact-creation endpoint.
    CreateArtifact,
    /// Twirp artifact-finalization endpoint.
    FinalizeArtifact,
    /// Twirp published-artifact listing endpoint.
    ListArtifacts,
    /// Twirp signed-download URL endpoint.
    GetSignedArtifactUrl,
    /// Azure-compatible block upload endpoint.
    Upload,
    /// Signed immutable artifact download endpoint.
    Download,
    /// Twirp cache-entry creation endpoint.
    CreateCache,
    /// Twirp cache-entry finalization endpoint.
    FinalizeCache,
    /// Twirp cache download-URL lookup endpoint.
    GetCacheDownloadUrl,
    /// Azure-compatible cache upload endpoint.
    CacheUpload,
    /// Signed immutable cache download endpoint, including `HEAD`.
    CacheDownload,
    /// Unmatched path, retained as one identifier-free bucket.
    Unknown,
}

/// Closed response-status class for a completed Results HTTP request.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResultsHttpStatusClass {
    /// An HTTP 1xx response.
    Informational,
    /// An HTTP 2xx response.
    Success,
    /// An HTTP 3xx response.
    Redirection,
    /// An HTTP 4xx response.
    ClientError,
    /// An HTTP 5xx response.
    ServerError,
    /// The request future was dropped before a response was produced.
    Cancelled,
}

/// Closed immutable-blob operation domain used by the Results service.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResultsBlobOperation {
    /// Conditional publication of one immutable object.
    Put,
    /// Bounded retrieval and digest verification of one immutable object.
    Get,
}

/// Closed terminal outcome for one physical immutable-blob operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResultsBlobOperationOutcome {
    /// A read completed successfully.
    Success,
    /// A conditional write created the immutable object.
    Created,
    /// A conditional write found byte-identical immutable content already present.
    AlreadyPresent,
    /// The provider future was dropped before returning a result.
    Cancelled,
    /// The immutable object was absent.
    NotFound,
    /// Existing immutable content contradicted the requested descriptor.
    Conflict,
    /// Returned bytes failed descriptor or digest verification.
    Integrity,
    /// The requested or returned object exceeded the caller's byte ceiling.
    TooLarge,
    /// Provider credentials did not authorize the operation.
    Unauthorized,
    /// The immutable-object provider was temporarily unavailable.
    Unavailable,
    /// The provider returned a structurally invalid response.
    InvalidResponse,
}

/// Closed `PostgreSQL` artifact-repository operation domain.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResultsRepositoryOperation {
    /// Creates or idempotently recovers a pending artifact identity.
    Create,
    /// Reserves immutable block metadata before object publication.
    ReserveBlock,
    /// Marks an exact block reservation ready after object publication.
    CompleteBlock,
    /// Commits an ordered list of ready staged blocks.
    CommitBlocks,
    /// Acquires or reconciles an exclusive finalization claim.
    BeginFinalization,
    /// Loads verification or publication work for a committed live claim.
    LoadFinalization,
    /// Extends the lease of the same finalization generation.
    RenewFinalization,
    /// Persists verified content and canonical manifest bytes.
    RecordVerification,
    /// Makes the persisted manifest visible under the live claim fence.
    CompleteFinalization,
    /// Lists bounded, published, non-expired artifact metadata.
    List,
    /// Resolves exact immutable metadata for a signed download.
    ResolveDownload,
}

/// Closed terminal outcome for one physical artifact-repository operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResultsRepositoryOperationOutcome {
    /// The durable operation returned successfully, including exact replay.
    Success,
    /// The repository future was dropped before returning a result.
    Cancelled,
    /// Required durable artifact or block state was absent.
    NotFound,
    /// The attempt or signed-upload authority did not own the current fence.
    Unauthorized,
    /// Immutable request metadata contradicted durable state.
    Conflict,
    /// The requested durable lifecycle transition was not legal.
    InvalidState,
    /// A configured durable byte or count ceiling would be exceeded.
    ResourceExhausted,
    /// Durable rows violated a trusted structural invariant.
    CorruptData,
    /// The durable repository was temporarily unavailable.
    Unavailable,
}

/// Provider-neutral observation seam for Results application operations.
///
/// Inputs contain only closed enums, monotonic durations, and aggregate byte
/// counts. Artifact identities, names, digests, media types, object keys,
/// endpoints, and provider error text never cross this seam.
pub trait ResultsObserver: fmt::Debug + Send + Sync {
    /// Records exactly one terminal outcome for a physical operation attempt.
    fn observe_operation(
        &self,
        _operation: ResultsOperation,
        _outcome: ResultsOperationOutcome,
        _duration: Duration,
    ) {
    }

    /// Records artifact payload bytes only after they were accepted or yielded.
    fn observe_transfer_bytes(&self, _direction: ResultsTransferDirection, _bytes: u64) {}

    /// Records entry into one finite Results HTTP route/method bucket.
    fn results_http_request_started(&self, _method: ResultsHttpMethod, _route: ResultsHttpRoute) {}

    /// Records exactly one completed Results HTTP response and its latency.
    fn observe_results_http_request(
        &self,
        _method: ResultsHttpMethod,
        _route: ResultsHttpRoute,
        _status: ResultsHttpStatusClass,
        _duration: Duration,
    ) {
    }

    /// Balances a prior request-start observation, including cancelled futures.
    fn results_http_request_finished(&self, _method: ResultsHttpMethod, _route: ResultsHttpRoute) {}

    /// Records exactly one terminal immutable-blob operation and its latency.
    fn observe_blob_operation(
        &self,
        _operation: ResultsBlobOperation,
        _outcome: ResultsBlobOperationOutcome,
        _duration: Duration,
    ) {
    }

    /// Records bytes accepted or returned by a successful blob operation.
    fn observe_blob_bytes(&self, _operation: ResultsBlobOperation, _bytes: u64) {}

    /// Records exactly one terminal repository operation and its latency.
    fn observe_repository_operation(
        &self,
        _operation: ResultsRepositoryOperation,
        _outcome: ResultsRepositoryOperationOutcome,
        _duration: Duration,
    ) {
    }
}

pub(crate) struct ResultsHttpObservation {
    observer: Arc<dyn ResultsObserver>,
    method: ResultsHttpMethod,
    route: ResultsHttpRoute,
    started: Instant,
    in_flight: bool,
}

impl ResultsHttpObservation {
    pub(crate) fn new(
        observer: Arc<dyn ResultsObserver>,
        method: &Method,
        route: ResultsHttpRoute,
    ) -> Self {
        let method = results_http_method(method);
        observer.results_http_request_started(method, route);
        Self {
            observer,
            method,
            route,
            started: Instant::now(),
            in_flight: true,
        }
    }

    pub(crate) fn finish(mut self, status: StatusCode) {
        self.observer.observe_results_http_request(
            self.method,
            self.route,
            results_http_status_class(status),
            self.started.elapsed(),
        );
        self.in_flight = false;
        self.observer
            .results_http_request_finished(self.method, self.route);
    }
}

impl Drop for ResultsHttpObservation {
    fn drop(&mut self) {
        if self.in_flight {
            self.in_flight = false;
            self.observer.observe_results_http_request(
                self.method,
                self.route,
                ResultsHttpStatusClass::Cancelled,
                self.started.elapsed(),
            );
            self.observer
                .results_http_request_finished(self.method, self.route);
        }
    }
}

const fn results_http_method(method: &Method) -> ResultsHttpMethod {
    match *method {
        Method::GET => ResultsHttpMethod::Get,
        Method::POST => ResultsHttpMethod::Post,
        Method::PUT => ResultsHttpMethod::Put,
        _ => ResultsHttpMethod::Other,
    }
}

fn results_http_status_class(status: StatusCode) -> ResultsHttpStatusClass {
    if status.is_informational() {
        ResultsHttpStatusClass::Informational
    } else if status.is_success() {
        ResultsHttpStatusClass::Success
    } else if status.is_redirection() {
        ResultsHttpStatusClass::Redirection
    } else if status.is_client_error() {
        ResultsHttpStatusClass::ClientError
    } else {
        ResultsHttpStatusClass::ServerError
    }
}

/// Observer used when Results metrics are not composed.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopResultsObserver;

impl ResultsObserver for NoopResultsObserver {}
