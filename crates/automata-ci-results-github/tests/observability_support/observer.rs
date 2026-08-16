use std::{
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use automata_ci_results_github::{
    ResultsBlobOperation, ResultsBlobOperationOutcome, ResultsHttpMethod, ResultsHttpRoute,
    ResultsHttpStatusClass, ResultsObserver, ResultsOperation, ResultsOperationOutcome,
    ResultsRepositoryOperation, ResultsRepositoryOperationOutcome, ResultsTransferDirection,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HttpEvent {
    Started(ResultsHttpMethod, ResultsHttpRoute),
    Completed {
        method: ResultsHttpMethod,
        route: ResultsHttpRoute,
        status: ResultsHttpStatusClass,
        duration: Duration,
    },
    Finished(ResultsHttpMethod, ResultsHttpRoute),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ObservationSnapshot {
    pub(crate) http_events: Vec<HttpEvent>,
    pub(crate) operations: Vec<(ResultsOperation, ResultsOperationOutcome, Duration)>,
    pub(crate) transfers: Vec<(ResultsTransferDirection, u64)>,
    pub(crate) blob_operations: Vec<(ResultsBlobOperation, ResultsBlobOperationOutcome, Duration)>,
    pub(crate) blob_bytes: Vec<(ResultsBlobOperation, u64)>,
    pub(crate) repository_operations: Vec<(
        ResultsRepositoryOperation,
        ResultsRepositoryOperationOutcome,
        Duration,
    )>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct RecordingObserver {
    observations: Arc<Mutex<ObservationSnapshot>>,
}

impl RecordingObserver {
    pub(crate) fn snapshot(&self) -> ObservationSnapshot {
        self.observations().clone()
    }

    fn observations(&self) -> MutexGuard<'_, ObservationSnapshot> {
        self.observations.lock().expect("results observations lock")
    }
}

impl ResultsObserver for RecordingObserver {
    fn observe_operation(
        &self,
        operation: ResultsOperation,
        outcome: ResultsOperationOutcome,
        duration: Duration,
    ) {
        self.observations()
            .operations
            .push((operation, outcome, duration));
    }

    fn observe_transfer_bytes(&self, direction: ResultsTransferDirection, bytes: u64) {
        self.observations().transfers.push((direction, bytes));
    }

    fn results_http_request_started(&self, method: ResultsHttpMethod, route: ResultsHttpRoute) {
        self.observations()
            .http_events
            .push(HttpEvent::Started(method, route));
    }

    fn observe_results_http_request(
        &self,
        method: ResultsHttpMethod,
        route: ResultsHttpRoute,
        status: ResultsHttpStatusClass,
        duration: Duration,
    ) {
        self.observations().http_events.push(HttpEvent::Completed {
            method,
            route,
            status,
            duration,
        });
    }

    fn results_http_request_finished(&self, method: ResultsHttpMethod, route: ResultsHttpRoute) {
        self.observations()
            .http_events
            .push(HttpEvent::Finished(method, route));
    }

    fn observe_blob_operation(
        &self,
        operation: ResultsBlobOperation,
        outcome: ResultsBlobOperationOutcome,
        duration: Duration,
    ) {
        self.observations()
            .blob_operations
            .push((operation, outcome, duration));
    }

    fn observe_blob_bytes(&self, operation: ResultsBlobOperation, bytes: u64) {
        self.observations().blob_bytes.push((operation, bytes));
    }

    fn observe_repository_operation(
        &self,
        operation: ResultsRepositoryOperation,
        outcome: ResultsRepositoryOperationOutcome,
        duration: Duration,
    ) {
        self.observations()
            .repository_operations
            .push((operation, outcome, duration));
    }
}
