#![allow(dead_code)]

use std::{
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use automata_ci_auth::{
    machine::{ExternalRunnerIdentity, MachineAuthenticationEvidence},
    time::{Clock, UnixTimestamp},
};
use automata_ci_core::{RunnerId, Sha256Digest};
use automata_ci_runner_auth::{
    DurableRunnerMachineAuthenticator, RunnerMachineAuthLimits, RunnerMachineDirectory,
    RunnerMachineDirectoryError, RunnerMachineRecord,
};
use automata_ci_runner_control::DesiredRunnerState;
use automata_ci_store::RunnerGeneration;
use sha2::{Digest as _, Sha256};

pub const NOW: u64 = 1_800_000_000;
pub const EXPIRES_AT: u64 = NOW + 3_600;

#[derive(Clone)]
enum DirectoryAnswer {
    Found(Option<RunnerMachineRecord>),
    Error(RunnerMachineDirectoryError),
}

pub struct FakeDirectory {
    answer: Mutex<DirectoryAnswer>,
    requests: Mutex<Vec<Sha256Digest>>,
    calls: AtomicUsize,
}

impl FakeDirectory {
    pub fn new(record: Option<RunnerMachineRecord>) -> Self {
        Self {
            answer: Mutex::new(DirectoryAnswer::Found(record)),
            requests: Mutex::new(Vec::new()),
            calls: AtomicUsize::new(0),
        }
    }

    pub fn set_record(&self, record: Option<RunnerMachineRecord>) {
        *self.answer.lock().expect("directory answer") = DirectoryAnswer::Found(record);
    }

    pub fn set_error(&self, error: RunnerMachineDirectoryError) {
        *self.answer.lock().expect("directory answer") = DirectoryAnswer::Error(error);
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }

    pub fn requests(&self) -> Vec<Sha256Digest> {
        self.requests.lock().expect("directory requests").clone()
    }
}

impl fmt::Debug for FakeDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeDirectory")
            .field("calls", &self.calls())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl RunnerMachineDirectory for FakeDirectory {
    async fn find_by_leaf_sha256(
        &self,
        leaf_sha256: Sha256Digest,
    ) -> Result<Option<RunnerMachineRecord>, RunnerMachineDirectoryError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.requests
            .lock()
            .expect("directory requests")
            .push(leaf_sha256);
        match self.answer.lock().expect("directory answer").clone() {
            DirectoryAnswer::Found(record) => Ok(record),
            DirectoryAnswer::Error(error) => Err(error),
        }
    }
}

#[derive(Debug)]
pub struct MutableClock(AtomicU64);

impl MutableClock {
    pub fn new(now: u64) -> Self {
        Self(AtomicU64::new(now))
    }

    pub fn set(&self, now: u64) {
        self.0.store(now, Ordering::Relaxed);
    }
}

impl Clock for MutableClock {
    fn now(&self) -> UnixTimestamp {
        UnixTimestamp::from_seconds(self.0.load(Ordering::Relaxed))
    }
}

pub fn digest(leaf: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(leaf).into())
}

pub fn record(
    leaf: &[u8],
    external_identity: &str,
    runner_id: RunnerId,
    generation: u64,
    expires_at: u64,
    desired_state: DesiredRunnerState,
) -> RunnerMachineRecord {
    RunnerMachineRecord::new(
        ExternalRunnerIdentity::new(external_identity).expect("external identity"),
        runner_id,
        RunnerGeneration::new(generation).expect("generation"),
        digest(leaf),
        UnixTimestamp::from_seconds(expires_at),
        desired_state,
    )
    .expect("runner machine record")
}

pub fn evidence(certificates: impl IntoIterator<Item = Vec<u8>>) -> MachineAuthenticationEvidence {
    MachineAuthenticationEvidence::new(certificates.into_iter().collect())
        .expect("machine authentication evidence")
}

pub fn authenticator(
    directory: &Arc<FakeDirectory>,
    clock: &Arc<MutableClock>,
    limits: RunnerMachineAuthLimits,
) -> DurableRunnerMachineAuthenticator {
    let directory: Arc<dyn RunnerMachineDirectory> = directory.clone();
    let clock: Arc<dyn Clock> = clock.clone();
    DurableRunnerMachineAuthenticator::new(directory, clock, limits)
}
