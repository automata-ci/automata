// Integration-test targets compile this shared module independently and use different subsets.
#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};

use automata_ci_core::{AttemptId, FencingToken, JobId, RunId};
use automata_ci_results_github::{
    CacheAccessScope, CacheAuthority, CachePermission, ExecutionAuthority, ResultsClock,
    ResultsIdGenerator, UploadId,
};

#[derive(Clone, Copy, Debug)]
pub(crate) struct FixedClock(pub(crate) u64);

impl ResultsClock for FixedClock {
    fn now_seconds(&self) -> u64 {
        self.0
    }
}

#[derive(Debug)]
pub(crate) struct MutableClock(AtomicU64);

impl MutableClock {
    pub(crate) fn new(now: u64) -> Self {
        Self(AtomicU64::new(now))
    }

    pub(crate) fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
}

impl ResultsClock for MutableClock {
    fn now_seconds(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct FixedIds(pub(crate) UploadId);

impl ResultsIdGenerator for FixedIds {
    fn next_upload_id(&self) -> UploadId {
        self.0
    }
}

pub(crate) fn fresh_execution_authority(fence: u64) -> ExecutionAuthority {
    ExecutionAuthority::new(
        RunId::new(),
        JobId::new(),
        AttemptId::new(),
        FencingToken::new(fence).expect("positive fencing token"),
    )
}

pub(crate) fn cache_authority(
    repository: &str,
    scopes: &[(&str, CachePermission)],
) -> CacheAuthority {
    let scopes = scopes
        .iter()
        .map(|(cache_ref, permission)| {
            CacheAccessScope::new(*cache_ref, *permission).expect("cache scope")
        })
        .collect();
    CacheAuthority::new(repository, scopes).expect("cache authority")
}

pub(crate) fn read_write_cache_authority(repository: &str, cache_ref: &str) -> CacheAuthority {
    cache_authority(repository, &[(cache_ref, CachePermission::ReadWrite)])
}
