//! Object-safe scheduling policy port and deterministic default policy.

use std::fmt;

use crate::{
    CandidateDecline, CandidateDeclineReason, PlacementDecision, PlacementDecline,
    RunnerRequirementDecline, SchedulingInput,
};

/// Pure, object-safe application port for selecting one placement.
///
/// Implementations must not perform I/O or mutate queue/runner state. The
/// application layer persists the returned placement atomically under its own
/// lease, fencing, and idempotency ports.
pub trait SchedulerPolicy: fmt::Debug + Send + Sync {
    /// Evaluates one already-validated immutable snapshot.
    fn decide(&self, input: SchedulingInput<'_>) -> PlacementDecision;
}

/// Stable FIFO policy with deterministic runner and slot tie-breaking.
///
/// Candidates are ordered by queue timestamp and attempt ID. Runners are
/// ordered by durable runner ID and slots by one-based ordinal. Input slice
/// order therefore cannot change a decision.
#[derive(Clone, Copy, Debug, Default)]
pub struct DeterministicScheduler;

impl SchedulerPolicy for DeterministicScheduler {
    fn decide(&self, input: SchedulingInput<'_>) -> PlacementDecision {
        if input.candidates().is_empty() {
            return PlacementDecision::Decline(PlacementDecline::NoRunnableCandidates);
        }
        if input.runners().is_empty() {
            return PlacementDecision::Decline(PlacementDecline::NoEffectiveRunners);
        }

        let mut candidates = input.candidates().iter().collect::<Vec<_>>();
        candidates.sort_by_key(|candidate| (candidate.queued_at(), candidate.attempt_id()));
        let mut runners = input.runners().iter().collect::<Vec<_>>();
        runners.sort_by_key(|runner| runner.session().runner_id());

        let mut declines = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let mut busy = Vec::new();
            let mut incompatible = Vec::new();
            for runner in &runners {
                match runner
                    .capabilities()
                    .satisfies(candidate.routing().runner())
                {
                    Ok(()) => {
                        if let Some(slot) = runner.available_slots().first().copied()
                            && let Ok(placement) = input.place(candidate, runner, slot)
                        {
                            return PlacementDecision::Place(placement);
                        }
                        busy.push(runner.session().runner_id());
                    }
                    Err(mismatches) => {
                        incompatible.push(RunnerRequirementDecline::new(
                            runner.session().runner_id(),
                            mismatches.into_vec(),
                        ));
                    }
                }
            }

            let reason = if busy.is_empty() {
                CandidateDeclineReason::NoCompatibleRunner(incompatible)
            } else {
                CandidateDeclineReason::CompatibleRunnersBusy(busy)
            };
            declines.push(CandidateDecline::new(candidate.attempt_id(), reason));
        }

        PlacementDecision::Decline(PlacementDecline::Candidates(declines))
    }
}
