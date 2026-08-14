//! Object-safe scheduling policy port and deterministic default policy.

use std::fmt;

use super::{
    CandidateCapacity, CandidateDecline, CandidateDeclineReason, EffectiveRunner,
    PlacementDecision, PlacementDecline, RunnableCandidate, RunnerRequirementDecline, RunnerSlot,
    SchedulingInput,
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
            let reason = match evaluate_candidate_capacity(candidate, &runners) {
                CandidateCapacityEvaluation::Available { runner, slot } => {
                    if let Ok(placement) = input.place(candidate, runner, slot) {
                        return PlacementDecision::Place(placement);
                    }
                    CandidateDeclineReason::CompatibleRunnersBusy(vec![
                        runner.session().runner_id(),
                    ])
                }
                CandidateCapacityEvaluation::CompatibleRunnersBusy(runners) => {
                    CandidateDeclineReason::CompatibleRunnersBusy(runners)
                }
                CandidateCapacityEvaluation::NoCompatibleRunner(runners) => {
                    CandidateDeclineReason::NoCompatibleRunner(runners)
                }
            };
            declines.push(CandidateDecline::new(candidate.attempt_id(), reason));
        }

        PlacementDecision::Decline(PlacementDecline::Candidates(declines))
    }
}

/// Classifies one runnable candidate using the exact scheduler capability and
/// effective-slot semantics.
#[must_use]
pub fn classify_candidate_capacity(
    candidate: &RunnableCandidate,
    runners: &[EffectiveRunner],
) -> CandidateCapacity {
    let runners = runners.iter().collect::<Vec<_>>();
    match evaluate_candidate_capacity(candidate, &runners) {
        CandidateCapacityEvaluation::Available { .. } => CandidateCapacity::Available,
        CandidateCapacityEvaluation::CompatibleRunnersBusy(_) => {
            CandidateCapacity::CompatibleRunnersBusy
        }
        CandidateCapacityEvaluation::NoCompatibleRunner(_) => CandidateCapacity::NoCompatibleRunner,
    }
}

enum CandidateCapacityEvaluation<'a> {
    Available {
        runner: &'a EffectiveRunner,
        slot: RunnerSlot,
    },
    CompatibleRunnersBusy(Vec<automata_ci_core::RunnerId>),
    NoCompatibleRunner(Vec<RunnerRequirementDecline>),
}

fn evaluate_candidate_capacity<'a>(
    candidate: &RunnableCandidate,
    runners: &[&'a EffectiveRunner],
) -> CandidateCapacityEvaluation<'a> {
    let mut busy = Vec::new();
    let mut incompatible = Vec::new();
    for runner in runners {
        match runner
            .capabilities()
            .satisfies(candidate.routing().runner())
        {
            Ok(()) => {
                if let Some(slot) = runner.available_slots().first().copied() {
                    return CandidateCapacityEvaluation::Available { runner, slot };
                }
                busy.push(runner.session().runner_id());
            }
            Err(mismatches) => incompatible.push(RunnerRequirementDecline::new(
                runner.session().runner_id(),
                mismatches.into_vec(),
            )),
        }
    }
    if busy.is_empty() {
        CandidateCapacityEvaluation::NoCompatibleRunner(incompatible)
    } else {
        CandidateCapacityEvaluation::CompatibleRunnersBusy(busy)
    }
}
