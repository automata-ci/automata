mod support;

use automata_ci_control_plane::{
    CandidateCapacity, CandidateDeclineReason, DeterministicScheduler, PlacementDecision,
    PlacementDecline, PlacementFactoryError, RunnableCandidate, SchedulerPolicy, SchedulingInput,
    SchedulingInputError, classify_candidate_capacity,
};
use automata_ci_core::RequirementMismatch;

use support::{candidate, effective_runner};

#[test]
fn default_policy_is_fifo_and_independent_of_input_order() {
    let newer = candidate(1, 200, &["linux"]);
    let older = candidate(2, 100, &["linux"]);
    let larger_runner = effective_runner(2, &["linux"], &[], &[2, 1]);
    let smaller_runner = effective_runner(1, &["linux"], &[], &[2, 1]);
    let candidates = [newer.clone(), older.clone()];
    let runners = [larger_runner.clone(), smaller_runner.clone()];
    let reversed_candidates = [older.clone(), newer];
    let reversed_runners = [smaller_runner, larger_runner];
    let policy = DeterministicScheduler;

    let first =
        policy.decide(SchedulingInput::new(&candidates, &runners).expect("snapshot must be valid"));
    let reversed = policy.decide(
        SchedulingInput::new(&reversed_candidates, &reversed_runners)
            .expect("snapshot must be valid"),
    );

    assert_eq!(first, reversed);
    let PlacementDecision::Place(placement) = first else {
        panic!("a matching placement was expected");
    };
    assert_eq!(placement.attempt_id(), older.attempt_id());
    assert_eq!(placement.session().runner_id(), support::runner_id(1));
    assert_eq!(placement.slot().ordinal(), 1);
    assert_eq!(
        placement.slot().runner_id(),
        placement.session().runner_id()
    );
}

#[test]
fn matching_runner_without_capacity_has_a_typed_busy_decline() {
    let candidates = [candidate(1, 100, &["linux"])];
    let runners = [effective_runner(1, &["linux"], &[], &[])];
    let decision = DeterministicScheduler
        .decide(SchedulingInput::new(&candidates, &runners).expect("snapshot must be valid"));

    let PlacementDecision::Decline(PlacementDecline::Candidates(declines)) = decision else {
        panic!("a per-candidate decline was expected");
    };
    assert_eq!(declines.len(), 1);
    assert_eq!(declines[0].attempt_id(), candidates[0].attempt_id());
    assert_eq!(
        declines[0].reason(),
        &CandidateDeclineReason::CompatibleRunnersBusy(vec![support::runner_id(1)])
    );
}

#[test]
fn aggregate_capacity_classification_uses_the_scheduler_match_and_slot_contract() {
    let candidate = candidate(1, 100, &["linux"]);
    assert_eq!(
        classify_candidate_capacity(&candidate, &[]),
        CandidateCapacity::NoCompatibleRunner
    );
    assert_eq!(
        classify_candidate_capacity(&candidate, &[effective_runner(1, &["windows"], &[], &[1])]),
        CandidateCapacity::NoCompatibleRunner
    );
    assert_eq!(
        classify_candidate_capacity(&candidate, &[effective_runner(1, &["linux"], &[], &[])]),
        CandidateCapacity::CompatibleRunnersBusy
    );
    assert_eq!(
        classify_candidate_capacity(&candidate, &[effective_runner(1, &["linux"], &[], &[1])]),
        CandidateCapacity::Available
    );
}

#[test]
fn incompatibility_preserves_complete_core_matching_diagnostics() {
    let candidates = [candidate(1, 100, &["gpu", "linux"])];
    let runners = [effective_runner(1, &["linux"], &[], &[1])];
    let decision = DeterministicScheduler
        .decide(SchedulingInput::new(&candidates, &runners).expect("snapshot must be valid"));

    let PlacementDecision::Decline(PlacementDecline::Candidates(declines)) = decision else {
        panic!("a per-candidate decline was expected");
    };
    let CandidateDeclineReason::NoCompatibleRunner(runner_declines) = declines[0].reason() else {
        panic!("a capability decline was expected");
    };
    assert_eq!(runner_declines.len(), 1);
    assert_eq!(runner_declines[0].runner_id(), support::runner_id(1));
    assert_eq!(
        runner_declines[0].mismatches(),
        &[RequirementMismatch::MissingLabel(support::label("gpu"))]
    );
}

#[test]
fn empty_queue_and_empty_runner_fleet_are_distinct_declines() {
    let no_candidates: [RunnableCandidate; 0] = [];
    let runner = effective_runner(1, &["linux"], &[], &[1]);
    let runners = [runner];
    assert_eq!(
        DeterministicScheduler.decide(
            SchedulingInput::new(&no_candidates, &runners).expect("snapshot must be valid")
        ),
        PlacementDecision::Decline(PlacementDecline::NoRunnableCandidates)
    );

    let candidates = [candidate(1, 100, &["linux"])];
    let no_runners = [];
    assert_eq!(
        DeterministicScheduler.decide(
            SchedulingInput::new(&candidates, &no_runners).expect("snapshot must be valid")
        ),
        PlacementDecision::Decline(PlacementDecline::NoEffectiveRunners)
    );
}

#[test]
fn scheduling_snapshot_rejects_ambiguous_attempt_and_runner_records() {
    let first = candidate(1, 100, &["linux"]);
    assert_eq!(
        SchedulingInput::new(&[first.clone(), first.clone()], &[])
            .expect_err("duplicate attempt must fail"),
        SchedulingInputError::DuplicateAttempt(first.attempt_id())
    );

    let runner = effective_runner(1, &["linux"], &[], &[1]);
    assert_eq!(
        SchedulingInput::new(&[], &[runner.clone(), runner])
            .expect_err("duplicate runner must fail"),
        SchedulingInputError::DuplicateRunner(support::runner_id(1))
    );
}

#[derive(Debug)]
struct FirstValidatedPlacement;

impl SchedulerPolicy for FirstValidatedPlacement {
    fn decide(&self, input: SchedulingInput<'_>) -> PlacementDecision {
        let candidate = &input.candidates()[0];
        let runner = &input.runners()[0];
        let slot = runner
            .available_slots()
            .first()
            .copied()
            .expect("available slot");
        PlacementDecision::Place(
            input
                .place(candidate, runner, slot)
                .expect("snapshot members form a validated placement"),
        )
    }
}

#[test]
fn external_policy_can_construct_only_validated_snapshot_placements() {
    let candidates = [candidate(1, 100, &["linux"])];
    let runners = [effective_runner(1, &["linux"], &[], &[1])];
    let input = SchedulingInput::new(&candidates, &runners).expect("valid snapshot");
    let decision = FirstValidatedPlacement.decide(input);
    let PlacementDecision::Place(placement) = decision else {
        panic!("external policy should be able to place validated members");
    };
    assert_eq!(placement.attempt_id(), candidates[0].attempt_id());

    let lookalike = candidates[0].clone();
    let slot = runners[0]
        .available_slots()
        .first()
        .copied()
        .expect("available slot");
    assert_eq!(
        input
            .place(&lookalike, &runners[0], slot)
            .expect_err("a cloned lookalike is not a snapshot member"),
        PlacementFactoryError::ForeignCandidate
    );
}
