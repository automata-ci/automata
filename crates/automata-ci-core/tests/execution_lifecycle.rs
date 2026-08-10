use automata_ci_core::JobLifecycle;

#[test]
fn lifecycle_allows_only_declared_edges_property_style() {
    let states = [
        JobLifecycle::Queued,
        JobLifecycle::Leased,
        JobLifecycle::Preparing,
        JobLifecycle::Running,
        JobLifecycle::Cancelling,
        JobLifecycle::Finalizing,
        JobLifecycle::Succeeded,
        JobLifecycle::Failed,
        JobLifecycle::Cancelled,
        JobLifecycle::TimedOut,
        JobLifecycle::Skipped,
        JobLifecycle::Lost,
    ];
    for from in states {
        for to in states {
            let expected = matches!(
                (from, to),
                (
                    JobLifecycle::Queued,
                    JobLifecycle::Leased | JobLifecycle::Cancelled | JobLifecycle::Skipped
                ) | (
                    JobLifecycle::Leased,
                    JobLifecycle::Preparing
                        | JobLifecycle::Queued
                        | JobLifecycle::Cancelling
                        | JobLifecycle::Failed
                        | JobLifecycle::Lost
                ) | (
                    JobLifecycle::Preparing,
                    JobLifecycle::Running
                        | JobLifecycle::Queued
                        | JobLifecycle::Cancelling
                        | JobLifecycle::Failed
                        | JobLifecycle::TimedOut
                        | JobLifecycle::Skipped
                        | JobLifecycle::Lost
                ) | (
                    JobLifecycle::Running,
                    JobLifecycle::Queued
                        | JobLifecycle::Cancelling
                        | JobLifecycle::Finalizing
                        | JobLifecycle::TimedOut
                        | JobLifecycle::Lost
                ) | (
                    JobLifecycle::Cancelling,
                    JobLifecycle::Finalizing
                        | JobLifecycle::Cancelled
                        | JobLifecycle::Failed
                        | JobLifecycle::TimedOut
                        | JobLifecycle::Lost
                ) | (
                    JobLifecycle::Finalizing,
                    JobLifecycle::Succeeded
                        | JobLifecycle::Failed
                        | JobLifecycle::Cancelled
                        | JobLifecycle::TimedOut
                        | JobLifecycle::Lost
                )
            );
            assert_eq!(
                from.validate_transition(to).is_ok(),
                expected,
                "unexpected validity for {from:?} -> {to:?}",
            );
        }
    }
}

#[test]
fn terminal_states_cannot_transition() {
    for terminal in [
        JobLifecycle::Succeeded,
        JobLifecycle::Failed,
        JobLifecycle::Cancelled,
        JobLifecycle::TimedOut,
        JobLifecycle::Skipped,
        JobLifecycle::Lost,
    ] {
        assert!(terminal.is_terminal());
        assert!(terminal.validate_transition(JobLifecycle::Queued).is_err());
    }
}
