use super::support;

use automata_ci_core::{OperationId, Sha256Digest};
use automata_ci_protocol::CommandSequence;
use automata_ci_runner_journal::{
    CommandDisposition, CommandIgnoredReason, DurableCommand, JournalError, JournalInvariantError,
    MAX_COMMAND_TOMBSTONES, RunnerJournal,
};
use support::{Fixture, Scratch};

fn command(sequence: u64, marker: u8) -> DurableCommand {
    DurableCommand::new(
        CommandSequence::new(sequence).expect("positive command sequence"),
        OperationId::new(),
        Sha256Digest::from_bytes([marker; 32]),
    )
}

#[test]
fn ignored_commands_advance_once_and_replay_only_with_exact_identity_and_reason() {
    let scratch = Scratch::new("ignored-commands");
    let fixture = Fixture::new();
    let journal = fixture.open(&scratch);
    journal.begin_session(fixture.binding()).expect("session");
    let ignored = command(1, 0x11);
    let disposition = CommandDisposition::Ignored(CommandIgnoredReason::UnsupportedCommand);
    let first = journal
        .record_command_disposition(fixture.session_id, ignored, disposition)
        .expect("record ignored command");
    assert_eq!(
        first
            .session()
            .expect("session")
            .command_cursor()
            .acknowledged_through(),
        Some(CommandSequence::new(1).expect("sequence"))
    );
    let replay = journal
        .record_command_disposition(fixture.session_id, ignored, disposition)
        .expect("exact replay");
    assert_eq!(replay.revision(), first.revision());

    let conflicting_digest = DurableCommand::new(
        ignored.sequence(),
        ignored.operation_id(),
        Sha256Digest::from_bytes([0x22; 32]),
    );
    assert!(matches!(
        journal.record_command_disposition(fixture.session_id, conflicting_digest, disposition,),
        Err(JournalError::Invariant(
            JournalInvariantError::CommandReplayConflict
        ))
    ));
    assert!(matches!(
        journal.record_command_disposition(
            fixture.session_id,
            ignored,
            CommandDisposition::Ignored(CommandIgnoredReason::InvalidCommand),
        ),
        Err(JournalError::Invariant(
            JournalInvariantError::CommandReplayConflict
        ))
    ));

    let no_slot = command(2, 0x33);
    journal
        .record_command_disposition(
            fixture.session_id,
            no_slot,
            CommandDisposition::Ignored(CommandIgnoredReason::SlotUnavailable),
        )
        .expect("no-slot command advances");
    let stale = command(3, 0x44);
    journal
        .record_command_disposition(
            fixture.session_id,
            stale,
            CommandDisposition::Ignored(CommandIgnoredReason::StaleLease),
        )
        .expect("stale command advances");
    drop(journal);

    let recovered = fixture.open(&scratch);
    let snapshot = recovered.snapshot().expect("recovered dispositions");
    let session = snapshot.session().expect("session");
    assert_eq!(session.command_tombstones().len(), 3);
    assert_eq!(
        session.command_tombstones()[2].disposition(),
        CommandDisposition::Ignored(CommandIgnoredReason::StaleLease)
    );
}

#[test]
fn digest_tombstones_are_bounded_without_wedging_the_contiguous_cursor() {
    let scratch = Scratch::new("bounded-command-tombstones");
    let fixture = Fixture::new();
    let journal = fixture.open(&scratch);
    journal.begin_session(fixture.binding()).expect("session");
    let first = command(1, 1);
    let mut latest = first;
    for sequence in 1..=u64::try_from(MAX_COMMAND_TOMBSTONES + 8).expect("bounded maximum") {
        let next = if sequence == 1 {
            first
        } else {
            command(sequence, u8::try_from(sequence % 251).expect("marker") + 1)
        };
        journal
            .record_command_disposition(
                fixture.session_id,
                next,
                CommandDisposition::Ignored(CommandIgnoredReason::UnsupportedCommand),
            )
            .expect("advance ignored command");
        latest = next;
    }
    let bounded = journal.snapshot().expect("bounded state");
    let session = bounded.session().expect("session");
    assert_eq!(session.command_tombstones().len(), MAX_COMMAND_TOMBSTONES);
    assert_eq!(
        session.command_cursor().acknowledged_through(),
        Some(latest.sequence())
    );

    let replay = journal
        .record_command_disposition(
            fixture.session_id,
            latest,
            CommandDisposition::Ignored(CommandIgnoredReason::UnsupportedCommand),
        )
        .expect("recent replay remains exact");
    assert_eq!(replay.revision(), bounded.revision());
    assert!(matches!(
        journal.record_command_disposition(
            fixture.session_id,
            first,
            CommandDisposition::Ignored(CommandIgnoredReason::UnsupportedCommand),
        ),
        Err(JournalError::Invariant(
            JournalInvariantError::CommandReplayOutsideWindow
        ))
    ));

    let next_sequence = latest.sequence().get() + 1;
    let applied = journal
        .record_lease_offer(fixture.session_id, fixture.offer(next_sequence))
        .expect("cursor remains usable for next applied command");
    assert!(applied.slot(fixture.slot).is_some());
}
