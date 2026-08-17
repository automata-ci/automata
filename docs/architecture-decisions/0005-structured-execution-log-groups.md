# ADR 0005: Model job logs as structured execution groups

- Status: Accepted
- Date: 2026-08-17

## Context

The durable job-log stream currently contains only an ordered sequence,
timestamp, channel, payload, and terminal marker. The web model consequently
projects every job as one flat list of lines. It cannot identify the step that
owned a line, represent setup and cleanup as distinct phases, or show live step
lifecycle independently of job lifecycle.

The browser also exposes durable cursors as page navigation. Active jobs poll a
complete rendered-page snapshot even though the shared UI already implements a
resumable SSE transport. Search filters only the currently rendered page. These
behaviors are internally consistent with a flat stream, but they cannot provide
the step-oriented workflow-run experience users expect.

GitHub Actions presents one disclosure row per execution step, includes runner
work as synthetic steps, expands the current or failed step, displays step
duration and status in the row, and keeps line permalinks inside each expanded
log panel. Automata needs the same information architecture without making
browser state or log-text conventions authoritative.

## Decision

Automata log schema 2 is an ordered stream of structured execution records.
Every record retains the attempt, stream, sequence, and emission time used by
the existing durability and replay protocol. Its payload is exactly one of:

- `group_started`: immutable group identity, optional parent, bounded display
  name, execution kind, and stable display ordinal;
- `line`: the owning group identity, output channel, and bounded raw bytes;
- `group_finished`: the group identity and terminal conclusion;
- `stream_finished`: the terminal marker for the attempt log stream.

Group identities are explicit and are never inferred from log text. Executors
must pass the group identity with every emitted line; a mutable process-global
"current step" is forbidden because nested actions and future concurrent
execution would make it ambiguous. Top-level kinds cover runner setup, workflow
steps, action pre/post phases, and cleanup. The parent relation leaves room for
composite-action hierarchy without changing the wire shape.

The GitHub executor opens a runner-diagnostics group for job-level messages and
a distinct group around every executable run, action pre, action main, and
action post phase. Resolved workflow display names label normal top-level run
and action execution; pre-job work retains its stable step identity because it
runs before the main step-expression context exists.

The runner writes start and finish records around every executor-owned group,
including groups that emit no lines. The terminal `JobResult` remains
authoritative for the final job and workflow-step conclusions; log records are
the presentation timeline and do not replace result persistence. Core validates
each typed frame and contiguous stream ordering, while the browser reducer
rejects duplicate groups and references to groups that were never started.

Immutable compressed segment objects remain the source of log records and
bytes. The job-log HTML response contains only authorized job metadata and a
same-resource ticket endpoint. It does not duplicate a partial log snapshot.
The browser replays the ordered stream from its beginning in bounded batches,
then uses the same connection and reducer for the live tail. This keeps one
authoritative delivery path for open and completed jobs and removes public log
page cursors entirely.

Live delivery uses the existing transport-neutral checkpoint contract with a
schema-2 event envelope. The browser applies group and line records to one
normalized reducer and advances a checkpoint only after application. Hidden
pages pause the transport and resume from the last checkpoint. Failed delivery
is shown explicitly; there is no second snapshot protocol with different
ordering semantics.

The active group is open by default and follows new lines while the viewer is
at the bottom. Scrolling away disables follow without moving the viewport;
"Follow logs" restores it and jumps to the current bottom. A newly started
group becomes the open panel and failed groups open automatically.
Reduced-motion mode never animates programmatic scrolling.

Search operates over the replayed document, filters by group, and expands
matching groups. The log experience requires JavaScript because authenticated
replay and tailing use short-lived, one-time capabilities.

## Compatibility and cutover

This is a greenfield hard cutover. Log schema 1, live-log protocol 1, snapshot
polling, flat line pagination, and their readers are deleted. Core accepts only
schema 2, and the browser render contract and live SSE envelope advance
together. Deployments must upgrade the control plane, runners, and UI as one
release. The migration deletes pre-cutover log-stream rows and outstanding live
log tickets, then constrains both durable schemas to version 2.

## Consequences

- Step grouping, lifecycle, ordering, and replay are durable facts shared by
  the runner, server replay, SSE, and browser reducer.
- Initial HTML cost is independent of total log size; replay cost remains
  proportional to the durable stream.
- The UI can closely match GitHub Actions while retaining Automata's explicit
  authorization, redaction, and transport boundaries.
- Runner, protocol, storage, web, and UI schemas change in one coordinated
  release with no mixed-version support.
- Historical schema-1 logs are not readable after the cutover.
