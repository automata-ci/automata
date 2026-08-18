import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { LiveLogLineRecord } from "../../src/logs/sse";
import { replayLogRecords, type LogGroupView } from "../../src/presenters/jobLogs";
import { previewJobLog, previewJobLogRecords } from "../../src/preview/models";
import { PREVIEW_PRIMARY_RUN_ID } from "../../src/preview/sampleData";
import type { JobLogsViewState, LogConnectionState } from "../../src/viewModels/jobLogs";
import { JobLogPageView, LogGroupPanel, LogLine, StreamState } from "../../src/views/JobLogPageView";

describe("job log presentation states", () => {
  it.each([
    [false, "idle", false, "Unavailable"],
    [true, "open", true, "Live"],
    [true, "connecting", true, "Connecting"],
    [true, "reconnecting", true, "Connecting"],
    [true, "complete", false, "Complete"],
    [true, "failed", false, "Failed"],
    [true, "paused", true, "Waiting"],
    [true, "idle", false, "Loaded"],
  ] satisfies ReadonlyArray<readonly [boolean, LogConnectionState, boolean, string]>) (
    "labels availability=%s state=%s running=%s as %s",
    (available, state, running, label) => {
      expect(renderToStaticMarkup(
        <StreamState available={available} running={running} state={state} />,
      )).toContain(label);
    },
  );

  it("renders restricted, searching, failed, waiting, and unavailable empty states", () => {
    const model = jobLogFixture();
    const states: ReadonlyArray<readonly [JobLogsViewState, typeof model, string]> = [
      [logs({ query: "missing" }), model, "No steps match your search."],
      [logs({ streamError: "offline" }), model, "Log output could not be loaded."],
      [logs({ running: true }), model, "Waiting for log output"],
      [logs(), model, "Logs are unavailable for this job."],
      [logs(), { ...model, logVisibility: "restricted" }, "do not have permission"],
    ];

    for (const [viewState, pageModel, copy] of states) {
      expect(renderToStaticMarkup(
        <JobLogPageView logs={viewState} model={pageModel} />,
      )).toContain(copy);
    }
  });

  it("renders collapsed, empty, and fragmented log group details", () => {
    const group = replayLogRecords(
      previewJobLogRecords(PREVIEW_PRIMARY_RUN_ID, null),
    ).ordered[0];
    if (group === undefined) throw new Error("preview job log has no group");
    expect(renderToStaticMarkup(
      <LogGroupPanel expanded={false} group={group} onToggle={vi.fn()} />,
    )).not.toContain("log-group__output");
    expect(renderToStaticMarkup(
      <LogGroupPanel
        expanded
        group={{ ...group, lines: [] }}
        onToggle={vi.fn()}
      />,
    )).toContain("No output");

    const line: LiveLogLineRecord = {
      channel: "stderr",
      emittedAtMs: 1_000,
      fragment: 2,
      groupId: group.id,
      sequence: "7",
      streamId: "12345678-1234-4123-8123-123456789abc",
      text: "fragmented",
      type: "line",
    };
    expect(renderToStaticMarkup(<LogLine line={line} />)).toContain("7.2");
    expect(renderToStaticMarkup(
      <LogGroupPanel
        expanded
        group={{ ...group, lines: [line] } satisfies LogGroupView}
        onToggle={vi.fn()}
      />,
    )).toContain("fragmented");
  });
});

function logs(overrides: Partial<JobLogsViewState> = {}): JobLogsViewState {
  return {
    canExpand: false,
    connection: "idle",
    expanded: new Set(),
    following: false,
    logToolsAvailable: false,
    onQueryChange: vi.fn(),
    onToggleAll: vi.fn(),
    onToggleFollowing: vi.fn(),
    onToggleGroup: vi.fn(),
    onViewerScroll: vi.fn(),
    query: "",
    running: false,
    streamError: null,
    visibleGroups: [],
    ...overrides,
  };
}

function jobLogFixture(): NonNullable<ReturnType<typeof previewJobLog>> {
  const model = previewJobLog(PREVIEW_PRIMARY_RUN_ID, null);
  if (model === null) throw new Error("preview job log fixture is missing");
  return model;
}
