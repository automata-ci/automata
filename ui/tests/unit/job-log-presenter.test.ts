import { describe, expect, it } from "vitest";
import type { LiveLogRecord } from "../../src/logs";
import {
  applyLogRecord,
  isNearLogBottom,
  logGroupDuration,
  logGroupPanelId,
  logGroupStatus,
  orderedLogGroups,
  projectVisibleLogGroups,
  replayLogRecords,
  toggleSet,
  type LogGroupView,
} from "../../src/presenters/jobLogs";

const started: LiveLogRecord = {
  type: "group_started",
  streamId: "00000000-0000-4000-8000-000000000001",
  sequence: "1",
  fragment: null,
  emittedAtMs: 1_000,
  group: { id: "build/one", parentId: null, name: "Build", kind: "step", ordinal: 2 },
};
const line: LiveLogRecord = {
  type: "line",
  streamId: started.streamId,
  sequence: "2",
  fragment: null,
  emittedAtMs: 1_250,
  groupId: "build/one",
  channel: "stdout",
  text: "Compiling automata",
};
const finished: LiveLogRecord = {
  type: "group_finished",
  streamId: started.streamId,
  sequence: "3",
  fragment: null,
  emittedAtMs: 2_250,
  groupId: "build/one",
  conclusion: "success",
};

describe("job log presentation", () => {
  it("replays, orders, filters, and formats structured groups", () => {
    const replayed = replayLogRecords([started, line, finished]);
    const group = replayed.ordered[0];
    expect(group).toMatchObject({ id: "build/one", conclusion: "success" });
    expect(group?.lines).toEqual([line]);
    expect(replayed.expanded).toEqual(new Set());
    expect(projectVisibleLogGroups(replayed.ordered, "COMPIL")[0]?.lines).toEqual([line]);
    expect(projectVisibleLogGroups(replayed.ordered, "stdout")[0]?.lines).toEqual([line]);
    expect(projectVisibleLogGroups(replayed.ordered, "2")[0]?.lines).toEqual([line]);
    expect(projectVisibleLogGroups(replayed.ordered, "missing")).toEqual([]);
    expect(projectVisibleLogGroups(replayed.ordered, "Build")[0]?.lines).toEqual([]);
    expect(logGroupDuration(group as LogGroupView)).toBe("1.3s");
    expect(logGroupStatus(group as LogGroupView)).toBe("Success");
    expect(logGroupPanelId("build/one")).toBe("log-group-6275696c642f6f6e65");
  });

  it("covers running, millisecond, timeout, and deterministic ordering states", () => {
    const running = replayLogRecords([started]).ordered[0] as LogGroupView;
    expect(logGroupDuration(running)).toBe("Running");
    expect(logGroupStatus(running)).toBe("Running");
    const timedOut = { ...running, finishedAtMs: 1_500, conclusion: "timed_out" as const };
    expect(logGroupDuration(timedOut)).toBe("500ms");
    expect(logGroupStatus(timedOut)).toBe("Timed out");
    const earlier = { ...running, id: "earlier", ordinal: 1 };
    expect(orderedLogGroups(new Map([[running.id, running], [earlier.id, earlier]])).map(({ id }) => id)).toEqual(["earlier", "build/one"]);
    const sameOrdinal = { ...running, id: "assemble", ordinal: running.ordinal };
    expect(orderedLogGroups(new Map([[running.id, running], [sameOrdinal.id, sameOrdinal]])).map(({ id }) => id)).toEqual(["assemble", "build/one"]);
  });

  it("rejects invalid stream transitions", () => {
    const groups = new Map<string, LogGroupView>();
    applyLogRecord(groups, started);
    expect(() => applyLogRecord(groups, started)).toThrow("repeated");
    expect(() => applyLogRecord(new Map(), line)).toThrow("unknown group");
    applyLogRecord(groups, finished);
    expect(() => applyLogRecord(groups, line)).toThrow("finished group");
    expect(() => applyLogRecord(new Map(), { ...started, group: { ...started.group, id: "child", parentId: "missing" } })).toThrow("unknown parent");
  });

  it("toggles sets and detects follow distance", () => {
    expect(toggleSet(new Set(["one"]), "one")).toEqual(new Set());
    expect(toggleSet(new Set(), "one")).toEqual(new Set(["one"]));
    expect(isNearLogBottom(null)).toBe(true);
    expect(isNearLogBottom({ scrollHeight: 500, scrollTop: 390, clientHeight: 40 } as HTMLElement)).toBe(true);
    expect(isNearLogBottom({ scrollHeight: 500, scrollTop: 100, clientHeight: 40 } as HTMLElement)).toBe(false);
  });
});
