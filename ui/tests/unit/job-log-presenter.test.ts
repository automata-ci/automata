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
  emittedAtMs: 1_000,
  group: { id: "build/one", parentId: null, name: "Build", kind: "step", ordinal: 2 },
};
const output: LiveLogRecord = {
  type: "output",
  streamId: started.streamId,
  sequence: "2",
  emittedAtMs: 1_250,
  groupId: "build/one",
  channel: "stdout",
  part: 0,
  data: Uint8Array.from("Compiling automata\n", (character) => character.charCodeAt(0)),
};
const finished: LiveLogRecord = {
  type: "group_finished",
  streamId: started.streamId,
  sequence: "3",
  emittedAtMs: 2_250,
  groupId: "build/one",
  conclusion: "success",
};

describe("job log presentation", () => {
  it("replays, orders, filters, and formats structured groups", () => {
    const replayed = replayLogRecords([started, output, finished]);
    const group = replayed.ordered[0];
    expect(group).toMatchObject({ id: "build/one", conclusion: "success" });
    expect(group?.lines[0]?.text).toBe("Compiling automata");
    expect(replayed.expanded).toEqual(new Set());
    expect(projectVisibleLogGroups(replayed.ordered, "COMPIL")[0]?.lines[0]?.text).toBe("Compiling automata");
    expect(projectVisibleLogGroups(replayed.ordered, "stdout")[0]?.lines).toHaveLength(1);
    expect(projectVisibleLogGroups(replayed.ordered, "2")[0]?.lines).toHaveLength(1);
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
    const groups = replayLogRecords([]).groups;
    applyLogRecord(groups, started);
    expect(() => applyLogRecord(groups, started)).toThrow("repeated");
    expect(() => applyLogRecord(new Map(), output)).toThrow("unknown group");
    applyLogRecord(groups, finished);
    expect(() => applyLogRecord(groups, output)).toThrow("finished group");
    expect(() => applyLogRecord(new Map(), { ...started, group: { ...started.group, id: "child", parentId: "missing" } })).toThrow("unknown parent");
  });

  it("keeps stdout, stderr, and system terminal state independent while interleaving", () => {
    const groups = replayLogRecords([]).groups;
    applyLogRecord(groups, started);
    applyLogRecord(groups, {
      ...output,
      data: Uint8Array.from([0x1b, 0x5b, 0x33, 0x31, 0x6d, 0xf0, 0x9f]),
    });
    applyLogRecord(groups, {
      ...output,
      sequence: "3",
      channel: "stderr",
      data: new TextEncoder().encode("error\n"),
    });
    applyLogRecord(groups, {
      ...output,
      sequence: "4",
      data: Uint8Array.from([0x98, 0x80, 0x1b, 0x5b, 0x30, 0x6d, 0x0a]),
    });

    const lines = orderedLogGroups(groups)[0]?.lines;
    expect(lines?.map((line) => [line.sourceSequence, line.channel, line.text])).toEqual([
      ["2", "stdout", "😀"],
      ["3", "stderr", "error"],
    ]);
    expect(lines?.[0]?.spans[0]?.style.foreground).toEqual({ kind: "palette", index: 1 });
    expect(lines?.[1]?.spans[0]?.style.foreground).toBeNull();
  });

  it("toggles sets and detects follow distance", () => {
    expect(toggleSet(new Set(["one"]), "one")).toEqual(new Set());
    expect(toggleSet(new Set(), "one")).toEqual(new Set(["one"]));
    expect(isNearLogBottom(null)).toBe(true);
    expect(isNearLogBottom({ scrollHeight: 500, scrollTop: 390, clientHeight: 40 } as HTMLElement)).toBe(true);
    expect(isNearLogBottom({ scrollHeight: 500, scrollTop: 100, clientHeight: 40 } as HTMLElement)).toBe(false);
  });
});
