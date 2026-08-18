import { createElement, createRef } from "react";
import { flushSync } from "react-dom";
import { createRoot } from "react-dom/client";
import { bench, describe } from "vitest";
import type { LiveLogOutputRecord, LiveLogRecord } from "../../src/logs/sse";
import { TerminalTranscript } from "../../src/logs/terminal";
import { applyLogRecord, orderedLogGroups, replayLogRecords } from "../../src/presenters/jobLogs";
import { previewJobLog } from "../../src/preview/models";
import { PREVIEW_PRIMARY_RUN_ID } from "../../src/preview/sampleData";
import type { JobLogsViewState } from "../../src/viewModels/jobLogs";
import { JobLogPageView } from "../../src/views/JobLogPageView";

const STREAM_ID = "00000000-0000-4000-8000-000000000099";
const encoder = new TextEncoder();
const linePayloads = Array.from({ length: 256 }, (_, index) =>
  encoder.encode(`\u001b[38;5;${index}mcompiled café 🚀 ${index}\u001b[0m\n`));
const records = logRecords(10_000);
const terminalChunks = Array.from({ length: 64 }, (_, part) => output(
  String(part),
  part,
  encoder.encode(`${"build output ".repeat(1_000)}\u001b[38;2;12;34;56mcafé 🚀\u001b[0m\n`),
));
const renderState = replayLogRecords(records.slice(0, 5_001));
const renderContainer = document.createElement("div");
const renderRoot = createRoot(renderContainer);
const renderModel = previewJobLog(PREVIEW_PRIMARY_RUN_ID, null);
if (renderModel === null) throw new Error("benchmark model is unavailable");
let renderSequence = 5_001;
let outputSubscriber: ((lines: ReturnType<typeof orderedLogGroups>[number]["lines"]) => void) | null = null;
flushSync(() => renderRoot.render(logPage(renderState.ordered)));
const renderOutput = renderContainer.querySelector<HTMLElement>(".log-group__output");
if (renderOutput === null) throw new Error("benchmark output is unavailable");

describe("log viewer throughput", () => {
  bench("replay and project 10,000 styled records", () => {
    const result = replayLogRecords(records);
    if (result.ordered[0]?.lines.length !== 10_000) throw new Error("projection lost output");
  }, { iterations: 3, warmupIterations: 1, time: 0 });

  bench("parse about 750 KiB of chunked terminal output", () => {
    const transcript = new TerminalTranscript();
    let lines = 0;
    for (const chunk of terminalChunks) lines += transcript.push(chunk).length;
    lines += transcript.finish().length;
    if (lines !== 64) throw new Error("terminal parser lost output");
  }, { iterations: 10, warmupIterations: 2, time: 0 });

  bench("append and render into a 5,000-line open viewer", () => {
    applyLogRecord(renderState.groups, output(String(renderSequence), 0, linePayloads[renderSequence % 256] as Uint8Array));
    renderSequence += 1;
    const lines = renderState.groups.get("benchmark")?.lines;
    if (lines === undefined || outputSubscriber === null) throw new Error("incremental renderer is unavailable");
    outputSubscriber(lines);
    if (renderOutput.childElementCount !== renderSequence - 1) throw new Error("incremental renderer lost output");
  }, { iterations: 5, warmupIterations: 2, time: 0 });
});

function logPage(visibleGroups: ReturnType<typeof orderedLogGroups>) {
  const logs: JobLogsViewState = {
    canExpand: false,
    connection: "open",
    expanded: new Set(["benchmark"]),
    following: true,
    logToolsAvailable: true,
    onQueryChange: () => undefined,
    onToggleAll: () => undefined,
    onToggleFollowing: () => undefined,
    onToggleGroup: () => undefined,
    onViewerScroll: () => undefined,
    query: "",
    running: true,
    streamError: null,
    subscribeOutput: (_groupId, subscriber) => {
      outputSubscriber = subscriber;
      return () => { outputSubscriber = null; };
    },
    viewerRef: createRef<HTMLDivElement>(),
    visibleGroups,
  };
  return createElement(JobLogPageView, { logs, model: renderModel! });
}

function logRecords(count: number): readonly LiveLogRecord[] {
  const result: LiveLogRecord[] = [{
    type: "group_started",
    streamId: STREAM_ID,
    sequence: "0",
    emittedAtMs: 1_777_890_010_000,
    group: { id: "benchmark", parentId: null, name: "Benchmark", kind: "step", ordinal: 0 },
  }];
  for (let index = 0; index < count; index += 1) {
    result.push(output(String(index + 1), 0, linePayloads[index % linePayloads.length] as Uint8Array));
  }
  result.push({
    type: "group_finished",
    streamId: STREAM_ID,
    sequence: String(count + 1),
    emittedAtMs: 1_777_890_010_000 + count + 1,
    groupId: "benchmark",
    conclusion: "success",
  });
  return result;
}

function output(sequence: string, part: number, data: Uint8Array): LiveLogOutputRecord {
  return {
    type: "output",
    streamId: STREAM_ID,
    sequence,
    emittedAtMs: 1_777_890_010_000 + Number(sequence),
    groupId: "benchmark",
    channel: "stdout",
    part,
    data,
  };
}
