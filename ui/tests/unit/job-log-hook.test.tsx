import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { LiveLogControllerOptions } from "../../src/logs/controller";
import type { LiveLogRecord } from "../../src/logs/sse";
import { useJobLogs } from "../../src/hooks/useJobLogs";
import { previewJobLog, previewJobLogRecords } from "../../src/preview/models";
import { PREVIEW_PRIMARY_RUN_ID } from "../../src/preview/sampleData";
import type { JobLogsViewState } from "../../src/viewModels/jobLogs";

const controllerHarness = vi.hoisted(() => ({
  instances: [] as Array<{
    options: LiveLogControllerOptions;
    start: ReturnType<typeof vi.fn>;
    pause: ReturnType<typeof vi.fn>;
    dispose: ReturnType<typeof vi.fn>;
  }>,
}));

vi.mock("../../src/logs/controller", () => ({
  LiveLogController: class {
    readonly start = vi.fn(async () => undefined);
    readonly pause = vi.fn();
    readonly dispose = vi.fn();

    constructor(readonly options: LiveLogControllerOptions) {
      controllerHarness.instances.push(this);
    }
  },
}));

vi.mock("../../src/logs/protocol", () => ({
  createSameOriginLiveLogAccessProvider: vi.fn(() => vi.fn()),
}));

let root: Root | null = null;

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  document.body.replaceChildren();
  controllerHarness.instances.length = 0;
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("useJobLogs", () => {
  it("projects records and owns the log viewer interactions", async () => {
    const model = jobLogFixture();
    const records = previewJobLogRecords(PREVIEW_PRIMARY_RUN_ID, null);
    let latest: JobLogsViewState | null = null;

    function Harness() {
      latest = useJobLogs({ initialRecords: records, model });
      return <div ref={latest.viewerRef} />;
    }

    const viewer = await render(<Harness />);
    const current = () => {
      if (latest === null) throw new Error("job log hook did not render");
      return latest as JobLogsViewState;
    };
    const firstGroup = current().visibleGroups[0];
    if (firstGroup === undefined) throw new Error("preview job log has no groups");

    expect(current().logToolsAvailable).toBe(true);
    expect(current().running).toBe(model.job.status.tone === "running");
    expect(current().connection).toBe("idle");

    await act(async () => current().onQueryChange(firstGroup.name));
    expect(current().query).toBe(firstGroup.name);
    expect(current().visibleGroups).toHaveLength(1);

    const wasExpanded = current().expanded.has(firstGroup.id);
    await act(async () => current().onToggleGroup(firstGroup.id));
    expect(current().expanded.has(firstGroup.id)).toBe(!wasExpanded);

    const firstToggleExpands = current().canExpand;
    await act(async () => current().onToggleAll());
    expect(current().expanded.size).toBe(
      firstToggleExpands ? current().visibleGroups.length : 0,
    );
    await act(async () => current().onToggleAll());
    expect(current().expanded.size).toBe(
      firstToggleExpands ? 0 : current().visibleGroups.length,
    );

    const scrollTo = vi.fn();
    Object.defineProperties(viewer, {
      clientHeight: { configurable: true, value: 100 },
      scrollHeight: { configurable: true, value: 1_000 },
      scrollTop: { configurable: true, value: 0, writable: true },
      scrollTo: { configurable: true, value: scrollTo },
    });
    await act(async () => current().onViewerScroll());
    expect(current().following).toBe(false);
    await act(async () => current().onToggleFollowing());
    expect(current().following).toBe(true);
    expect(scrollTo).toHaveBeenCalledWith({ top: 1_000 });
    await act(async () => current().onToggleFollowing());
    expect(current().following).toBe(false);
    Object.defineProperty(viewer, "scrollTop", {
      configurable: true,
      value: 900,
      writable: true,
    });
    await act(async () => current().onViewerScroll());
    expect(current().following).toBe(false);
  });

  it("marks a queued job as running even before records arrive", async () => {
    const model = jobLogFixture();
    let latest: JobLogsViewState | null = null;

    function Harness() {
      latest = useJobLogs({
        initialRecords: [],
        model: {
          ...model,
          job: {
            ...model.job,
            status: { ...model.job.status, tone: "queued" },
          },
        },
      });
      return null;
    }

    await render(<Harness />);
    if (latest === null) throw new Error("job log hook did not render");
    expect((latest as JobLogsViewState).running).toBe(true);
    expect((latest as JobLogsViewState).logToolsAvailable).toBe(true);
  });

  it("owns the live controller lifecycle and applies streamed records", async () => {
    const fixture = jobLogFixture();
    const model = {
      ...fixture,
      live: { ticketHref: `${fixture.job.href}/live-ticket` },
    };
    let latest: JobLogsViewState | null = null;

    function Harness() {
      latest = useJobLogs({ initialRecords: [], model });
      return null;
    }

    const visibility = vi.spyOn(document, "visibilityState", "get").mockReturnValue("visible");
    await render(<Harness />);
    const current = () => {
      if (latest === null) throw new Error("job log hook did not render");
      return latest as JobLogsViewState;
    };
    const controller = controllerHarness.instances[0];
    if (controller === undefined) throw new Error("live controller was not created");
    expect(controller.start).toHaveBeenCalledOnce();

    await act(async () => controller.options.onStateChange?.({ kind: "open" }));
    expect(current().connection).toBe("open");
    await act(async () => controller.options.onFailure?.({
      code: "network",
      message: "offline",
    }));
    expect(current().streamError).toContain("could not be opened");

    const records = streamedRecords();
    const firstRecord = records[0];
    if (firstRecord === undefined) throw new Error("stream fixture is empty");
    await act(async () => controller.options.onRecord(firstRecord, firstRecord.sequence));
    const outputSubscriber = vi.fn();
    const unsubscribeOutput = current().subscribeOutput("successful-step", outputSubscriber);
    for (const record of records.slice(1)) {
      await act(async () => controller.options.onRecord(record, record.sequence));
    }
    expect(outputSubscriber).toHaveBeenCalledWith(expect.arrayContaining([
      expect.objectContaining({ text: "building" }),
    ]));
    unsubscribeOutput();
    expect(current().visibleGroups).toHaveLength(2);
    expect(current().expanded.has("successful-step")).toBe(false);
    expect(current().expanded.has("failed-step")).toBe(true);

    visibility.mockReturnValue("hidden");
    document.dispatchEvent(new Event("visibilitychange"));
    expect(controller.pause).toHaveBeenCalledOnce();
    visibility.mockReturnValue("visible");
    controller.start.mockRejectedValueOnce(new Error("offline"));
    await act(async () => document.dispatchEvent(new Event("visibilitychange")));
    expect(current().streamError).toBe("The log stream could not be opened.");

    await act(async () => root?.unmount());
    root = null;
    expect(controller.dispose).toHaveBeenCalledOnce();
  });

  it("does not create a live controller for restricted logs", async () => {
    const fixture = jobLogFixture();

    function Harness() {
      useJobLogs({
        initialRecords: [],
        model: {
          ...fixture,
          live: { ticketHref: `${fixture.job.href}/live-ticket` },
          logVisibility: "restricted",
        },
      });
      return null;
    }

    await render(<Harness />);
    expect(controllerHarness.instances).toHaveLength(0);
  });
});

async function render(element: React.ReactNode): Promise<HTMLDivElement> {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
  await act(async () => root?.render(element));
  return container.firstElementChild instanceof HTMLDivElement
    ? container.firstElementChild
    : container;
}

function streamedRecords(): readonly LiveLogRecord[] {
  const base = {
    streamId: "12345678-1234-4123-8123-123456789abc",
  } as const;
  return [
    {
      ...base,
      type: "group_started",
      sequence: "1",
      emittedAtMs: 1_000,
      group: {
        id: "successful-step",
        parentId: null,
        name: "Build",
        kind: "step",
        ordinal: 1,
      },
    },
    {
      ...base,
      type: "output",
      sequence: "2",
      emittedAtMs: 1_100,
      groupId: "successful-step",
      channel: "stdout",
      part: 0,
      data: Uint8Array.from("building\n", (character) => character.charCodeAt(0)),
    },
    {
      ...base,
      type: "group_finished",
      sequence: "3",
      emittedAtMs: 1_200,
      groupId: "successful-step",
      conclusion: "success",
    },
    {
      ...base,
      type: "group_started",
      sequence: "4",
      emittedAtMs: 1_300,
      group: {
        id: "failed-step",
        parentId: null,
        name: "Test",
        kind: "step",
        ordinal: 2,
      },
    },
    {
      ...base,
      type: "group_finished",
      sequence: "5",
      emittedAtMs: 1_400,
      groupId: "failed-step",
      conclusion: "failure",
    },
  ];
}

function jobLogFixture(): NonNullable<ReturnType<typeof previewJobLog>> {
  const model = previewJobLog(PREVIEW_PRIMARY_RUN_ID, null);
  if (model === null) throw new Error("preview job log fixture is missing");
  return model;
}
