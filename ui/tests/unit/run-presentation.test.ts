import { describe, expect, it } from "vitest";
import {
  durationCopy,
  emptyArtifactsCopy,
  emptyJobsCopy,
  formatEventName,
  startTimeCopy,
} from "../../src/presentation/runPresentation";

describe("run presentation copy", () => {
  it("formats machine event identifiers for people", () => {
    expect(formatEventName("pull_request")).toBe("pull request");
    expect(formatEventName("workflow_dispatch")).toBe("workflow dispatch");
    expect(formatEventName("pull__request")).toBe("pull request");
    expect(formatEventName("push")).toBe("push");
    expect(formatEventName("___")).toBe("workflow event");
  });

  it("describes missing and duplicate durations without repeating status", () => {
    expect(durationCopy({ label: "Queued", tone: "queued" }, null)).toBe(
      "Not started",
    );
    expect(durationCopy({ label: "In progress", tone: "running" }, null)).toBe(
      "Duration in progress",
    );
    expect(durationCopy({ label: "Succeeded", tone: "success" }, null)).toBe(
      "Duration not recorded",
    );
    expect(
      durationCopy({ label: "In progress", tone: "running" }, "In progress"),
    ).toBe("Duration in progress");
    expect(
      durationCopy({ label: "Succeeded", tone: "success" }, "2m 14s"),
    ).toBe("2m 14s");
  });

  it("uses waiting copy only for work that is actually queued", () => {
    const queued = { label: "Queued", tone: "queued" } as const;
    const running = { label: "In progress", tone: "running" } as const;
    const terminal = { label: "Failed", tone: "failure" } as const;

    expect(startTimeCopy(queued)).toBe("Waiting to start");
    expect(startTimeCopy(terminal)).toBe("Start time not recorded");
    expect(emptyJobsCopy(queued)).toContain("will appear");
    expect(emptyJobsCopy(running)).toBe("No jobs have been recorded yet.");
    expect(emptyJobsCopy(terminal)).toBe("No jobs were recorded for this run.");
    expect(emptyArtifactsCopy(queued)).toContain("after this run starts");
    expect(emptyArtifactsCopy(terminal)).toBe(
      "This run did not produce any artifacts.",
    );
  });
});
