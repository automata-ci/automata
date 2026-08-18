import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { TerminalOutput } from "../../src/components/TerminalOutput";
import type { TerminalLine, TerminalSpan, TerminalTextStyle } from "../../src/logs/terminal";
import type { LogGroupView } from "../../src/presenters/jobLogs";
import type { LogOutputSubscriber } from "../../src/viewModels/jobLogs";

let root: Root | null = null;

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  document.body.replaceChildren();
  vi.unstubAllGlobals();
});

describe("TerminalOutput", () => {
  it("hydrates into a direct DOM surface and incrementally appends styled safe rows", async () => {
    const first = line("1", [
      span("red", { bold: true, dim: true, italic: true, foreground: { kind: "palette", index: 1 } }),
      span(" cube", { background: { kind: "palette", index: 22 }, strike: true, overline: true, underline: "double", underlineColor: { kind: "palette", index: 244 } }, "https://example.test/log"),
      span(" rgb", { conceal: true, foreground: { kind: "rgb", red: 1, green: 2, blue: 3 }, inverse: true, underline: "curly" }),
    ]);
    const lines = [first];
    let subscriber: LogOutputSubscriber | null = null;
    const unsubscribe = vi.fn();
    const container = await render(
      <TerminalOutput
        group={group(lines)}
        panelId="terminal-test"
        subscribeOutput={(_groupId, value) => {
          subscriber = value;
          return unsubscribe;
        }}
      />,
    );
    const original = container.querySelector(".log-line");
    const terminalLink = container.querySelector<HTMLAnchorElement>(".terminal-link");
    expect(original?.textContent).toContain("red cube rgb");
    expect(terminalLink?.href).toBe("https://example.test/log");
    expect(terminalLink?.rel).toBe("nofollow noreferrer");
    expect(container.querySelector<HTMLElement>(".terminal-text")?.style.color).not.toBe("");

    lines.push(line("2", [span("next", { underline: "dotted" }), span(" gray", { foreground: { kind: "palette", index: 250 }, underline: "dashed" })]));
    if (subscriber === null) throw new Error("terminal output did not subscribe");
    (subscriber as LogOutputSubscriber)(lines);

    expect(container.querySelectorAll(".log-line")).toHaveLength(2);
    expect(container.querySelector(".log-line")).toBe(original);
    expect(container.textContent).toContain("next gray");

    await act(async () => root?.unmount());
    root = null;
    expect(unsubscribe).toHaveBeenCalledOnce();
  });

  it("replaces the empty server fallback when the DOM surface takes ownership", async () => {
    const container = await render(
      <TerminalOutput group={group([])} panelId="empty-terminal" subscribeOutput={undefined} />,
    );
    expect(container.querySelector(".log-group__empty")).toBeNull();
    expect(container.querySelector(".log-group__output")?.childElementCount).toBe(0);
  });
});

async function render(element: React.ReactNode): Promise<HTMLDivElement> {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
  await act(async () => root?.render(element));
  return container;
}

function group(lines: readonly TerminalLine[]): LogGroupView {
  return {
    conclusion: null,
    finishedAtMs: null,
    id: "terminal",
    kind: "step",
    lines,
    name: "Terminal",
    ordinal: 0,
    parentId: null,
    startedAtMs: 1_777_890_010_000,
  };
}

function line(key: string, spans: readonly TerminalSpan[]): TerminalLine {
  return {
    channel: "stdout",
    emittedAtMs: 1_777_890_010_000,
    key,
    number: key,
    sourceSequence: key,
    spans,
    text: spans.map((value) => value.text).join(""),
  };
}

function span(text: string, overrides: Partial<TerminalTextStyle>, href: string | null = null): TerminalSpan {
  return {
    href,
    text,
    style: {
      background: null,
      blink: false,
      bold: false,
      conceal: false,
      dim: false,
      foreground: null,
      inverse: false,
      italic: false,
      overline: false,
      strike: false,
      underline: "none",
      underlineColor: null,
      ...overrides,
    },
  };
}
