import { describe, expect, it } from "vitest";
import { TerminalDomRenderer } from "../../src/logs/domRenderer";
import type { TerminalLine } from "../../src/logs/terminal";

describe("TerminalDomRenderer", () => {
  it("appends rows without touching rendered history", () => {
    const host = document.createElement("div");
    const renderer = new TerminalDomRenderer(host, createLine);
    const lines = [line("1"), line("2")];
    renderer.sync(lines);
    const first = host.firstElementChild;

    lines.push(line("3"));
    renderer.sync(lines);

    expect(host.children).toHaveLength(3);
    expect(host.firstElementChild).toBe(first);
    expect(host.lastElementChild?.textContent).toBe("3");
  });

  it("replaces a changing terminal tail while preserving completed rows", () => {
    const host = document.createElement("div");
    const renderer = new TerminalDomRenderer(host, createLine);
    const completed = line("1");
    const pending = line("2", "working");
    renderer.sync([completed, pending]);
    const first = host.firstElementChild;
    const oldTail = host.lastElementChild;

    renderer.sync([completed, line("2", "done")]);

    expect(host.firstElementChild).toBe(first);
    expect(host.lastElementChild).not.toBe(oldTail);
    expect(host.lastElementChild?.textContent).toBe("done");
  });

  it("fully reconciles non-local changes", () => {
    const host = document.createElement("div");
    const renderer = new TerminalDomRenderer(host, createLine);
    const original = Array.from({ length: 20 }, (_, index) => line(String(index)));
    renderer.sync(original);
    const first = host.firstElementChild;

    const replacement = [...original];
    replacement[0] = line("replacement");
    renderer.sync(replacement);

    expect(host.firstElementChild).not.toBe(first);
    expect(host.firstElementChild?.textContent).toBe("replacement");
    expect(host.children).toHaveLength(20);
  });
});

function createLine(value: TerminalLine): HTMLElement {
  const element = document.createElement("div");
  element.textContent = value.text;
  return element;
}

function line(key: string, text = key): TerminalLine {
  return {
    channel: "stdout",
    emittedAtMs: 1_777_890_010_000,
    key,
    number: key,
    sourceSequence: key,
    spans: [],
    text,
  };
}
