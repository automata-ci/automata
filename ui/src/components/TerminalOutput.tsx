import { useLayoutEffect, useRef, useState, type CSSProperties } from "react";
import { TerminalDomRenderer } from "../logs/domRenderer";
import type { TerminalColor, TerminalLine, TerminalSpan } from "../logs/terminal";
import { logTime, type LogGroupView } from "../presenters/jobLogs";
import type { JobLogsViewState, LogOutputSubscriber } from "../viewModels/jobLogs";

export function TerminalOutput({ group, panelId, subscribeOutput }: { readonly group: LogGroupView; readonly panelId: string; readonly subscribeOutput: JobLogsViewState["subscribeOutput"] | undefined }) {
  const hostRef = useRef<HTMLDivElement>(null);
  const rendererRef = useRef<TerminalDomRenderer | null>(null);
  const [domOwned, setDomOwned] = useState(false);

  useLayoutEffect(() => setDomOwned(true), []);
  useLayoutEffect(() => {
    const host = hostRef.current;
    if (!domOwned || host === null) return;
    rendererRef.current ??= new TerminalDomRenderer(
      host,
      (line) => createTerminalLine(host.ownerDocument, line),
    );
    rendererRef.current.sync(group.lines);
  }, [domOwned, group.lines, group.lines.length]);
  useLayoutEffect(() => {
    if (!domOwned || subscribeOutput === undefined) return undefined;
    const subscriber: LogOutputSubscriber = (lines) => rendererRef.current?.sync(lines);
    return subscribeOutput(group.id, subscriber);
  }, [domOwned, group.id, subscribeOutput]);

  return (
    <div aria-label={`${group.name} log output`} className="log-group__output" id={panelId} ref={hostRef} role="region" tabIndex={0}>
      {domOwned ? null : group.lines.length === 0
        ? <div className="log-group__empty">No output</div>
        : group.lines.map((line) => <LogLine key={line.key} line={line} />)}
    </div>
  );
}

function LogLine({ line }: { readonly line: TerminalLine }) {
  const id = logLineId(line);
  return <div className="log-line" data-channel={line.channel} id={id}><a aria-label={`Link to log line ${line.number}`} href={`#${id}`}>{line.number}</a><time dateTime={new Date(line.emittedAtMs).toISOString()}>{logTime(line.emittedAtMs)}</time><code>{line.spans.map((span, index) => <TerminalText key={`${line.key}:${index}`} span={span} />)}</code></div>;
}

function TerminalText({ span }: { readonly span: TerminalSpan }) {
  const content = <span className="terminal-text" style={terminalStyle(span)}>{span.text}</span>;
  return span.href === null ? content : <a className="terminal-link" href={span.href} rel="nofollow noreferrer" target="_blank">{content}</a>;
}

function createTerminalLine(document: Document, line: TerminalLine): HTMLElement {
  const element = document.createElement("div");
  const id = logLineId(line);
  element.className = "log-line";
  element.dataset.channel = line.channel;
  element.id = id;

  const link = document.createElement("a");
  link.ariaLabel = `Link to log line ${line.number}`;
  link.href = `#${id}`;
  link.textContent = line.number;
  element.append(link);

  const time = document.createElement("time");
  time.dateTime = new Date(line.emittedAtMs).toISOString();
  time.textContent = logTime(line.emittedAtMs);
  element.append(time);

  const code = document.createElement("code");
  for (const span of line.spans) {
    const text = document.createElement("span");
    text.className = "terminal-text";
    text.textContent = span.text;
    Object.assign(text.style, terminalStyle(span));
    if (span.href === null) {
      code.append(text);
    } else {
      const terminalLink = document.createElement("a");
      terminalLink.className = "terminal-link";
      terminalLink.href = span.href;
      terminalLink.rel = "nofollow noreferrer";
      terminalLink.target = "_blank";
      terminalLink.append(text);
      code.append(terminalLink);
    }
  }
  element.append(code);
  return element;
}

function logLineId(line: TerminalLine): string {
  return `log-line-${line.number.replaceAll(".", "-")}`;
}

function terminalStyle(span: TerminalSpan): CSSProperties {
  const style = span.style;
  const foreground = style.inverse ? style.background : style.foreground;
  const background = style.inverse ? style.foreground : style.background;
  return {
    ...(foreground === null ? style.inverse ? { color: "var(--log-canvas)" } : {} : { color: terminalColor(foreground) }),
    ...(background === null ? style.inverse ? { backgroundColor: "var(--log-fg)" } : {} : { backgroundColor: terminalColor(background) }),
    ...(style.bold ? { fontWeight: 700 } : {}),
    ...(style.dim ? { opacity: 0.68 } : {}),
    ...(style.italic ? { fontStyle: "italic" } : {}),
    ...(style.conceal ? { color: "transparent" } : {}),
    ...(style.strike || style.underline !== "none" || style.overline ? {
      textDecorationLine: [style.underline !== "none" ? "underline" : "", style.strike ? "line-through" : "", style.overline ? "overline" : ""].filter(Boolean).join(" "),
      ...(style.underline === "curly" ? { textDecorationStyle: "wavy" as const } : style.underline === "dotted" ? { textDecorationStyle: "dotted" as const } : style.underline === "dashed" ? { textDecorationStyle: "dashed" as const } : style.underline === "double" ? { textDecorationStyle: "double" as const } : {}),
      ...(style.underlineColor === null ? {} : { textDecorationColor: terminalColor(style.underlineColor) }),
    } : {}),
  };
}

function terminalColor(color: TerminalColor): string {
  if (color.kind === "rgb") return `rgb(${color.red} ${color.green} ${color.blue})`;
  if (color.index < 16) return ANSI_PALETTE[color.index] ?? "inherit";
  if (color.index < 232) {
    const index = color.index - 16;
    const levels = [0, 95, 135, 175, 215, 255] as const;
    return `rgb(${levels[Math.floor(index / 36)]} ${levels[Math.floor(index / 6) % 6]} ${levels[index % 6]})`;
  }
  const level = 8 + (color.index - 232) * 10;
  return `rgb(${level} ${level} ${level})`;
}

const ANSI_PALETTE = [
  "#484f58", "#ff7b72", "#3fb950", "#d29922", "#58a6ff", "#bc8cff", "#39c5cf", "#b1bac4",
  "#6e7681", "#ffa198", "#56d364", "#e3b341", "#79c0ff", "#d2a8ff", "#56d4dd", "#f0f6fc",
] as const;
