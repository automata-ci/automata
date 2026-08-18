import type {
  LiveLogChannel,
  LiveLogGroup,
  LiveLogGroupFinishedRecord,
  LiveLogRecord,
} from "../logs/sse";
import { TerminalTranscript, type TerminalLine } from "../logs/terminal";

export interface LogGroupView extends LiveLogGroup {
  readonly startedAtMs: number;
  readonly finishedAtMs: number | null;
  readonly conclusion: LiveLogGroupFinishedRecord["conclusion"] | null;
  readonly lines: readonly TerminalLine[];
}

interface LogGroupState extends LogGroupView {
  readonly transcripts: Readonly<Record<LiveLogChannel, TerminalTranscript>>;
  completeLines: TerminalLine[];
}

export interface InitialLogViewState {
  readonly expanded: ReadonlySet<string>;
  readonly groups: Map<string, LogGroupState>;
  readonly ordered: readonly LogGroupView[];
}

export function replayLogRecords(records: readonly LiveLogRecord[]): InitialLogViewState {
  const groups = new Map<string, LogGroupState>();
  for (const record of records) applyLogRecord(groups, record);
  return {
    groups,
    ordered: orderedLogGroups(groups),
    expanded: new Set(
      [...groups.values()]
        .filter((group) => group.conclusion !== "success")
        .map((group) => group.id),
    ),
  };
}

export function applyLogRecord(
  groups: Map<string, LogGroupState>,
  record: LiveLogRecord,
): void {
  if (record.type === "group_started") {
    if (groups.has(record.group.id)) throw new Error("the log stream repeated a group");
    if (record.group.parentId !== null && !groups.has(record.group.parentId)) {
      throw new Error("the log stream referenced an unknown parent group");
    }
    const completeLines: TerminalLine[] = [];
    groups.set(record.group.id, {
      ...record.group,
      startedAtMs: record.emittedAtMs,
      finishedAtMs: null,
      conclusion: null,
      lines: completeLines,
      transcripts: {
        stdout: new TerminalTranscript(),
        stderr: new TerminalTranscript(),
        system: new TerminalTranscript(),
      },
      completeLines,
    });
    return;
  }
  const group = groups.get(record.groupId);
  if (group === undefined) throw new Error("the log stream referenced an unknown group");
  if (group.conclusion !== null) throw new Error("the log stream referenced a finished group");
  if (record.type === "output") {
    group.completeLines = insertCompletedLines(group.completeLines, group.transcripts[record.channel].push(record));
    groups.set(record.groupId, {
      ...group,
      lines: terminalLines(group.transcripts, group.completeLines),
    });
  } else {
    group.completeLines = insertCompletedLines(group.completeLines, [
      ...group.transcripts.stdout.finish(),
      ...group.transcripts.stderr.finish(),
      ...group.transcripts.system.finish(),
    ]);
    groups.set(record.groupId, {
      ...group,
      finishedAtMs: record.emittedAtMs,
      conclusion: record.conclusion,
      lines: group.completeLines,
    });
  }
}

export function orderedLogGroups(
  groups: ReadonlyMap<string, LogGroupView>,
): readonly LogGroupView[] {
  return [...groups.values()].sort(
    (left, right) => left.ordinal - right.ordinal || left.id.localeCompare(right.id),
  ).map((group) => {
    if (!isLogGroupState(group)) return group;
    const { transcripts: _transcripts, completeLines: _completeLines, ...view } = group;
    return view;
  });
}

function isLogGroupState(group: LogGroupView): group is LogGroupState {
  return "transcripts" in group && "completeLines" in group;
}

function terminalLines(
  transcripts: Readonly<Record<LiveLogChannel, TerminalTranscript>>,
  completeLines: readonly TerminalLine[],
): readonly TerminalLine[] {
  const pending = [
    transcripts.stdout.currentLine(),
    transcripts.stderr.currentLine(),
    transcripts.system.currentLine(),
  ].filter((line): line is TerminalLine => line !== null);
  if (pending.length === 0) return completeLines;
  return [...completeLines, ...pending].sort((left, right) => compareSequence(left.sourceSequence, right.sourceSequence));
}

function insertCompletedLines(target: TerminalLine[], additions: readonly TerminalLine[]): TerminalLine[] {
  for (const line of additions) {
    const tail = target[target.length - 1];
    if (tail === undefined || compareSequence(tail.sourceSequence, line.sourceSequence) <= 0) {
      target.push(line);
      continue;
    }
    let lower = 0;
    let upper = target.length;
    while (lower < upper) {
      const middle = (lower + upper) >>> 1;
      if (compareSequence(target[middle]?.sourceSequence ?? "0", line.sourceSequence) <= 0) lower = middle + 1;
      else upper = middle;
    }
    const reordered = [...target];
    reordered.splice(lower, 0, line);
    target = reordered;
  }
  return target;
}

function compareSequence(left: string, right: string): number {
  if (left.length !== right.length) return left.length - right.length;
  return left === right ? 0 : left < right ? -1 : 1;
}

export function projectVisibleLogGroups(
  groups: readonly LogGroupView[],
  query: string,
): readonly LogGroupView[] {
  const normalized = query.trim().toLocaleLowerCase();
  if (normalized === "") return groups;
  return groups
    .filter((group) =>
      group.name.toLocaleLowerCase().includes(normalized) ||
      group.lines.some((line) => logLineMatches(line, normalized)),
    )
    .map((group) => ({
      ...group,
      lines: group.lines.filter((line) => logLineMatches(line, normalized)),
    }));
}

function logLineMatches(line: TerminalLine, query: string): boolean {
  return line.text.toLocaleLowerCase().includes(query) ||
    line.channel.includes(query) ||
    line.number.includes(query);
}

export function toggleSet(values: ReadonlySet<string>, id: string): ReadonlySet<string> {
  const next = new Set(values);
  if (next.has(id)) next.delete(id); else next.add(id);
  return next;
}

export function isNearLogBottom(element: HTMLElement | null): boolean {
  return element === null || element.scrollHeight - element.scrollTop - element.clientHeight < 80;
}

export function logGroupDuration(group: LogGroupView): string {
  if (group.finishedAtMs === null) return "Running";
  const milliseconds = Math.max(0, group.finishedAtMs - group.startedAtMs);
  return milliseconds < 1_000
    ? `${milliseconds}ms`
    : `${(milliseconds / 1_000).toFixed(milliseconds < 10_000 ? 1 : 0)}s`;
}

export function logGroupStatus(group: LogGroupView): string {
  if (group.conclusion === null) return "Running";
  if (group.conclusion === "timed_out") return "Timed out";
  return `${group.conclusion[0]?.toLocaleUpperCase() ?? ""}${group.conclusion.slice(1)}`;
}

export function logTime(milliseconds: number): string {
  logTimeFormatter ??= new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
  return logTimeFormatter.format(milliseconds);
}

let logTimeFormatter: Intl.DateTimeFormat | undefined;

export function logGroupPanelId(value: string): string {
  let encoded = "";
  for (let index = 0; index < value.length; index += 1) {
    encoded += value.charCodeAt(index).toString(16).padStart(2, "0");
  }
  return `log-group-${encoded}`;
}
