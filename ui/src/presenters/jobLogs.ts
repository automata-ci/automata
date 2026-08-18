import type {
  LiveLogGroup,
  LiveLogGroupFinishedRecord,
  LiveLogLineRecord,
  LiveLogRecord,
} from "../logs/sse";

export interface LogGroupView extends LiveLogGroup {
  readonly startedAtMs: number;
  readonly finishedAtMs: number | null;
  readonly conclusion: LiveLogGroupFinishedRecord["conclusion"] | null;
  readonly lines: readonly LiveLogLineRecord[];
}

export interface InitialLogViewState {
  readonly expanded: ReadonlySet<string>;
  readonly groups: Map<string, LogGroupView>;
  readonly ordered: readonly LogGroupView[];
}

export function replayLogRecords(records: readonly LiveLogRecord[]): InitialLogViewState {
  const groups = new Map<string, LogGroupView>();
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
  groups: Map<string, LogGroupView>,
  record: LiveLogRecord,
): void {
  if (record.type === "group_started") {
    if (groups.has(record.group.id)) throw new Error("the log stream repeated a group");
    if (record.group.parentId !== null && !groups.has(record.group.parentId)) {
      throw new Error("the log stream referenced an unknown parent group");
    }
    groups.set(record.group.id, {
      ...record.group,
      startedAtMs: record.emittedAtMs,
      finishedAtMs: null,
      conclusion: null,
      lines: [],
    });
    return;
  }
  const group = groups.get(record.groupId);
  if (group === undefined) throw new Error("the log stream referenced an unknown group");
  if (group.conclusion !== null) throw new Error("the log stream referenced a finished group");
  if (record.type === "line") {
    groups.set(record.groupId, { ...group, lines: [...group.lines, record] });
  } else {
    groups.set(record.groupId, {
      ...group,
      finishedAtMs: record.emittedAtMs,
      conclusion: record.conclusion,
    });
  }
}

export function orderedLogGroups(
  groups: ReadonlyMap<string, LogGroupView>,
): readonly LogGroupView[] {
  return [...groups.values()].sort(
    (left, right) => left.ordinal - right.ordinal || left.id.localeCompare(right.id),
  );
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

function logLineMatches(line: LiveLogLineRecord, query: string): boolean {
  return line.text.toLocaleLowerCase().includes(query) ||
    line.channel.includes(query) ||
    line.sequence.includes(query);
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
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(milliseconds);
}

export function logGroupPanelId(value: string): string {
  let encoded = "";
  for (let index = 0; index < value.length; index += 1) {
    encoded += value.charCodeAt(index).toString(16).padStart(2, "0");
  }
  return `log-group-${encoded}`;
}
