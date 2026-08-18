import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import type { JobLogPageModel } from "../models";
import type {
  LiveLogGroup,
  LiveLogGroupFinishedRecord,
  LiveLogLineRecord,
  LiveLogRecord,
} from "../logs/sse";
import { LiveLogController, type LiveLogControllerState } from "../logs/controller";
import { createSameOriginLiveLogAccessProvider } from "../logs/protocol";
import { ActionsLayout } from "../components/ActionsLayout";
import { Breadcrumbs } from "../components/Breadcrumbs";
import { RunNavigation } from "../components/RunNavigation";
import { Shell } from "../components/Shell";
import { StatusBadge } from "../components/StatusBadge";
import { durationCopy, startTimeCopy } from "../presentation/runPresentation";

export interface JobLogPageProps {
  readonly model: JobLogPageModel;
  readonly shellUtility?: ReactNode;
  /** Structured sample records used only by the standalone UI preview. */
  readonly initialRecords?: readonly LiveLogRecord[];
}

interface LogGroupView extends LiveLogGroup {
  readonly startedAtMs: number;
  readonly finishedAtMs: number | null;
  readonly conclusion: LiveLogGroupFinishedRecord["conclusion"] | null;
  readonly lines: LiveLogLineRecord[];
}

type ConnectionState = LiveLogControllerState["kind"] | "idle";

export function JobLogPage({ model, shellUtility, initialRecords = [] }: JobLogPageProps) {
  const initialStateRef = useRef<InitialLogViewState | null>(null);
  initialStateRef.current ??= replayRecords(initialRecords);
  const groupsRef = useRef(initialStateRef.current.groups);
  const [groups, setGroups] = useState<readonly LogGroupView[]>(initialStateRef.current.ordered);
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(initialStateRef.current.expanded);
  const [query, setQuery] = useState("");
  const [connection, setConnection] = useState<ConnectionState>("idle");
  const [following, setFollowing] = useState(true);
  const followingRef = useRef(true);
  const [streamError, setStreamError] = useState<string | null>(null);
  const viewerRef = useRef<HTMLDivElement>(null);
  const shouldScrollRef = useRef(false);

  useEffect(() => {
    if (model.live === null || model.logVisibility !== "full") return undefined;
    const controller = new LiveLogController({
      access: createSameOriginLiveLogAccessProvider({ endpoint: model.live.ticketHref }),
      onRecord: (record) => {
        shouldScrollRef.current = followingRef.current && isNearBottom(viewerRef.current);
        applyRecord(groupsRef.current, record);
        setGroups(orderedGroups(groupsRef.current));
        if (record.type === "group_started") {
          setExpanded((current) => new Set(current).add(record.group.id));
        } else if (record.type === "group_finished") {
          setExpanded((current) => {
            const next = new Set(current);
            if (record.conclusion === "success") next.delete(record.groupId);
            else next.add(record.groupId);
            return next;
          });
        }
      },
      onStateChange: (state) => setConnection(state.kind),
      onFailure: () => setStreamError(
        "The log stream could not be opened. Refresh the page to try again.",
      ),
    });
    const start = () => {
      void controller.start().catch(() =>
        setStreamError("The log stream could not be opened."),
      );
    };
    const visibilityChanged = () => {
      if (document.visibilityState === "visible") start();
      else controller.pause();
    };
    document.addEventListener("visibilitychange", visibilityChanged);
    visibilityChanged();
    return () => {
      document.removeEventListener("visibilitychange", visibilityChanged);
      controller.dispose();
    };
  }, [model.live, model.logVisibility]);

  useLayoutEffect(() => {
    if (shouldScrollRef.current) {
      viewerRef.current?.scrollTo({ top: viewerRef.current.scrollHeight });
      shouldScrollRef.current = false;
    }
  }, [groups]);

  const normalizedQuery = query.trim().toLocaleLowerCase();
  const visibleGroups = useMemo(
    () => filterGroups(groups, normalizedQuery),
    [groups, normalizedQuery],
  );
  const canExpand = visibleGroups.length === 0 || visibleGroups.some((group) => !expanded.has(group.id));
  const running = model.job.status.tone === "queued" || model.job.status.tone === "running";
  const logToolsAvailable = model.live !== null || groups.length > 0 || running;

  return (
    <Shell shell={model.shell} repository={model.repository} utility={shellUtility}>
      <main className="layout-wide page">
        <ActionsLayout navigation={
          <RunNavigation
            jobs={model.jobs}
            jobsVisibility="full"
            pagination={model.navigationPagination}
            selectedJobId={model.job.id}
            summaryHref={model.run.href}
          />
        }>
          <Breadcrumbs items={[
            { href: model.repository.runsHref, label: "Actions" },
            { href: model.run.workflowHref, label: model.run.workflowName },
            { href: model.run.href, label: `Run #${model.run.number}` },
            { href: null, label: model.job.name },
          ]} />

          <header className="page-heading page-heading--run log-page-heading">
            <div>
              <div className="heading-status">
                <StatusBadge status={model.job.status} />
                <span>Run attempt {model.run.attempt}</span>
                <span>Job attempt {model.job.attempt}</span>
                <span>{model.job.startedAt === null ? startTimeCopy(model.job.status) : `Started ${model.job.startedAt.label}`}</span>
                {model.job.durationLabel === null ? null : <span>{durationCopy(model.job.status, model.job.durationLabel)}</span>}
              </div>
              <h1>{model.job.name}</h1>
              <p><a href={model.run.href}>Run #{model.run.number}: {model.run.name}</a></p>
            </div>
          </header>

          <section className="log-viewer" aria-labelledby="job-logs-heading">
            <div className="log-toolbar">
              <div className="log-toolbar__title">
                <h2 id="job-logs-heading">Job logs</h2>
                <StreamState available={logToolsAvailable} state={connection} running={running} />
              </div>
              {model.logVisibility === "full" && logToolsAvailable ? (
                <div className="log-toolbar__actions">
                  <label className="log-search">
                    <span className="sr-only">Search job logs</span>
                    <input
                      autoCapitalize="none"
                      autoComplete="off"
                      className="form-control form-control--compact"
                      onChange={(event) => setQuery(event.currentTarget.value)}
                      placeholder="Search logs"
                      spellCheck={false}
                      type="search"
                      value={query}
                    />
                  </label>
                  <button className="button button--compact" onClick={() => setExpanded(canExpand ? new Set(visibleGroups.map((group) => group.id)) : new Set())} type="button">
                    {canExpand ? "Expand all" : "Collapse all"}
                  </button>
                  <button
                    aria-pressed={following}
                    className="button button--compact"
                    onClick={() => {
                      followingRef.current = !followingRef.current;
                      setFollowing(followingRef.current);
                      if (followingRef.current) {
                        viewerRef.current?.scrollTo({
                          top: viewerRef.current.scrollHeight,
                        });
                      }
                    }}
                    type="button"
                  >
                    {following ? "Following" : "Follow logs"}
                  </button>
                </div>
              ) : null}
            </div>

            {model.notice === null ? null : <p className="log-notice" role="status">{model.notice}</p>}
            {streamError === null ? null : <p className="log-stream-error" role="alert">{streamError}</p>}
            {model.logVisibility === "restricted" ? (
              <div className="log-empty">Logs are unavailable or you do not have permission to view them.</div>
            ) : (
              <div
                aria-label={`${model.job.name} output`}
                className="log-groups"
                onScroll={() => {
                  if (!isNearBottom(viewerRef.current)) {
                    followingRef.current = false;
                    setFollowing(false);
                  }
                }}
                ref={viewerRef}
                role="region"
                tabIndex={0}
              >
                {visibleGroups.length === 0 ? (
                  <div className="log-empty">
                    {normalizedQuery !== ""
                      ? "No steps match your search."
                      : streamError !== null
                        ? "Log output could not be loaded."
                      : running
                        ? "Waiting for log output…"
                        : "Logs are unavailable for this job."}
                  </div>
                ) : visibleGroups.map((group) => (
                  <LogGroupPanel
                    expanded={expanded.has(group.id) || normalizedQuery !== ""}
                    group={group}
                    key={group.id}
                    onToggle={() => setExpanded((current) => toggled(current, group.id))}
                    query={normalizedQuery}
                  />
                ))}
              </div>
            )}
          </section>
        </ActionsLayout>
      </main>
    </Shell>
  );
}

function LogGroupPanel({ expanded, group, onToggle, query }: {
  readonly expanded: boolean;
  readonly group: LogGroupView;
  readonly onToggle: () => void;
  readonly query: string;
}) {
  const lines = query === "" ? group.lines : group.lines.filter((line) => lineMatches(line, query));
  const panelId = groupPanelId(group.id);
  return (
    <article className="log-group" data-state={group.conclusion ?? "running"}>
      <button aria-controls={panelId} aria-expanded={expanded} className="log-group__summary" onClick={onToggle} type="button">
        <span aria-hidden="true" className="log-group__chevron">›</span>
        <span aria-hidden="true" className="log-group__status" />
        <span className="sr-only">{groupStatus(group)}</span>
        <span className="log-group__name">{group.name}</span>
        <span className="log-group__duration">{groupDuration(group)}</span>
      </button>
      {expanded ? (
        <div
          aria-label={`${group.name} log output`}
          className="log-group__output"
          id={panelId}
          role="region"
          tabIndex={0}
        >
          {lines.length === 0 ? <div className="log-group__empty">No output</div> : lines.map((line) => <LogLine key={`${line.sequence}.${line.fragment ?? 0}`} line={line} />)}
        </div>
      ) : null}
    </article>
  );
}

function LogLine({ line }: { readonly line: LiveLogLineRecord }) {
  const number = line.fragment === null ? line.sequence : `${line.sequence}.${line.fragment}`;
  const id = `log-line-${number.replace(".", "-")}`;
  return (
    <div className="log-line" data-channel={line.channel} id={id}>
      <a aria-label={`Link to log line ${number}`} href={`#${id}`}>{number}</a>
      <time dateTime={new Date(line.emittedAtMs).toISOString()}>{formatLogTime(line.emittedAtMs)}</time>
      <code>{line.text}</code>
    </div>
  );
}

function StreamState({ available, state, running }: { readonly available: boolean; readonly state: ConnectionState; readonly running: boolean }) {
  const label = !available && !running ? "Unavailable" : state === "open" ? "Live" : state === "reconnecting" || state === "connecting" ? "Connecting" : state === "complete" ? "Complete" : state === "failed" ? "Failed" : running ? "Waiting" : "Loaded";
  return <span className="log-stream-state" data-state={state}><span aria-hidden="true" />{label}</span>;
}

function applyRecord(groups: Map<string, LogGroupView>, record: LiveLogRecord): void {
  if (record.type === "group_started") {
    if (groups.has(record.group.id)) throw new Error("the log stream repeated a group");
    if (
      record.group.parentId !== null &&
      !groups.has(record.group.parentId)
    ) {
      throw new Error("the log stream referenced an unknown parent group");
    }
    groups.set(record.group.id, { ...record.group, startedAtMs: record.emittedAtMs, finishedAtMs: null, conclusion: null, lines: [] });
    return;
  }
  const groupId = record.groupId;
  const group = groups.get(groupId);
  if (group === undefined) throw new Error("the log stream referenced an unknown group");
  if (group.conclusion !== null) {
    throw new Error("the log stream referenced a finished group");
  }
  if (record.type === "line") {
    group.lines.push(record);
  } else {
    groups.set(groupId, { ...group, finishedAtMs: record.emittedAtMs, conclusion: record.conclusion });
  }
}

interface InitialLogViewState {
  readonly groups: Map<string, LogGroupView>;
  readonly ordered: readonly LogGroupView[];
  readonly expanded: ReadonlySet<string>;
}

function replayRecords(records: readonly LiveLogRecord[]): InitialLogViewState {
  const groups = new Map<string, LogGroupView>();
  for (const record of records) applyRecord(groups, record);
  return {
    groups,
    ordered: orderedGroups(groups),
    expanded: new Set(
      [...groups.values()]
        .filter((group) => group.conclusion !== "success")
        .map((group) => group.id),
    ),
  };
}

function orderedGroups(groups: ReadonlyMap<string, LogGroupView>): readonly LogGroupView[] {
  return [...groups.values()].sort((left, right) => left.ordinal - right.ordinal || left.id.localeCompare(right.id));
}

function filterGroups(groups: readonly LogGroupView[], query: string): readonly LogGroupView[] {
  if (query === "") return groups;
  return groups.filter((group) => group.name.toLocaleLowerCase().includes(query) || group.lines.some((line) => lineMatches(line, query)));
}

function lineMatches(line: LiveLogLineRecord, query: string): boolean {
  return line.text.toLocaleLowerCase().includes(query) || line.channel.includes(query) || line.sequence.includes(query);
}

function toggled(values: ReadonlySet<string>, id: string): ReadonlySet<string> {
  const next = new Set(values);
  if (next.has(id)) next.delete(id); else next.add(id);
  return next;
}

function isNearBottom(element: HTMLElement | null): boolean {
  return element === null || element.scrollHeight - element.scrollTop - element.clientHeight < 80;
}

function groupDuration(group: LogGroupView): string {
  if (group.finishedAtMs === null) return "Running";
  const milliseconds = Math.max(0, group.finishedAtMs - group.startedAtMs);
  return milliseconds < 1_000 ? `${milliseconds}ms` : `${(milliseconds / 1_000).toFixed(milliseconds < 10_000 ? 1 : 0)}s`;
}

function groupStatus(group: LogGroupView): string {
  if (group.conclusion === null) return "Running";
  if (group.conclusion === "timed_out") return "Timed out";
  return `${group.conclusion[0]?.toLocaleUpperCase() ?? ""}${group.conclusion.slice(1)}`;
}

function formatLogTime(milliseconds: number): string {
  return new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(milliseconds);
}

function groupPanelId(value: string): string {
  let encoded = "";
  for (let index = 0; index < value.length; index += 1) {
    encoded += value.charCodeAt(index).toString(16).padStart(2, "0");
  }
  return `log-group-${encoded}`;
}
