import type { ReactNode } from "react";
import type { JobLogPageModel } from "../models";
import type { LiveLogLineRecord } from "../logs/sse";
import type { JobLogsViewState, LogConnectionState } from "../viewModels/jobLogs";
import type { LogGroupView } from "../presenters/jobLogs";
import { ActionsLayout } from "../components/ActionsLayout";
import { Breadcrumbs } from "../components/Breadcrumbs";
import { RunNavigation } from "../components/RunNavigation";
import { Shell } from "../components/Shell";
import { StatusBadge } from "../components/StatusBadge";
import { durationCopy, startTimeCopy } from "../presentation/runPresentation";
import {
  logGroupDuration,
  logGroupPanelId,
  logGroupStatus,
  logTime,
} from "../presenters/jobLogs";

export interface JobLogPageViewProps {
  readonly logs: JobLogsViewState;
  readonly model: JobLogPageModel;
  readonly shellUtility?: ReactNode;
}

export function JobLogPageView({ logs, model, shellUtility }: JobLogPageViewProps) {
  const normalizedQuery = logs.query.trim().toLocaleLowerCase();
  return (
    <Shell shell={model.shell} repository={model.repository} utility={shellUtility}>
      <main className="layout-wide page">
        <ActionsLayout navigation={<RunNavigation jobs={model.jobs} jobsVisibility="full" pagination={model.navigationPagination} selectedJobId={model.job.id} summaryHref={model.run.href} />}>
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
                <span>Run attempt {model.run.attempt}</span><span>Job attempt {model.job.attempt}</span>
                <span>{model.job.startedAt === null ? startTimeCopy(model.job.status) : `Started ${model.job.startedAt.label}`}</span>
                {model.job.durationLabel === null ? null : <span>{durationCopy(model.job.status, model.job.durationLabel)}</span>}
              </div>
              <h1>{model.job.name}</h1><p><a href={model.run.href}>Run #{model.run.number}: {model.run.name}</a></p>
            </div>
          </header>
          <section className="log-viewer" aria-labelledby="job-logs-heading">
            <div className="log-toolbar">
              <div className="log-toolbar__title"><h2 id="job-logs-heading">Job logs</h2><StreamState available={logs.logToolsAvailable} state={logs.connection} running={logs.running} /></div>
              {model.logVisibility === "full" && logs.logToolsAvailable ? (
                <div className="log-toolbar__actions">
                  <label className="log-search"><span className="sr-only">Search job logs</span><input autoCapitalize="none" autoComplete="off" className="form-control form-control--compact" onChange={(event) => logs.onQueryChange(event.currentTarget.value)} placeholder="Search logs" spellCheck={false} type="search" value={logs.query} /></label>
                  <button className="button button--compact" onClick={logs.onToggleAll} type="button">{logs.canExpand ? "Expand all" : "Collapse all"}</button>
                  <button aria-pressed={logs.following} className="button button--compact" onClick={logs.onToggleFollowing} type="button">{logs.following ? "Following" : "Follow logs"}</button>
                </div>
              ) : null}
            </div>
            {model.notice === null ? null : <p className="log-notice" role="status">{model.notice}</p>}
            {logs.streamError === null ? null : <p className="log-stream-error" role="alert">{logs.streamError}</p>}
            {model.logVisibility === "restricted" ? (
              <div className="log-empty">Logs are unavailable or you do not have permission to view them.</div>
            ) : (
              <div aria-label={`${model.job.name} output`} className="log-groups" onScroll={logs.onViewerScroll} ref={logs.viewerRef} role="region" tabIndex={0}>
                {logs.visibleGroups.length === 0 ? (
                  <div className="log-empty">{normalizedQuery !== "" ? "No steps match your search." : logs.streamError !== null ? "Log output could not be loaded." : logs.running ? "Waiting for log output…" : "Logs are unavailable for this job."}</div>
                ) : logs.visibleGroups.map((group) => (
                  <LogGroupPanel expanded={logs.expanded.has(group.id) || normalizedQuery !== ""} group={group} key={group.id} onToggle={() => logs.onToggleGroup(group.id)} />
                ))}
              </div>
            )}
          </section>
        </ActionsLayout>
      </main>
    </Shell>
  );
}

function LogGroupPanel({ expanded, group, onToggle }: { readonly expanded: boolean; readonly group: LogGroupView; readonly onToggle: () => void }) {
  const panelId = logGroupPanelId(group.id);
  return (
    <article className="log-group" data-state={group.conclusion ?? "running"}>
      <button aria-controls={panelId} aria-expanded={expanded} className="log-group__summary" onClick={onToggle} type="button">
        <span aria-hidden="true" className="log-group__chevron">›</span><span aria-hidden="true" className="log-group__status" /><span className="sr-only">{logGroupStatus(group)}</span><span className="log-group__name">{group.name}</span><span className="log-group__duration">{logGroupDuration(group)}</span>
      </button>
      {expanded ? <div aria-label={`${group.name} log output`} className="log-group__output" id={panelId} role="region" tabIndex={0}>{group.lines.length === 0 ? <div className="log-group__empty">No output</div> : group.lines.map((line) => <LogLine key={`${line.sequence}.${line.fragment ?? 0}`} line={line} />)}</div> : null}
    </article>
  );
}

function LogLine({ line }: { readonly line: LiveLogLineRecord }) {
  const number = line.fragment === null ? line.sequence : `${line.sequence}.${line.fragment}`;
  const id = `log-line-${number.replace(".", "-")}`;
  return <div className="log-line" data-channel={line.channel} id={id}><a aria-label={`Link to log line ${number}`} href={`#${id}`}>{number}</a><time dateTime={new Date(line.emittedAtMs).toISOString()}>{logTime(line.emittedAtMs)}</time><code>{line.text}</code></div>;
}

function StreamState({ available, state, running }: { readonly available: boolean; readonly state: LogConnectionState; readonly running: boolean }) {
  const label = !available && !running ? "Unavailable" : state === "open" ? "Live" : state === "reconnecting" || state === "connecting" ? "Connecting" : state === "complete" ? "Complete" : state === "failed" ? "Failed" : running ? "Waiting" : "Loaded";
  return <span className="log-stream-state" data-state={state}><span aria-hidden="true" />{label}</span>;
}
