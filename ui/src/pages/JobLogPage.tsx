import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import type { JobLogLineModel, JobLogPageModel } from "../models";
import { ActionsLayout } from "../components/ActionsLayout";
import { Breadcrumbs } from "../components/Breadcrumbs";
import { Icon } from "../components/Icon";
import { MetadataSeparator } from "../components/MetadataSeparator";
import { Pagination } from "../components/Pagination";
import { RunNavigation } from "../components/RunNavigation";
import { Shell } from "../components/Shell";
import { StatusBadge } from "../components/StatusBadge";
import {
  enforceLogQueryValidity,
  isValidLogQuery,
} from "../components/textInputConstraints";
import { durationCopy, startTimeCopy } from "../presentation/runPresentation";
import { encodeQueryComponent } from "../queryEncoding";
import { RENDER_REQUEST_LIMITS } from "../validation/limits";

export interface JobLogPageProps {
  readonly model: JobLogPageModel;
  readonly shellUtility?: ReactNode;
}

const LOG_OUTPUT_ID = "job-log-output";
const LOG_RESULT_COUNT_ID = "job-log-result-count";

export function JobLogPage({ model, shellUtility }: JobLogPageProps) {
  const [query, setQuery] = useState(model.search.query);
  const normalizedQuery = normalizeQuery(query);
  const visibleLines = useMemo(
    () => filterLogLines(model.lines, normalizedQuery),
    [model.lines, normalizedQuery],
  );
  const resultLabel =
    normalizedQuery.length === 0
      ? model.pagination.label
      : matchingLineCount(visibleLines.length);
  const canRefresh =
    model.job.status.tone === "queued" || model.job.status.tone === "running";
  const navigationQuery = isValidLogQuery(query)
    ? query.trim()
    : model.search.query;
  const refreshHref = logQueryHref(
    model.search.action,
    navigationQuery,
    model.pagination.currentCursor,
  );
  const clearHref = logQueryHref(
    model.search.clearHref,
    "",
    model.pagination.currentCursor,
  );
  const pagination = useMemo(
    () => ({
      label: model.pagination.label,
      previousHref: cursorHref(
        model.search.action,
        navigationQuery,
        model.pagination.previousCursor,
      ),
      nextHref: cursorHref(
        model.search.action,
        navigationQuery,
        model.pagination.nextCursor,
      ),
    }),
    [model.pagination, model.search.action, navigationQuery],
  );

  return (
    <Shell
      shell={model.shell}
      repository={model.repository}
      utility={shellUtility}
    >
      <main className="layout-wide page">
        <ActionsLayout
          navigation={
            <RunNavigation
              jobs={model.jobs}
              jobsVisibility="full"
              pagination={model.navigationPagination}
              selectedJobId={model.job.id}
              summaryHref={model.run.href}
            />
          }
        >
          <Breadcrumbs
            items={[
              { href: model.repository.runsHref, label: "Actions" },
              { href: model.run.workflowHref, label: model.run.workflowName },
              { href: model.run.href, label: `Run #${model.run.number}` },
              { href: null, label: model.job.name },
            ]}
          />

          <header className="page-heading page-heading--run log-page-heading">
            <div>
              <div className="heading-status">
                <StatusBadge status={model.job.status} />
                <span>Run attempt {model.run.attempt}</span>
                <span>Job attempt {model.job.attempt}</span>
                {model.job.startedAt === null ? (
                  <span>{startTimeCopy(model.job.status)}</span>
                ) : (
                  <span>
                    Started{" "}
                    <time dateTime={model.job.startedAt.iso}>
                      {model.job.startedAt.label}
                    </time>
                  </span>
                )}
                {model.job.status.tone === "queued" &&
                model.job.durationLabel === null ? null : (
                  <span>
                    {durationCopy(model.job.status, model.job.durationLabel)}
                  </span>
                )}
              </div>
              <h1>{model.job.name}</h1>
              <p>
                <a href={model.run.href}>
                  Run #{model.run.number}: {model.run.name}
                </a>
                {model.job.runnerLabel === null ? null : (
                  <>
                    <MetadataSeparator />
                    {model.job.runnerLabel}
                  </>
                )}
              </p>
            </div>
            {canRefresh ? (
              <a className="button" href={refreshHref}>
                Refresh
              </a>
            ) : null}
          </header>

          <section
            className="panel log-viewer"
            aria-labelledby="job-logs-heading"
          >
            <div className="log-toolbar">
              <div>
                <h2 id="job-logs-heading">Job logs</h2>
                <span aria-live="polite" id={LOG_RESULT_COUNT_ID}>
                  {resultLabel}
                </span>
              </div>
              <form
                action={model.search.action}
                aria-label="Search job logs"
                className="log-search-form"
                method="get"
                role="search"
              >
                {model.pagination.currentCursor === null ? null : (
                  <input
                    name="cursor"
                    type="hidden"
                    value={model.pagination.currentCursor}
                  />
                )}
                <div className="filter-search log-search">
                  <Icon name="search" />
                  <label className="sr-only" htmlFor="log-search">
                    Search job logs
                  </label>
                  <input
                    autoCapitalize="none"
                    autoComplete="off"
                    autoCorrect="off"
                    aria-controls={LOG_OUTPUT_ID}
                    aria-describedby={LOG_RESULT_COUNT_ID}
                    id="log-search"
                    maxLength={RENDER_REQUEST_LIMITS.shortTextLength}
                    name="q"
                    onChange={(event) => setQuery(event.currentTarget.value)}
                    onInput={(event) =>
                      enforceLogQueryValidity(event.currentTarget)
                    }
                    placeholder="Search logs"
                    spellCheck={false}
                    type="search"
                    value={query}
                  />
                </div>
                <button className="button" type="submit">
                  Search
                </button>
                {query.trim().length === 0 ? null : (
                  <a className="text-link" href={clearHref}>
                    Clear search
                  </a>
                )}
              </form>
            </div>

            {model.notice === null ? null : (
              <p className="log-notice" role="status">
                {model.notice}
              </p>
            )}

            <div
              aria-label={`${model.job.name} output`}
              className="log-output"
              id={LOG_OUTPUT_ID}
              role="region"
              tabIndex={0}
            >
              {visibleLines.length === 0 ? (
                <p className="log-output__empty">
                  {normalizedQuery.length === 0
                    ? "No log lines are available on this page."
                    : "No log lines on this page match your search."}
                </p>
              ) : (
                visibleLines.map((line) => (
                  <LogLine key={line.id} line={line} />
                ))
              )}
            </div>

            <Pagination
              label="Job log pages"
              pagination={pagination}
              variant="log"
            />
          </section>
        </ActionsLayout>
      </main>
    </Shell>
  );
}

function LogLine({ line }: { readonly line: JobLogLineModel }) {
  const domId = logLineDomId(line.id);

  return (
    <div className="log-line" data-channel={line.channel} id={domId}>
      <a aria-label={`Link to log line ${line.number}`} href={`#${domId}`}>
        {line.number}
      </a>
      <time dateTime={line.timestamp.iso}>{line.timestamp.label}</time>
      <span className="log-line__channel">{line.channel}</span>
      <code>{line.text}</code>
    </div>
  );
}

function normalizeQuery(query: string): string {
  return query.trim().toLowerCase();
}

function filterLogLines(
  lines: readonly JobLogLineModel[],
  normalizedQuery: string,
): readonly JobLogLineModel[] {
  return normalizedQuery.length === 0
    ? lines
    : lines.filter((line) => matchesQuery(line, normalizedQuery));
}

function matchesQuery(line: JobLogLineModel, normalizedQuery: string): boolean {
  return [
    line.number,
    line.timestamp.iso,
    line.timestamp.label,
    line.channel,
    line.text,
  ].some((value) =>
    value.toLowerCase().includes(normalizedQuery),
  );
}

function matchingLineCount(count: number): string {
  return `${count} matching ${count === 1 ? "line" : "lines"} on this page`;
}

function cursorHref(
  action: string,
  query: string,
  cursor: string | null,
): string | null {
  if (cursor === null) {
    return null;
  }
  return logQueryHref(action, query, cursor);
}

function logQueryHref(
  action: string,
  query: string,
  cursor: string | null,
): string {
  const parameters: string[] = [];
  if (query.length > 0) {
    parameters.push(`q=${encodeQueryComponent(query)}`);
  }
  if (cursor !== null) {
    parameters.push(`cursor=${encodeQueryComponent(cursor)}`);
  }
  if (parameters.length === 0) {
    return action;
  }
  const separator = action.includes("?") ? "&" : "?";
  return `${action}${separator}${parameters.join("&")}`;
}

/** Keep host identities out of the document-wide ID namespace. */
function logLineDomId(id: string): string {
  return `automata-log-line-${id}`;
}
