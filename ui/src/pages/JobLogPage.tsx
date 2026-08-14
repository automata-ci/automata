import { useEffect, useMemo, useState } from "react";
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
import { parseRenderRequest } from "../serialization";
import { RENDER_REQUEST_LIMITS } from "../validation/limits";

export interface JobLogPageProps {
  readonly model: JobLogPageModel;
  readonly shellUtility?: ReactNode;
}

const LOG_OUTPUT_ID = "job-log-output";
const LOG_RESULT_COUNT_ID = "job-log-result-count";

export function JobLogPage({ model, shellUtility }: JobLogPageProps) {
  const [liveModel, setLiveModel] = useState(model);
  const [query, setQuery] = useState(model.search.query);
  const normalizedQuery = normalizeQuery(query);
  const visibleLines = useMemo(
    () => filterLogLines(liveModel.lines, normalizedQuery),
    [liveModel.lines, normalizedQuery],
  );
  const resultLabel =
    normalizedQuery.length === 0
      ? liveModel.pagination.label
      : matchingLineCount(visibleLines.length);
  const canRefresh =
    liveModel.job.status.tone === "queued" ||
    liveModel.job.status.tone === "running";
  const navigationQuery = isValidLogQuery(query)
    ? query.trim()
    : liveModel.search.query;
  const refreshHref = logQueryHref(
    liveModel.search.action,
    navigationQuery,
    liveModel.pagination.currentCursor,
  );
  useEffect(() => {
    if (!canRefresh) {
      return undefined;
    }
    const controller = new AbortController();
    let timeout: number | undefined;
    let etag: string | null = null;
    let delay = 2_000;
    const snapshotHref = logQueryHref(
      `${model.job.href}/snapshot`,
      model.search.query,
      model.pagination.currentCursor,
    );
    const schedule = (nextDelay = delay) => {
      window.clearTimeout(timeout);
      if (document.visibilityState === "visible") {
        timeout = window.setTimeout(async () => {
          try {
            const headers = new Headers();
            headers.set("Accept", "application/json");
            if (etag !== null) {
              headers.set("If-None-Match", etag);
            }
            const response = await fetch(snapshotHref, {
              credentials: "same-origin",
              headers,
              signal: controller.signal,
            });
            if (response.status === 304) {
              delay = 2_000;
              schedule();
              return;
            }
            if (!response.ok) {
              throw new Error(`job snapshot returned ${response.status}`);
            }
            const next = parseRenderRequest(await response.text());
            if (
              next.page.kind !== "job-log" ||
              next.page.job.id !== model.job.id ||
              next.page.job.href !== model.job.href ||
              next.page.run.href !== model.run.href
            ) {
              throw new Error("job snapshot changed request scope");
            }
            etag = response.headers.get("ETag");
            delay = 2_000;
            setLiveModel(next.page);
            if (
              next.page.job.status.tone === "queued" ||
              next.page.job.status.tone === "running"
            ) {
              schedule();
            }
          } catch (error) {
            if (controller.signal.aborted) {
              return;
            }
            delay = Math.min(delay * 2, 30_000);
            schedule(delay);
          }
        }, nextDelay);
      }
    };
    const visibilityChanged = () => {
      window.clearTimeout(timeout);
      if (document.visibilityState === "visible") {
        schedule(0);
      }
    };
    document.addEventListener("visibilitychange", visibilityChanged);
    schedule();
    return () => {
      document.removeEventListener("visibilitychange", visibilityChanged);
      controller.abort();
      window.clearTimeout(timeout);
    };
  }, [
    canRefresh,
    model.job.href,
    model.job.id,
    model.pagination.currentCursor,
    model.run.href,
    model.search.query,
  ]);
  const clearHref = logQueryHref(
    liveModel.search.clearHref,
    "",
    liveModel.pagination.currentCursor,
  );
  const pagination = useMemo(
    () => ({
      label: liveModel.pagination.label,
      previousHref: cursorHref(
        liveModel.search.action,
        navigationQuery,
        liveModel.pagination.previousCursor,
      ),
      nextHref: cursorHref(
        liveModel.search.action,
        navigationQuery,
        liveModel.pagination.nextCursor,
      ),
    }),
    [liveModel.pagination, liveModel.search.action, navigationQuery],
  );

  return (
    <Shell
      shell={liveModel.shell}
      repository={liveModel.repository}
      utility={shellUtility}
    >
      <main className="layout-wide page">
        <ActionsLayout
          navigation={
            <RunNavigation
              jobs={liveModel.jobs}
              jobsVisibility="full"
              pagination={liveModel.navigationPagination}
              selectedJobId={liveModel.job.id}
              summaryHref={liveModel.run.href}
            />
          }
        >
          <Breadcrumbs
            items={[
              { href: liveModel.repository.runsHref, label: "Actions" },
              {
                href: liveModel.run.workflowHref,
                label: liveModel.run.workflowName,
              },
              {
                href: liveModel.run.href,
                label: `Run #${liveModel.run.number}`,
              },
              { href: null, label: liveModel.job.name },
            ]}
          />

          <header className="page-heading page-heading--run log-page-heading">
            <div>
              <div className="heading-status">
                <StatusBadge status={liveModel.job.status} />
                <span>Run attempt {liveModel.run.attempt}</span>
                <span>Job attempt {liveModel.job.attempt}</span>
                {liveModel.job.startedAt === null ? (
                  <span>{startTimeCopy(liveModel.job.status)}</span>
                ) : (
                  <span>
                    Started{" "}
                    <time dateTime={liveModel.job.startedAt.iso}>
                      {liveModel.job.startedAt.label}
                    </time>
                  </span>
                )}
                {liveModel.job.status.tone === "queued" &&
                liveModel.job.durationLabel === null ? null : (
                  <span>
                    {durationCopy(
                      liveModel.job.status,
                      liveModel.job.durationLabel,
                    )}
                  </span>
                )}
              </div>
              <h1>{liveModel.job.name}</h1>
              <p>
                <a href={liveModel.run.href}>
                  Run #{liveModel.run.number}: {liveModel.run.name}
                </a>
                {liveModel.job.runnerLabel === null ? null : (
                  <>
                    <MetadataSeparator />
                    {liveModel.job.runnerLabel}
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
              {liveModel.logVisibility === "full" ? (
                <form
                  action={liveModel.search.action}
                  aria-label="Search job logs"
                  className="log-search-form"
                  method="get"
                  role="search"
                >
                  {liveModel.pagination.currentCursor === null ? null : (
                    <input
                      name="cursor"
                      type="hidden"
                      value={liveModel.pagination.currentCursor}
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
              ) : null}
            </div>

            {liveModel.notice === null ? null : (
              <p className="log-notice" role="status">
                {liveModel.notice}
              </p>
            )}

            {liveModel.logVisibility === "restricted" ? (
              <p className="log-output__empty" role="status">
                Logs are unavailable or you do not have permission to view them.
              </p>
            ) : (
              <div
                aria-label={`${liveModel.job.name} output`}
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
            )}

            {liveModel.logVisibility === "full" ? (
              <Pagination
                label="Job log pages"
                pagination={pagination}
                variant="log"
              />
            ) : null}
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
