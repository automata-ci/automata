import type {
  PaginationModel,
  ResultCollectionVisibility,
  StatusModel,
} from "../models";
import { Icon } from "./Icon";
import { Pagination } from "./Pagination";
import { StatusBadge } from "./StatusBadge";

export interface RunNavigationJob {
  readonly id: string;
  readonly href: string | null;
  readonly name: string;
  readonly status: StatusModel;
}

export interface RunNavigationProps {
  readonly jobs: readonly RunNavigationJob[];
  readonly jobsVisibility: ResultCollectionVisibility;
  readonly pagination: PaginationModel | null;
  readonly selectedJobId: string | null;
  readonly summaryHref: string | null;
}

export function RunNavigation({
  jobs,
  jobsVisibility,
  pagination,
  selectedJobId,
  summaryHref,
}: RunNavigationProps) {
  const selectedJob = jobs.find((job) => job.id === selectedJobId);
  const currentLabel = selectedJob?.name ?? "Summary";

  return (
    <div className="run-navigation">
      <div className="run-navigation__desktop">
        <RunNavigationContents
          jobs={jobs}
          jobsVisibility={jobsVisibility}
          pagination={pagination}
          selectedJobId={selectedJobId}
          summaryHref={summaryHref}
        />
      </div>
      <details className="run-navigation__mobile">
        <summary className="run-navigation__disclosure-summary">
          <span className="run-navigation__disclosure-label">Workflow run</span>
          <span className="run-navigation__disclosure-current">
            {selectedJob === undefined ? null : (
              <StatusBadge labelMode="accessible" status={selectedJob.status} />
            )}
            <span>{currentLabel}</span>
          </span>
          <Icon className="run-navigation__disclosure-icon" name="chevron-right" />
        </summary>
        <div className="run-navigation__menu">
          <RunNavigationContents
            jobs={jobs}
            jobsVisibility={jobsVisibility}
            pagination={pagination}
            selectedJobId={selectedJobId}
            summaryHref={summaryHref}
          />
        </div>
      </details>
    </div>
  );
}

function RunNavigationContents({
  jobs,
  jobsVisibility,
  pagination,
  selectedJobId,
  summaryHref,
}: RunNavigationProps) {
  const summary = (
    <>
      <Icon name="overview" />
      <span>Summary</span>
    </>
  );

  return (
    <>
      <nav aria-label="Run navigation">
        <div className="run-navigation__title">
          <Icon name="actions" size={18} />
          <span>Workflow run</span>
        </div>
        <div className="run-navigation__summary-link">
          {summaryHref === null ? (
            <span aria-current="page">{summary}</span>
          ) : (
            <a href={summaryHref}>{summary}</a>
          )}
        </div>
        <div className="run-navigation__section">
          <span className="run-navigation__section-heading">Jobs</span>
          {jobs.length === 0 ? (
            <p>
              {jobsVisibility === "restricted"
                ? "Jobs are unavailable with your current access."
                : "No jobs are available."}
            </p>
          ) : (
            <div className="run-navigation__jobs">
              {jobs.map((job) => {
                const contents = (
                  <>
                    <StatusBadge labelMode="accessible" status={job.status} />
                    <span>
                      {job.name}
                      {job.href === null ? " — logs unavailable" : null}
                    </span>
                  </>
                );
                return job.href === null ? (
                  <span
                    aria-disabled="true"
                    className="run-navigation__job"
                    key={job.id}
                  >
                    {contents}
                  </span>
                ) : (
                  <a
                    aria-current={job.id === selectedJobId ? "page" : undefined}
                    className="run-navigation__job"
                    href={job.href}
                    key={job.id}
                  >
                    {contents}
                  </a>
                );
              })}
            </div>
          )}
        </div>
      </nav>
      {pagination === null ? null : (
        <Pagination label="Run job pages" pagination={pagination} />
      )}
    </>
  );
}
