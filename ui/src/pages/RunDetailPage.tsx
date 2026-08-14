import { useState, type ReactNode } from "react";
import type {
  ArtifactModel,
  JobModel,
  ResultCollectionModel,
  ResultCollectionVisibility,
  RunDetailModel,
  RunDetailPageModel,
  RunRerunControlsModel,
  StatusModel,
} from "../models";
import { ActionsLayout } from "../components/ActionsLayout";
import { Breadcrumbs } from "../components/Breadcrumbs";
import { CommitLink } from "../components/CommitLink";
import { EmptyState } from "../components/EmptyState";
import { Icon } from "../components/Icon";
import { MetadataSeparator } from "../components/MetadataSeparator";
import { Pagination } from "../components/Pagination";
import { RunNavigation } from "../components/RunNavigation";
import { Shell } from "../components/Shell";
import {
  SourceRefLink,
  sourceRefLabel,
} from "../components/SourceRefLink";
import { StatusBadge } from "../components/StatusBadge";
import {
  durationCopy,
  emptyArtifactsCopy,
  emptyJobsCopy,
  formatEventName,
} from "../presentation/runPresentation";

export interface RunDetailPageProps {
  readonly model: RunDetailPageModel;
  readonly shellUtility?: ReactNode;
}

export function RunDetailPage({ model, shellUtility }: RunDetailPageProps) {
  const { run } = model;
  const jobs = model.jobs.items;

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
              jobs={jobs}
              jobsVisibility={model.jobs.visibility}
              pagination={null}
              selectedJobId={null}
              summaryHref={null}
            />
          }
        >
          <Breadcrumbs
            items={[
              { href: model.repository.runsHref, label: "Actions" },
              { href: run.workflowHref, label: run.workflowName },
              { href: null, label: `Run #${run.number}` },
            ]}
          />

          <header className="page-heading page-heading--run">
            <div>
              <div className="heading-status">
                <StatusBadge status={run.status} />
                <span>Attempt {run.attempt}</span>
              </div>
              <h1>{run.name}</h1>
              <p>
                {run.actor === null ? (
                  <>Triggered via {formatEventName(run.event)}</>
                ) : (
                  <>
                    Triggered by <strong>{run.actor}</strong> via{" "}
                    {formatEventName(run.event)}
                  </>
                )}
              </p>
            </div>
            {model.rerun === null ? null : (
              <RunRerunControls
                controls={model.rerun}
                runsHref={model.repository.runsHref}
              />
            )}
          </header>

          <RunSummary run={run} />
          <JobsSection
            collection={model.jobs}
            pagination={model.jobPagination}
            runStatus={run.status}
          />
          <ArtifactsSection
            collection={model.artifacts}
            runStatus={run.status}
          />
        </ActionsLayout>
      </main>
    </Shell>
  );
}

function RunRerunControls({
  controls,
  runsHref,
}: {
  readonly controls: RunRerunControlsModel;
  readonly runsHref: string;
}) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function rerun(mode: "entire_workflow" | "failed_jobs_and_dependents") {
    if (pending) return;
    setPending(true);
    setError(null);
    try {
      const response = await fetch(controls.endpoint, {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "content-type": "application/json",
          "x-automata-csrf-token": controls.csrfToken,
        },
        body: JSON.stringify({
          operation_id: crypto.randomUUID(),
          selection: { mode },
        }),
      });
      if (!response.ok) throw new Error("rerun rejected");
      const document: unknown = await response.json();
      if (
        typeof document !== "object" ||
        document === null ||
        !("run_id" in document) ||
        typeof document.run_id !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
          document.run_id,
        )
      ) {
        throw new Error("invalid rerun response");
      }
      window.location.assign(`${runsHref}/runs/${document.run_id}`);
    } catch {
      setPending(false);
      setError("The rerun could not be started. Refresh and try again.");
    }
  }

  return (
    <div aria-label="Rerun controls">
      <button
        className="button button--primary"
        disabled={pending}
        onClick={() => void rerun("entire_workflow")}
        type="button"
      >
        {pending ? "Starting rerun…" : "Re-run all jobs"}
      </button>
      {controls.failedJobsAvailable ? (
        <button
          className="button button--quiet"
          disabled={pending}
          onClick={() => void rerun("failed_jobs_and_dependents")}
          type="button"
        >
          Re-run failed jobs
        </button>
      ) : null}
      {error === null ? null : <p role="alert">{error}</p>}
    </div>
  );
}

function RunSummary({ run }: { readonly run: RunDetailModel }) {
  return (
    <section className="panel run-overview" aria-labelledby="summary-heading">
      <div className="panel__heading">
        <h2 id="summary-heading">Run summary</h2>
        <span>#{run.number}</span>
      </div>
      <dl className="run-summary">
        {run.sourceRef === null ? null : (
          <div>
            <dt>{sourceRefLabel(run.sourceRef.kind)}</dt>
            <dd>
              <SourceRefLink refModel={run.sourceRef} size={15} />
            </dd>
          </div>
        )}
        <div>
          <dt>Commit</dt>
          <dd>
            <Icon name="commit" size={15} />
            <CommitLink
              className="run-summary__commit"
              commit={run.commit}
              messageClassName="run-summary__commit-message"
              showIcon={false}
            />
          </dd>
        </div>
        <div>
          <dt>Created</dt>
          <dd>
            <time dateTime={run.createdAt.iso}>{run.createdAt.label}</time>
          </dd>
        </div>
        <div>
          <dt>Duration</dt>
          <dd>{durationCopy(run.status, run.durationLabel)}</dd>
        </div>
      </dl>
    </section>
  );
}

function JobsSection({
  collection,
  pagination,
  runStatus,
}: {
  readonly collection: ResultCollectionModel<JobModel>;
  readonly pagination: RunDetailPageModel["jobPagination"];
  readonly runStatus: StatusModel;
}) {
  const { items: jobs, visibility } = collection;

  return (
    <section aria-labelledby="jobs-heading">
      <div className="section-heading">
        <h2 id="jobs-heading">Jobs</h2>
        <span>{collectionCount(jobs.length, "job", visibility)}</span>
      </div>
      {visibility === "restricted" && jobs.length > 0 ? (
        <p className="results-visibility-notice">
          Some jobs are hidden because you don’t have access to view them.
        </p>
      ) : null}
      {jobs.length === 0 ? (
        <EmptyState
          description={
            visibility === "restricted"
              ? "Jobs for this run are unavailable with your current access."
              : emptyJobsCopy(runStatus)
          }
          variant="compact"
        />
      ) : (
        <div className="job-list">
          {jobs.map((job) => (
            <JobSummaryLink job={job} key={job.id} />
          ))}
        </div>
      )}
      <Pagination label="Run job pages" pagination={pagination} />
    </section>
  );
}

function JobSummaryLink({ job }: { readonly job: JobModel }) {
  const contents = (
    <>
      <span className="job__heading">
        <span className="job__title">
          <StatusBadge labelMode="accessible" status={job.status} />
          <span>
            <strong>{job.name}</strong>
            {job.runnerLabel === null && job.startedAt === null ? null : (
              <small>
                {job.runnerLabel}
                {job.runnerLabel !== null && job.startedAt !== null ? (
                  <MetadataSeparator />
                ) : null}
                {job.startedAt === null ? null : (
                  <>
                    Started{" "}
                    <time dateTime={job.startedAt.iso}>{job.startedAt.label}</time>
                  </>
                )}
              </small>
            )}
          </span>
        </span>
        <span className="job__result">
          <span aria-hidden="true">{job.status.label}</span>
          <span>{durationCopy(job.status, job.durationLabel)}</span>
          {job.href === null ? (
            <span>Logs unavailable</span>
          ) : (
            <Icon name="chevron-right" />
          )}
        </span>
      </span>
    </>
  );
  return job.href === null ? (
    <div
      aria-disabled="true"
      className="panel job-summary-link is-unavailable"
    >
      {contents}
    </div>
  ) : (
    <a className="panel job-summary-link" href={job.href}>
      {contents}
    </a>
  );
}

function ArtifactsSection({
  collection,
  runStatus,
}: {
  readonly collection: ResultCollectionModel<ArtifactModel>;
  readonly runStatus: StatusModel;
}) {
  const { items: artifacts, visibility } = collection;

  return (
    <section className="panel artifacts" aria-labelledby="artifacts-heading">
      <div className="panel__heading">
        <h2 id="artifacts-heading">Artifacts</h2>
        <span>{collectionCount(artifacts.length, "artifact", visibility)}</span>
      </div>
      {visibility === "restricted" && artifacts.length > 0 ? (
        <p className="results-visibility-notice">
          Some artifacts are hidden because you don’t have access to view them.
        </p>
      ) : null}
      {artifacts.length === 0 ? (
        <p className="artifacts__empty">
          {visibility === "restricted"
            ? "Artifacts for this run are unavailable with your current access."
            : emptyArtifactsCopy(runStatus)}
        </p>
      ) : (
        <ul className="artifact-list">
          {artifacts.map((artifact) => (
            <li key={artifact.id}>
              <Icon name="artifact" size={20} />
              <div className="artifact-list__content">
                {artifact.downloadHref === null ? (
                  <span className="artifact-list__identity">
                    <strong>{artifact.name}</strong>
                    <small>Download unavailable</small>
                  </span>
                ) : (
                  <a href={artifact.downloadHref}>{artifact.name}</a>
                )}
                <code className="artifact-list__digest">
                  SHA-256 {artifact.digest}
                </code>
              </div>
              <span>{artifact.sizeLabel}</span>
              {artifact.expiresAt === null ? null : (
                <span>
                  Expires{" "}
                  <time dateTime={artifact.expiresAt.iso}>
                    {artifact.expiresAt.label}
                  </time>
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function collectionCount(
  count: number,
  singular: "artifact" | "job",
  visibility: ResultCollectionVisibility,
): string {
  const noun = count === 1 ? singular : `${singular}s`;
  return visibility === "restricted" ? `${count} visible ${noun}` : `${count} ${noun}`;
}
