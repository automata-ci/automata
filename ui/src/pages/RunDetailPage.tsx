import type { RunDetailPageModel } from "../models";
import { Shell } from "../components/Shell";
import { StatusBadge } from "../components/StatusBadge";

export interface RunDetailPageProps {
  readonly model: RunDetailPageModel;
}

export function RunDetailPage({ model }: RunDetailPageProps) {
  const { run } = model;

  return (
    <Shell shell={model.shell} repository={model.repository}>
      <main className="layout-width page" id="main-content">
        <nav className="breadcrumbs" aria-label="Breadcrumb">
          <a href={model.repository.runsHref}>Workflow runs</a>
          <span aria-hidden="true">/</span>
          <span aria-current="page">Run {run.id}</span>
        </nav>

        <div className="page-heading page-heading--run">
          <div>
            <div className="heading-status">
              <StatusBadge status={run.status} />
              <span>Attempt {run.attempt}</span>
            </div>
            <h1>{run.name}</h1>
            <p>
              <a href={run.workflowHref}>{run.workflowName}</a>
              <span aria-hidden="true"> · </span>
              triggered by {run.actor} via {run.event}
            </p>
          </div>
          <div className="actions" aria-label="Run actions">
            {model.operations.map((operation) => (
              <form
                action={operation.action}
                method="post"
                key={`${operation.action}:${operation.label}`}
                data-confirm={operation.confirmation}
              >
                <input type="hidden" name="csrf_token" value={model.csrfToken} />
                <button className={`button button--${operation.style}`} type="submit">
                  {operation.label}
                </button>
              </form>
            ))}
          </div>
        </div>

        <section className="run-summary" aria-label="Run summary">
          <div>
            <span className="summary-label">Branch</span>
            <a href={run.branchHref}>{run.branch}</a>
          </div>
          <div>
            <span className="summary-label">Commit</span>
            <a href={run.commit.href} title={run.commit.message}>
              {run.commit.shortSha}
            </a>
          </div>
          <div>
            <span className="summary-label">Created</span>
            <time dateTime={run.createdAt.iso}>{run.createdAt.label}</time>
          </div>
          <div>
            <span className="summary-label">Duration</span>
            <span>{run.durationLabel}</span>
          </div>
        </section>

        <div className="detail-grid">
          <section className="panel" aria-labelledby="jobs-heading">
            <div className="panel__heading">
              <h2 id="jobs-heading">Jobs</h2>
              <span>{model.jobs.length} total</span>
            </div>
            <div className="job-list">
              {model.jobs.map((job) => (
                <article className="job" key={job.id}>
                  <div className="job__heading">
                    <div>
                      <a className="job__name" href={job.href}>
                        {job.name}
                      </a>
                      <span className="subdued">{job.runnerLabel}</span>
                    </div>
                    <div className="job__result">
                      <StatusBadge status={job.status} />
                      <span>{job.durationLabel}</span>
                    </div>
                  </div>
                  {job.steps.length === 0 ? (
                    <p className="job__empty">Waiting for steps to begin.</p>
                  ) : (
                    <ol className="steps">
                      {job.steps.map((step) => (
                        <li key={step.number}>
                          <span className={`step-marker step-marker--${step.status.tone}`} aria-hidden="true" />
                          <a href={step.logHref}>{step.name}</a>
                          <span className="steps__status">{step.status.label}</span>
                          <span>{step.durationLabel}</span>
                        </li>
                      ))}
                    </ol>
                  )}
                </article>
              ))}
            </div>
          </section>

          <aside className="panel artifacts" aria-labelledby="artifacts-heading">
            <div className="panel__heading">
              <h2 id="artifacts-heading">Artifacts</h2>
              <span>{model.artifacts.length}</span>
            </div>
            {model.artifacts.length === 0 ? (
              <p className="artifacts__empty">This run did not produce any artifacts.</p>
            ) : (
              <ul className="artifact-list">
                {model.artifacts.map((artifact) => (
                  <li key={artifact.id}>
                    <a href={artifact.downloadHref}>{artifact.name}</a>
                    <span>{artifact.sizeLabel}</span>
                    <span title={artifact.digest}>SHA-256 {artifact.digest.slice(0, 12)}…</span>
                    <span>
                      Expires <time dateTime={artifact.expiresAt.iso}>{artifact.expiresAt.label}</time>
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </aside>
        </div>
      </main>
    </Shell>
  );
}
