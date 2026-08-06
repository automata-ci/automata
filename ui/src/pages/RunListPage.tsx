import type { RunListPageModel } from "../models";
import { Shell } from "../components/Shell";
import { StatusBadge } from "../components/StatusBadge";

export interface RunListPageProps {
  readonly model: RunListPageModel;
}

export function RunListPage({ model }: RunListPageProps) {
  return (
    <Shell shell={model.shell} repository={model.repository}>
      <main className="layout-width page" id="main-content">
        <div className="page-heading">
          <div>
            <p className="eyebrow">Actions</p>
            <h1>{model.heading}</h1>
            <p>{model.summary}</p>
          </div>
        </div>

        <form className="filters" action={model.filters.action} method="get" role="search">
          <div className="field">
            <label htmlFor="run-status">Status</label>
            <select id="run-status" name="status" defaultValue={model.filters.status}>
              {model.filters.statusOptions.map((option) => (
                <option value={option.value} key={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
          <div className="field field--grow">
            <label htmlFor="run-branch">Branch</label>
            <input
              id="run-branch"
              name="branch"
              type="search"
              defaultValue={model.filters.branch}
              placeholder="Filter by branch"
            />
          </div>
          <button className="button button--secondary" type="submit">
            Apply filters
          </button>
          <a className="text-link" href={model.filters.clearHref}>
            Clear
          </a>
        </form>

        <section className="panel" aria-labelledby="runs-heading">
          <div className="panel__heading">
            <h2 id="runs-heading">Recent runs</h2>
            <span>{model.pagination.label}</span>
          </div>
          {model.runs.length === 0 ? (
            <div className="empty-state">
              <h3>No workflow runs match these filters</h3>
              <p>Clear the filters to see all runs for this repository.</p>
              <a className="button button--secondary" href={model.filters.clearHref}>
                View all runs
              </a>
            </div>
          ) : (
            <div className="table-scroll">
              <table className="runs-table">
                <thead>
                  <tr>
                    <th scope="col">Run</th>
                    <th scope="col">Status</th>
                    <th scope="col">Source</th>
                    <th scope="col">Started</th>
                  </tr>
                </thead>
                <tbody>
                  {model.runs.map((run) => (
                    <tr key={run.id}>
                      <td>
                        <a className="run-name" href={run.href}>
                          {run.name}
                        </a>
                        <span className="subdued">{run.workflowName}</span>
                      </td>
                      <td>
                        <StatusBadge status={run.status} />
                        <span className="subdued">{run.durationLabel}</span>
                      </td>
                      <td>
                        <span className="branch-pill">{run.branch}</span>
                        <a className="commit-link" href={run.commit.href} title={run.commit.message}>
                          {run.commit.shortSha}
                        </a>
                        <span className="subdued">
                          {run.event} by {run.actor}
                        </span>
                      </td>
                      <td>
                        <time dateTime={run.startedAt.iso}>{run.startedAt.label}</time>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <nav className="pagination" aria-label="Workflow run pages">
            {model.pagination.previousHref === null ? (
              <span className="button button--quiet" aria-disabled="true">
                Previous
              </span>
            ) : (
              <a className="button button--quiet" href={model.pagination.previousHref}>
                Previous
              </a>
            )}
            {model.pagination.nextHref === null ? (
              <span className="button button--quiet" aria-disabled="true">
                Next
              </span>
            ) : (
              <a className="button button--quiet" href={model.pagination.nextHref}>
                Next
              </a>
            )}
          </nav>
        </section>
      </main>
    </Shell>
  );
}
