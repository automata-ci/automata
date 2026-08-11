import type { ReactNode } from "react";
import type {
  RunFiltersModel,
  RunListItemModel,
  RunListPageModel,
} from "../models";
import { ActionsLayout } from "../components/ActionsLayout";
import { CommitLink } from "../components/CommitLink";
import { EmptyState } from "../components/EmptyState";
import { Icon } from "../components/Icon";
import { MetadataSeparator } from "../components/MetadataSeparator";
import { Pagination } from "../components/Pagination";
import { Shell } from "../components/Shell";
import { SourceRefLink } from "../components/SourceRefLink";
import { StatusBadge } from "../components/StatusBadge";
import { WorkflowNavigation } from "../components/WorkflowNavigation";
import { enforceBranchFilterValidity } from "../components/textInputConstraints";
import { durationCopy, formatEventName } from "../presentation/runPresentation";
import { RUN_STATUS_FILTER_OPTIONS } from "../runFilters";
import { RENDER_REQUEST_LIMITS } from "../validation/limits";

export interface RunListPageProps {
  readonly model: RunListPageModel;
  readonly shellUtility?: ReactNode;
}

export function RunListPage({ model, shellUtility }: RunListPageProps) {
  const view = deriveRunListView(model);

  return (
    <Shell
      shell={model.shell}
      repository={model.repository}
      utility={shellUtility}
    >
      <main className="layout-wide page">
        <ActionsLayout
          navigation={
            <WorkflowNavigation
              navigation={model.workflowNavigation}
              repository={model.repository}
            />
          }
        >
          <header className="page-heading">
            <div>
              <h1>{model.heading}</h1>
              <p>{model.summary}</p>
            </div>
          </header>

          <RunFilters
            filters={model.filters}
            hasActiveFilters={view.hasActiveFilters}
          />

          <section className="panel" aria-labelledby="runs-heading">
            <div className="panel__heading">
              <h2 id="runs-heading">{view.panelHeading}</h2>
              <span>{model.pagination.label}</span>
            </div>
            {model.runs.length === 0 ? (
              <EmptyState
                action={
                  view.hasActiveFilters ? (
                    <a className="button" href={model.filters.clearHref}>
                      Clear filters
                    </a>
                  ) : undefined
                }
                description={view.emptyDescription}
                heading={view.emptyHeading}
                icon="actions"
              />
            ) : (
              <ul className="run-list">
                {model.runs.map((run) => (
                  <RunRow key={run.id} run={run} />
                ))}
              </ul>
            )}
            <Pagination
              label="Workflow run pages"
              pagination={model.pagination}
            />
          </section>
        </ActionsLayout>
      </main>
    </Shell>
  );
}

interface RunListView {
  readonly emptyDescription: string;
  readonly emptyHeading: string;
  readonly hasActiveFilters: boolean;
  readonly panelHeading: string;
}

function deriveRunListView(model: RunListPageModel): RunListView {
  const hasActiveFilters =
    model.filters.status !== "all" || model.filters.branch.length > 0;
  const selectedWorkflowName = model.workflowNavigation?.selectedWorkflow?.name;
  const workflowScope =
    selectedWorkflowName === undefined
      ? "workflow runs"
      : `${selectedWorkflowName} workflow runs`;

  return {
    hasActiveFilters,
    panelHeading:
      selectedWorkflowName === undefined ? "All workflow runs" : workflowScope,
    emptyHeading: hasActiveFilters
      ? `No ${workflowScope} match these filters`
      : `No ${workflowScope} yet`,
    emptyDescription: hasActiveFilters
      ? selectedWorkflowName === undefined
        ? "Try changing the branch, tag, or status filter."
        : `Try changing the branch, tag, or status filter for ${selectedWorkflowName}.`
      : selectedWorkflowName === undefined
        ? model.summary
        : `No runs have been recorded for ${selectedWorkflowName}.`,
  };
}

function RunFilters({
  filters,
  hasActiveFilters,
}: {
  readonly filters: RunFiltersModel;
  readonly hasActiveFilters: boolean;
}) {
  return (
    <form
      aria-label="Filter workflow runs"
      className="filters"
      action={filters.action}
      method="get"
      role="search"
    >
      <div className="filter-search">
        <Icon name="search" />
        <label className="sr-only" htmlFor="run-branch">
          Filter runs by branch or Git ref
        </label>
        <input
          autoCapitalize="none"
          autoComplete="off"
          autoCorrect="off"
          defaultValue={filters.branch}
          id="run-branch"
          maxLength={RENDER_REQUEST_LIMITS.shortTextLength}
          name="branch"
          onInput={(event) => enforceBranchFilterValidity(event.currentTarget)}
          placeholder="Branch or refs/tags/v1.0.0"
          spellCheck={false}
          type="search"
        />
      </div>
      <label className="select-control" htmlFor="run-status">
        <span className="sr-only">Filter by status</span>
        <select id="run-status" name="status" defaultValue={filters.status}>
          {RUN_STATUS_FILTER_OPTIONS.map((option) => (
            <option value={option.value} key={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </label>
      <button className="button" type="submit">
        Filter
      </button>
      {hasActiveFilters ? (
        <a className="text-link" href={filters.clearHref}>
          Clear filters
        </a>
      ) : null}
    </form>
  );
}

function RunRow({ run }: { readonly run: RunListItemModel }) {
  return (
    <li className="run-row">
      <div className="run-row__status">
        <StatusBadge labelMode="none" status={run.status} />
      </div>
      <div className="run-row__content">
        <a className="run-name" href={run.href}>
          {run.name}
        </a>
        <p className="run-row__context">
          <a href={run.workflowHref}>{run.workflowName}</a>
          <MetadataSeparator />
          <a href={run.href}>#{run.number}</a>
          <MetadataSeparator />
          <span>
            {formatEventName(run.event)}
            {run.actor === null ? null : ` by ${run.actor}`}
          </span>
        </p>
        <div className="run-row__meta">
          {run.sourceRef === null ? null : (
            <SourceRefLink
              className="run-row__source-ref"
              refModel={run.sourceRef}
            />
          )}
          <CommitLink
            className="run-row__commit"
            commit={run.commit}
            messageClassName="run-row__commit-message"
          />
          <time dateTime={run.createdAt.iso}>{run.createdAt.label}</time>
        </div>
      </div>
      <div className="run-row__result">
        <span>{run.status.label}</span>
        <span>{durationCopy(run.status, run.durationLabel)}</span>
      </div>
    </li>
  );
}
