import type { RepositoryModel, WorkflowNavigationModel } from "../models";
import { Icon } from "./Icon";
import { Pagination } from "./Pagination";

export interface WorkflowNavigationProps {
  readonly navigation: WorkflowNavigationModel | null;
  readonly repository: RepositoryModel;
}

export function WorkflowNavigation({
  navigation,
  repository,
}: WorkflowNavigationProps) {
  const selectedWorkflow = navigation?.selectedWorkflow ?? null;
  const workflows = navigation?.workflows ?? [];
  const currentLabel =
    selectedWorkflow === null
      ? "All workflows"
      : `${selectedWorkflow.name}${selectedWorkflow.enabled ? "" : " · Disabled"}`;

  return (
    <div className="workflow-navigation">
      <div className="workflow-navigation__desktop">
        <WorkflowNavigationContents
          repository={repository}
          selectedWorkflow={selectedWorkflow}
          workflows={workflows}
          pagination={navigation?.pagination ?? null}
        />
      </div>
      <details className="workflow-navigation__mobile">
        <summary className="workflow-navigation__disclosure-summary">
          <span className="workflow-navigation__disclosure-label">
            Workflows
          </span>
          <span className="workflow-navigation__disclosure-current">
            {currentLabel}
          </span>
          <Icon
            className="workflow-navigation__disclosure-icon"
            name="chevron-right"
          />
        </summary>
        <div className="workflow-navigation__menu">
          <WorkflowNavigationContents
            repository={repository}
            selectedWorkflow={selectedWorkflow}
            workflows={workflows}
            pagination={navigation?.pagination ?? null}
          />
        </div>
      </details>
    </div>
  );
}

interface WorkflowNavigationContentsProps {
  readonly repository: RepositoryModel;
  readonly selectedWorkflow: WorkflowNavigationModel["selectedWorkflow"];
  readonly workflows: WorkflowNavigationModel["workflows"];
  readonly pagination: WorkflowNavigationModel["pagination"] | null;
}

function WorkflowNavigationContents({
  repository,
  selectedWorkflow,
  workflows,
  pagination,
}: WorkflowNavigationContentsProps) {
  const selectedWorkflowId = selectedWorkflow?.id ?? null;
  const selectedIsOnPage = workflows.some(
    (workflow) => workflow.id === selectedWorkflowId,
  );
  return (
    <>
      <nav aria-label="Actions navigation">
        <div className="workflow-navigation__title">
          <Icon name="actions" size={18} />
          <span>Actions</span>
        </div>
        <div className="workflow-navigation__primary">
          <a
            href={repository.runsHref}
            aria-current={selectedWorkflowId === null ? "page" : undefined}
          >
            <Icon name="workflow" />
            <span>All workflows</span>
          </a>
        </div>
        {selectedWorkflow === null || selectedIsOnPage ? null : (
          <div className="workflow-navigation__section">
            <span className="workflow-navigation__section-heading">
              Current workflow
            </span>
            <WorkflowLink
              selectedWorkflowId={selectedWorkflowId}
              workflow={selectedWorkflow}
            />
          </div>
        )}
        {workflows.length === 0 ? null : (
          <div className="workflow-navigation__section">
            <span className="workflow-navigation__section-heading">
              Workflows
            </span>
            <div className="workflow-navigation__workflows">
              {workflows.map((workflow) => (
                <WorkflowLink
                  key={workflow.id}
                  selectedWorkflowId={selectedWorkflowId}
                  workflow={workflow}
                />
              ))}
            </div>
          </div>
        )}
      </nav>
      {pagination === null ? null : (
        <Pagination label="Workflow pages" pagination={pagination} />
      )}
    </>
  );
}

function WorkflowLink({
  selectedWorkflowId,
  workflow,
}: {
  readonly selectedWorkflowId: string | null;
  readonly workflow: WorkflowNavigationModel["workflows"][number];
}) {
  return (
    <a
      aria-current={workflow.id === selectedWorkflowId ? "page" : undefined}
      className="workflow-navigation__workflow"
      href={workflow.href}
    >
      <Icon name="workflow" />
      <span className="workflow-navigation__workflow-name">
        {workflow.name}
      </span>
      {workflow.enabled ? null : (
        <span
          aria-label="Disabled for new events"
          className="workflow-navigation__workflow-state"
        >
          Disabled
        </span>
      )}
    </a>
  );
}
