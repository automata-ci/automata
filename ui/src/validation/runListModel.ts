import {
  validateCommit,
  validatePagination,
  validateRepository,
  validateRepositoryShell,
  validateRunNumber,
  validateShell,
  validateSourceRef,
  validateStatus,
  validateTimestamp,
} from "./commonModels";
import type { RepositoryContext } from "./commonModels";
import { RENDER_REQUEST_LIMITS, utf8ByteLength } from "./limits";
import {
  hasForbiddenDisplayCharacter,
  hasVisibleDisplayCharacter,
} from "../unicode";
import {
  expectArray,
  expectBoolean,
  expectDisplayText,
  expectIdField,
  expectLiteral,
  expectObject,
  expectRouteField,
  expectString,
  expectTextField,
  expectUnique,
  invalid,
} from "./primitives";

const GIT_REF_PREFIX = "refs/";
const HEAD_REF_PREFIX = "refs/heads/";

export function validateRunListPage(value: unknown, path: string): void {
  const page = expectObject(value, path, [
    "kind",
    "shell",
    "repository",
    "heading",
    "summary",
    "filters",
    "workflowNavigation",
    "runs",
    "pagination",
  ]);
  expectLiteral(page.kind, `${path}.kind`, "run-list");
  const shell = validateShell(page.shell, `${path}.shell`);
  const repository = validateRepository(page.repository, `${path}.repository`);
  validateRepositoryShell(repository, shell, path);
  expectTextField(page, "heading", path);
  expectTextField(page, "summary", path, RENDER_REQUEST_LIMITS.longTextLength);
  const filters = validateRunFilters(page.filters, `${path}.filters`);
  const selectedWorkflowHref =
    page.workflowNavigation === null
      ? null
      : validateWorkflowNavigation(
          page.workflowNavigation,
          `${path}.workflowNavigation`,
        );
  const expectedFilterAction = selectedWorkflowHref ?? repository.runsHref;
  if (filters.action !== expectedFilterAction) {
    invalid(`${path}.filters.action`, "the selected workflow destination");
  }
  if (filters.clearHref !== expectedFilterAction) {
    invalid(`${path}.filters.clearHref`, "the selected workflow destination");
  }

  const runsPath = `${path}.runs`;
  const runs = expectArray(page.runs, runsPath, RENDER_REQUEST_LIMITS.runCount);
  const seenRunIds = new Set<string>();
  const seenRunHrefs = new Set<string>();
  runs.forEach((run, index) => {
    const itemPath = `${runsPath}[${index}]`;
    const identity = validateRunListItem(run, itemPath, repository);
    expectUnique(seenRunIds, identity.id, `${itemPath}.id`);
    expectUnique(seenRunHrefs, identity.href, `${itemPath}.href`);
  });
  validatePagination(page.pagination, `${path}.pagination`);
}

function validateWorkflowNavigation(
  value: unknown,
  path: string,
): string | null {
  const navigation = expectObject(value, path, [
    "selectedWorkflow",
    "workflows",
    "pagination",
  ]);
  const selectedWorkflow =
    navigation.selectedWorkflow === null
      ? null
      : validateWorkflowNavigationItem(
          navigation.selectedWorkflow,
          `${path}.selectedWorkflow`,
        );
  const workflowsPath = `${path}.workflows`;
  const workflows = expectArray(
    navigation.workflows,
    workflowsPath,
    RENDER_REQUEST_LIMITS.workflowCount,
  );
  const seenWorkflowIds = new Set<string>();
  const seenWorkflowHrefs = new Set<string>();
  workflows.forEach((workflow, index) => {
    const itemPath = `${workflowsPath}[${index}]`;
    const item = validateWorkflowNavigationItem(workflow, itemPath);
    expectUnique(seenWorkflowIds, item.id, `${itemPath}.id`);
    expectUnique(seenWorkflowHrefs, item.href, `${itemPath}.href`);
    if (
      selectedWorkflow !== null &&
      item.id === selectedWorkflow.id &&
      (item.name !== selectedWorkflow.name ||
        item.href !== selectedWorkflow.href ||
        item.enabled !== selectedWorkflow.enabled)
    ) {
      invalid(itemPath, "the selected workflow projection");
    }
  });
  validatePagination(navigation.pagination, `${path}.pagination`);
  return selectedWorkflow?.href ?? null;
}

interface WorkflowNavigationIdentity {
  readonly id: string;
  readonly name: string;
  readonly href: string;
  readonly enabled: boolean;
}

function validateWorkflowNavigationItem(
  value: unknown,
  path: string,
): WorkflowNavigationIdentity {
  const item = expectObject(value, path, ["id", "name", "href", "enabled"]);
  const id = expectIdField(item, "id", path);
  const name = expectTextField(item, "name", path);
  const href = expectRouteField(item, "href", path);
  expectBoolean(item.enabled, `${path}.enabled`);
  const enabled = item.enabled as boolean;
  return { id, name, href, enabled };
}

function validateRunFilters(
  value: unknown,
  path: string,
): { readonly action: string; readonly clearHref: string } {
  const filters = expectObject(value, path, [
    "action",
    "status",
    "branch",
    "clearHref",
  ]);
  const action = expectRouteField(filters, "action", path);
  const selectedStatus = expectString(
    filters.status,
    `${path}.status`,
    RENDER_REQUEST_LIMITS.shortTextLength,
    1,
  );
  const branch = expectString(
    filters.branch,
    `${path}.branch`,
    RENDER_REQUEST_LIMITS.shortTextLength,
  );
  if (
    branch.length > 0 &&
    (branch !== branch.trim() ||
      !hasVisibleDisplayCharacter(branch) ||
      hasForbiddenDisplayCharacter(branch) ||
      utf8ByteLength(
        branch.startsWith(GIT_REF_PREFIX)
          ? branch
          : `${HEAD_REF_PREFIX}${branch}`,
      ) > RENDER_REQUEST_LIMITS.shortTextLength)
  ) {
    invalid(
      `${path}.branch`,
      "empty or visible trimmed filter text without control or bidi formatting characters",
    );
  }

  if (!["all", "queued", "in_progress", "completed"].includes(selectedStatus)) {
    invalid(`${path}.status`, "a supported workflow-run status filter");
  }
  const clearHref = expectRouteField(filters, "clearHref", path);
  return { action, clearHref };
}

function validateRunListItem(
  value: unknown,
  path: string,
  repository: RepositoryContext,
): { readonly id: string; readonly href: string } {
  const run = expectObject(value, path, [
    "id",
    "number",
    "name",
    "workflowName",
    "workflowHref",
    "href",
    "status",
    "sourceRef",
    "event",
    "actor",
    "commit",
    "createdAt",
    "durationLabel",
  ]);
  const id = expectIdField(run, "id", path);
  validateRunNumber(run.number, `${path}.number`);
  expectTextField(run, "name", path);
  expectTextField(run, "workflowName", path);
  expectRouteField(run, "workflowHref", path);
  const href = expectRouteField(run, "href", path);
  validateStatus(run.status, `${path}.status`);
  validateSourceRef(run.sourceRef, `${path}.sourceRef`, repository);
  expectTextField(run, "event", path);
  if (run.actor !== null) {
    expectTextField(run, "actor", path);
  }
  validateCommit(run.commit, `${path}.commit`, repository);
  validateTimestamp(run.createdAt, `${path}.createdAt`);
  if (run.durationLabel !== null) {
    expectDisplayText(
      run.durationLabel,
      `${path}.durationLabel`,
      RENDER_REQUEST_LIMITS.shortTextLength,
    );
  }
  return { id, href };
}
