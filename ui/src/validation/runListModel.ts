import {
  validateCommit,
  validateRepository,
  validateShell,
  validateStatus,
  validateTimestamp,
} from "./commonModels";
import { RENDER_REQUEST_LIMITS } from "./limits";
import {
  expectArray,
  expectIdField,
  expectLiteral,
  expectNullableRoute,
  expectObject,
  expectRouteField,
  expectTextField,
  expectUnique,
} from "./primitives";

export function validateRunListPage(value: unknown, path: string): void {
  const page = expectObject(value, path, [
    "kind",
    "shell",
    "repository",
    "heading",
    "summary",
    "filters",
    "runs",
    "pagination",
  ]);
  expectLiteral(page.kind, `${path}.kind`, "run-list");
  validateShell(page.shell, `${path}.shell`);
  validateRepository(page.repository, `${path}.repository`);
  expectTextField(page, "heading", path);
  expectTextField(page, "summary", path, RENDER_REQUEST_LIMITS.longTextLength);
  validateRunFilters(page.filters, `${path}.filters`);

  const runsPath = `${path}.runs`;
  const runs = expectArray(page.runs, runsPath, RENDER_REQUEST_LIMITS.runCount);
  const seenRunIds = new Set<string>();
  runs.forEach((run, index) => {
    const itemPath = `${runsPath}[${index}]`;
    const id = validateRunListItem(run, itemPath);
    expectUnique(seenRunIds, id, `${itemPath}.id`);
  });
  validatePagination(page.pagination, `${path}.pagination`);
}

function validateRunFilters(value: unknown, path: string): void {
  const filters = expectObject(value, path, [
    "action",
    "status",
    "branch",
    "statusOptions",
    "clearHref",
  ]);
  expectRouteField(filters, "action", path);
  expectTextField(filters, "status", path);
  expectTextField(filters, "branch", path);

  const optionsPath = `${path}.statusOptions`;
  const options = expectArray(
    filters.statusOptions,
    optionsPath,
    RENDER_REQUEST_LIMITS.optionCount,
  );
  const seenValues = new Set<string>();
  options.forEach((option, index) => {
    const itemPath = `${optionsPath}[${index}]`;
    const optionRecord = expectObject(option, itemPath, ["value", "label"]);
    const optionValue = expectTextField(optionRecord, "value", itemPath);
    expectTextField(optionRecord, "label", itemPath);
    expectUnique(seenValues, optionValue, `${itemPath}.value`);
  });
  expectRouteField(filters, "clearHref", path);
}

function validateRunListItem(value: unknown, path: string): string {
  const run = expectObject(value, path, [
    "id",
    "name",
    "workflowName",
    "href",
    "status",
    "branch",
    "event",
    "actor",
    "commit",
    "startedAt",
    "durationLabel",
  ]);
  const id = expectIdField(run, "id", path);
  expectTextField(run, "name", path);
  expectTextField(run, "workflowName", path);
  expectRouteField(run, "href", path);
  validateStatus(run.status, `${path}.status`);
  expectTextField(run, "branch", path);
  expectTextField(run, "event", path);
  expectTextField(run, "actor", path);
  validateCommit(run.commit, `${path}.commit`);
  validateTimestamp(run.startedAt, `${path}.startedAt`);
  expectTextField(run, "durationLabel", path);
  return id;
}

function validatePagination(value: unknown, path: string): void {
  const pagination = expectObject(value, path, ["previousHref", "nextHref", "label"]);
  expectNullableRoute(pagination.previousHref, `${path}.previousHref`);
  expectNullableRoute(pagination.nextHref, `${path}.nextHref`);
  expectTextField(pagination, "label", path);
}
