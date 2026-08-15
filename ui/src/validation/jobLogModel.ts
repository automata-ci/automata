import {
  validatePagination,
  validateRepository,
  validateRunNumber,
  validateRepositoryShell,
  validateShell,
  validateStatus,
  validateTimestamp,
} from "./commonModels";
import type { StatusContext } from "./commonModels";
import { RENDER_REQUEST_LIMITS } from "./limits";
import {
  expectArray,
  expectDisplayText,
  expectIdField,
  expectInteger,
  expectLiteral,
  expectLogText,
  expectNullableRoute,
  expectObject,
  expectOneOf,
  expectRouteField,
  expectString,
  expectTextField,
  expectUnique,
  invalid,
} from "./primitives";

const LOG_LINE_NUMBER = /^(0|[1-9][0-9]{0,19})(?:\.([1-9][0-9]{0,9}))?$/u;
const LOG_LINE_ID = /^[A-Za-z][A-Za-z0-9:._-]*$/u;
const MAX_U64_DECIMAL = "18446744073709551615";
const MAX_U32_DECIMAL = "4294967295";
const LOG_CURSOR = /^[A-Za-z0-9_-]{1,512}$/u;

interface NavigationJobContext {
  readonly id: string;
  readonly name: string;
  readonly href: string | null;
  readonly status: StatusContext;
}

interface SelectedJobContext extends Omit<NavigationJobContext, "href"> {
  readonly href: string;
  readonly attempt: number;
}

interface LogLineIdentity {
  readonly id: string;
  readonly number: string;
  readonly sequence: string;
  readonly fragment: string | null;
}

export function validateJobLogPage(value: unknown, path: string): void {
  const page = expectObject(value, path, [
    "kind",
    "shell",
    "repository",
    "run",
    "jobs",
    "navigationPagination",
    "job",
    "logVisibility",
    "search",
    "lines",
    "live",
    "notice",
    "pagination",
  ]);
  expectLiteral(page.kind, `${path}.kind`, "job-log");
  const shell = validateShell(page.shell, `${path}.shell`);
  const repository = validateRepository(page.repository, `${path}.repository`);
  validateRepositoryShell(repository, shell, path);
  validateRun(page.run, `${path}.run`);

  const jobsPath = `${path}.jobs`;
  const jobs = expectArray(page.jobs, jobsPath, RENDER_REQUEST_LIMITS.jobCount);
  if (jobs.length === 0) {
    invalid(jobsPath, "at least the selected job");
  }
  const jobsById = new Map<string, NavigationJobContext>();
  const seenJobHrefs = new Set<string>();
  jobs.forEach((job, index) => {
    const itemPath = `${jobsPath}[${index}]`;
    const context = validateNavigationJob(job, itemPath);
    if (jobsById.has(context.id)) {
      invalid(`${itemPath}.id`, "a unique value");
    }
    jobsById.set(context.id, context);
    if (context.href !== null) {
      expectUnique(seenJobHrefs, context.href, `${itemPath}.href`);
    }
  });

  const selectedJob = validateSelectedJob(page.job, `${path}.job`);
  const logVisibility = expectOneOf(
    page.logVisibility,
    `${path}.logVisibility`,
    ["full", "restricted"],
  );
  const navigationJob = jobsById.get(selectedJob.id);
  if (navigationJob === undefined) {
    invalid(`${path}.job.id`, "an ID present in jobs");
  }
  validateSelectedJobMatchesNavigation(selectedJob, navigationJob, `${path}.job`);
  validateNavigationPagination(
    page.navigationPagination,
    `${path}.navigationPagination`,
    selectedJob.href,
    seenJobHrefs,
  );

  validateSearch(page.search, `${path}.search`, selectedJob.href);

  const linesPath = `${path}.lines`;
  const lines = expectArray(page.lines, linesPath, RENDER_REQUEST_LIMITS.logLineCount);
  if (logVisibility === "restricted" && lines.length !== 0) {
    invalid(linesPath, "an empty restricted log collection");
  }
  const seenLineIds = new Set<string>();
  let previousLine: LogLineIdentity | null = null;
  lines.forEach((line, index) => {
    const itemPath = `${linesPath}[${index}]`;
    const identity = validateLine(line, itemPath);
    expectUnique(seenLineIds, identity.id, `${itemPath}.id`);
    if (previousLine !== null && !isAfterLogLine(identity, previousLine)) {
      invalid(`${itemPath}.number`, "a strictly increasing canonical log sequence");
    }
    previousLine = identity;
  });

  validateLive(page.live, `${path}.live`, logVisibility);

  if (page.notice !== null) {
    expectDisplayText(
      page.notice,
      `${path}.notice`,
      RENDER_REQUEST_LIMITS.longTextLength,
    );
  }
  validateLogPagination(page.pagination, `${path}.pagination`);
}

function validateLive(
  value: unknown,
  path: string,
  logVisibility: "full" | "restricted",
): void {
  if (value === null) {
    return;
  }
  if (logVisibility === "restricted") {
    invalid(path, "no live tail for a restricted log collection");
  }
  const live = expectObject(value, path, [
    "checkpoint",
    "state",
    "moreAvailable",
  ]);
  validateCursor(live.checkpoint, `${path}.checkpoint`);
  expectOneOf(live.state, `${path}.state`, ["open", "closed"]);
  if (typeof live.moreAvailable !== "boolean") {
    invalid(`${path}.moreAvailable`, "a boolean");
  }
  if (live.moreAvailable && live.checkpoint === null) {
    invalid(`${path}.checkpoint`, "a checkpoint when more data is available");
  }
}

function validateNavigationPagination(
  value: unknown,
  path: string,
  selectedJobHref: string,
  currentPageHrefs: ReadonlySet<string>,
): void {
  validatePagination(value, path);
  const pagination = expectObject(value, path, [
    "previousHref",
    "nextHref",
    "label",
  ]);
  for (const field of ["previousHref", "nextHref"] as const) {
    const href = pagination[field];
    if (href === null) {
      continue;
    }
    const route = expectRouteField(pagination, field, path);
    validateJobLogDestination(route, `${path}.${field}`);
    if (route === selectedJobHref || currentPageHrefs.has(route)) {
      invalid(`${path}.${field}`, "a job destination outside the current page");
    }
  }
}

function validateLogPagination(value: unknown, path: string): void {
  const pagination = expectObject(value, path, [
    "currentCursor",
    "previousCursor",
    "nextCursor",
    "label",
  ]);
  const current = validateCursor(
    pagination.currentCursor,
    `${path}.currentCursor`,
  );
  const previous = validateCursor(
    pagination.previousCursor,
    `${path}.previousCursor`,
  );
  const next = validateCursor(pagination.nextCursor, `${path}.nextCursor`);
  if (previous !== null && previous === next) {
    invalid(`${path}.nextCursor`, "a cursor distinct from previousCursor");
  }
  if (current !== null && (current === previous || current === next)) {
    invalid(`${path}.currentCursor`, "a cursor distinct from page destinations");
  }
  expectTextField(pagination, "label", path);
}

function validateCursor(value: unknown, path: string): string | null {
  if (value === null) {
    return null;
  }
  const cursor = expectString(value, path, 512, 1);
  if (!LOG_CURSOR.test(cursor)) {
    invalid(path, "a canonical URL-safe pagination cursor");
  }
  return cursor;
}

function validateRun(value: unknown, path: string): void {
  const run = expectObject(value, path, [
    "number",
    "name",
    "href",
    "workflowName",
    "workflowHref",
    "attempt",
  ]);
  validateRunNumber(run.number, `${path}.number`);
  expectTextField(run, "name", path);
  expectRouteField(run, "href", path);
  expectTextField(run, "workflowName", path);
  expectRouteField(run, "workflowHref", path);
  expectInteger(run.attempt, `${path}.attempt`, 1, 10_000);
}

function validateNavigationJob(value: unknown, path: string): NavigationJobContext {
  const job = expectObject(value, path, ["id", "name", "href", "status"]);
  const id = expectIdField(job, "id", path);
  const name = expectTextField(job, "name", path);
  const hrefPath = `${path}.href`;
  const href = expectNullableRoute(job.href, hrefPath);
  if (href !== null) {
    validateJobLogDestination(href, hrefPath);
  }
  const status = validateStatus(job.status, `${path}.status`);
  return { id, name, href, status };
}

function validateSelectedJob(value: unknown, path: string): SelectedJobContext {
  const job = expectObject(value, path, [
    "id",
    "name",
    "href",
    "attempt",
    "runnerLabel",
    "status",
    "startedAt",
    "durationLabel",
  ]);
  const id = expectIdField(job, "id", path);
  const name = expectTextField(job, "name", path);
  const hrefPath = `${path}.href`;
  const href = expectRouteField(job, "href", path);
  validateJobLogDestination(href, hrefPath);
  const attempt = expectInteger(
    job.attempt,
    `${path}.attempt`,
    1,
    4_294_967_295,
  );
  if (job.runnerLabel !== null) {
    expectTextField(job, "runnerLabel", path);
  }
  const status = validateStatus(job.status, `${path}.status`);
  if (job.startedAt !== null) {
    validateTimestamp(job.startedAt, `${path}.startedAt`);
  }
  if (job.durationLabel !== null) {
    expectDisplayText(
      job.durationLabel,
      `${path}.durationLabel`,
      RENDER_REQUEST_LIMITS.shortTextLength,
    );
  }
  return { id, name, href, attempt, status };
}

function validateSelectedJobMatchesNavigation(
  selected: SelectedJobContext,
  navigation: NavigationJobContext,
  path: string,
): void {
  if (selected.name !== navigation.name) {
    invalid(`${path}.name`, "the selected navigation job name");
  }
  if (selected.href !== navigation.href) {
    invalid(`${path}.href`, "the selected navigation job destination");
  }
  if (selected.status.label !== navigation.status.label) {
    invalid(`${path}.status.label`, "the selected navigation job status label");
  }
}

function validateSearch(value: unknown, path: string, jobHref: string): void {
  const search = expectObject(value, path, [
    "action",
    "query",
    "clearHref",
  ]);
  const actionPath = `${path}.action`;
  const action = expectRouteField(search, "action", path);
  validateJobLogDestination(action, actionPath);
  const query = expectString(
    search.query,
    `${path}.query`,
    RENDER_REQUEST_LIMITS.shortTextLength,
  );
  if (query.length > 0) {
    expectDisplayText(
      query,
      `${path}.query`,
      RENDER_REQUEST_LIMITS.shortTextLength,
    );
  }
  const clearHrefPath = `${path}.clearHref`;
  const clearHref = expectRouteField(search, "clearHref", path);
  validateJobLogDestination(clearHref, clearHrefPath);
  if (action !== jobHref) {
    invalid(`${path}.action`, "the selected job destination");
  }
  if (clearHref !== jobHref) {
    invalid(`${path}.clearHref`, "the selected job destination");
  }
}

function validateJobLogDestination(value: string, path: string): void {
  if (value.includes("?") || value.includes("#")) {
    invalid(path, "a query- and fragment-free job-log destination");
  }
}

function validateLine(value: unknown, path: string): LogLineIdentity {
  const line = expectObject(value, path, ["id", "number", "timestamp", "channel", "text"]);
  const id = expectIdField(line, "id", path);
  if (!LOG_LINE_ID.test(id)) {
    invalid(`${path}.id`, "a DOM-safe log line identifier");
  }
  const number = expectString(line.number, `${path}.number`, 31, 1);
  const numberMatch = LOG_LINE_NUMBER.exec(number);
  const sequence = numberMatch?.[1];
  const fragment = numberMatch?.[2] ?? null;
  if (
    sequence === undefined ||
    !isBoundedDecimal(sequence, MAX_U64_DECIMAL) ||
    (fragment !== null && !isBoundedDecimal(fragment, MAX_U32_DECIMAL))
  ) {
    invalid(`${path}.number`, "a lossless decimal log sequence");
  }
  validateTimestamp(line.timestamp, `${path}.timestamp`);
  expectOneOf(line.channel, `${path}.channel`, ["stdout", "stderr", "system"]);
  expectLogText(
    line.text,
    `${path}.text`,
    RENDER_REQUEST_LIMITS.logLineTextLength,
  );
  return { id, number, sequence, fragment };
}

function isAfterLogLine(current: LogLineIdentity, previous: LogLineIdentity): boolean {
  const sequenceOrder = compareDecimal(current.sequence, previous.sequence);
  if (sequenceOrder !== 0) {
    return sequenceOrder > 0;
  }
  if (current.fragment === null || previous.fragment === null) {
    return false;
  }
  return compareDecimal(current.fragment, previous.fragment) > 0;
}

function isBoundedDecimal(value: string, maximum: string): boolean {
  return value.length < maximum.length || (value.length === maximum.length && value <= maximum);
}

function compareDecimal(left: string, right: string): number {
  if (left.length !== right.length) {
    return left.length - right.length;
  }
  return left === right ? 0 : left < right ? -1 : 1;
}
