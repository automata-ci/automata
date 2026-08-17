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
  expectNullableRoute,
  expectObject,
  expectOneOf,
  expectRouteField,
  expectTextField,
  expectUnique,
  invalid,
} from "./primitives";

interface NavigationJobContext {
  readonly id: string;
  readonly name: string;
  readonly href: string | null;
  readonly status: StatusContext;
}

interface SelectedJobContext extends Omit<NavigationJobContext, "href"> {
  readonly href: string;
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
    "live",
    "notice",
  ]);
  expectLiteral(page.kind, `${path}.kind`, "job-log");
  const shell = validateShell(page.shell, `${path}.shell`);
  const repository = validateRepository(page.repository, `${path}.repository`);
  validateRepositoryShell(repository, shell, path);
  validateRun(page.run, `${path}.run`);

  const jobsPath = `${path}.jobs`;
  const jobs = expectArray(page.jobs, jobsPath, RENDER_REQUEST_LIMITS.jobCount);
  if (jobs.length === 0) invalid(jobsPath, "at least the selected job");
  const jobsById = new Map<string, NavigationJobContext>();
  const seenJobHrefs = new Set<string>();
  jobs.forEach((job, index) => {
    const itemPath = `${jobsPath}[${index}]`;
    const item = validateNavigationJob(job, itemPath);
    if (jobsById.has(item.id)) invalid(`${itemPath}.id`, "a unique value");
    jobsById.set(item.id, item);
    if (item.href !== null) expectUnique(seenJobHrefs, item.href, `${itemPath}.href`);
  });

  const selected = validateSelectedJob(page.job, `${path}.job`);
  const navigation = jobsById.get(selected.id);
  if (navigation === undefined) invalid(`${path}.job.id`, "an ID present in jobs");
  if (
    selected.name !== navigation.name ||
    selected.href !== navigation.href ||
    selected.status.label !== navigation.status.label ||
    selected.status.tone !== navigation.status.tone
  ) {
    invalid(`${path}.job`, "the selected navigation job");
  }
  validateNavigationPagination(
    page.navigationPagination,
    `${path}.navigationPagination`,
    selected.href,
    seenJobHrefs,
  );

  const visibility = expectOneOf(page.logVisibility, `${path}.logVisibility`, ["full", "restricted"]);
  validateLive(page.live, `${path}.live`, visibility, selected.href);
  if (page.notice !== null) {
    expectDisplayText(page.notice, `${path}.notice`, RENDER_REQUEST_LIMITS.longTextLength);
  }
}

function validateLive(
  value: unknown,
  path: string,
  visibility: "full" | "restricted",
  jobHref: string,
): void {
  if (value === null) return;
  if (visibility === "restricted") invalid(path, "no live tail for restricted logs");
  const live = expectObject(value, path, ["ticketHref"]);
  const ticketHref = expectRouteField(live, "ticketHref", path);
  if (ticketHref !== `${jobHref}/live-ticket`) {
    invalid(`${path}.ticketHref`, "the selected job live-ticket destination");
  }
}

function validateRun(value: unknown, path: string): void {
  const run = expectObject(value, path, [
    "number", "name", "href", "workflowName", "workflowHref", "attempt",
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
  const href = expectNullableRoute(job.href, `${path}.href`);
  if (href !== null) validateJobLogDestination(href, `${path}.href`);
  return {
    id: expectIdField(job, "id", path),
    name: expectTextField(job, "name", path),
    href,
    status: validateStatus(job.status, `${path}.status`),
  };
}

function validateSelectedJob(value: unknown, path: string): SelectedJobContext {
  const job = expectObject(value, path, [
    "id", "name", "href", "attempt", "runnerLabel", "status", "startedAt", "durationLabel",
  ]);
  const href = expectRouteField(job, "href", path);
  validateJobLogDestination(href, `${path}.href`);
  expectInteger(job.attempt, `${path}.attempt`, 1, 4_294_967_295);
  if (job.runnerLabel !== null) expectTextField(job, "runnerLabel", path);
  if (job.startedAt !== null) validateTimestamp(job.startedAt, `${path}.startedAt`);
  if (job.durationLabel !== null) {
    expectDisplayText(job.durationLabel, `${path}.durationLabel`, RENDER_REQUEST_LIMITS.shortTextLength);
  }
  return {
    id: expectIdField(job, "id", path),
    name: expectTextField(job, "name", path),
    href,
    status: validateStatus(job.status, `${path}.status`),
  };
}

function validateNavigationPagination(
  value: unknown,
  path: string,
  selectedJobHref: string,
  currentPageHrefs: ReadonlySet<string>,
): void {
  validatePagination(value, path);
  const pagination = expectObject(value, path, ["previousHref", "nextHref", "label"]);
  for (const field of ["previousHref", "nextHref"] as const) {
    if (pagination[field] === null) continue;
    const href = expectRouteField(pagination, field, path);
    validateJobLogDestination(href, `${path}.${field}`);
    if (href === selectedJobHref || currentPageHrefs.has(href)) {
      invalid(`${path}.${field}`, "a job destination outside the current page");
    }
  }
}

function validateJobLogDestination(value: string, path: string): void {
  if (value.includes("?") || value.includes("#")) {
    invalid(path, "a query- and fragment-free job-log destination");
  }
}
