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
import { RENDER_REQUEST_LIMITS } from "./limits";
import {
  expectArray,
  expectBoolean,
  expectDisplayText,
  expectIdField,
  expectInteger,
  expectLiteral,
  expectNullableRoute,
  expectObject,
  expectOneOf,
  expectRouteField,
  expectString,
  expectTextField,
  expectUnique,
  invalid,
} from "./primitives";

export function validateRunDetailPage(value: unknown, path: string): void {
  const page = expectObject(value, path, [
    "kind",
    "shell",
    "repository",
    "run",
    "jobs",
    "jobPagination",
    "artifacts",
    "priorityUpdate",
    "rerun",
  ]);
  expectLiteral(page.kind, `${path}.kind`, "run-detail");
  const shell = validateShell(page.shell, `${path}.shell`);
  const repository = validateRepository(page.repository, `${path}.repository`);
  validateRepositoryShell(repository, shell, path);
  validateRunDetail(page.run, `${path}.run`, repository);
  validateResultCollection(
    page.jobs,
    `${path}.jobs`,
    RENDER_REQUEST_LIMITS.jobCount,
    validateJob,
  );
  if (page.priorityUpdate !== null) {
    const priority = expectObject(page.priorityUpdate, `${path}.priorityUpdate`, [
      "endpoint",
      "csrfToken",
      "current",
    ]);
    expectRouteField(priority, "endpoint", `${path}.priorityUpdate`);
    expectString(priority.csrfToken, `${path}.priorityUpdate.csrfToken`, 256, 1);
    expectInteger(priority.current, `${path}.priorityUpdate.current`, 0, 99);
  }
  validatePagination(page.jobPagination, `${path}.jobPagination`);
  validateResultCollection(
    page.artifacts,
    `${path}.artifacts`,
    RENDER_REQUEST_LIMITS.artifactCount,
    validateArtifact,
  );
  if (page.rerun !== null) {
    const rerun = expectObject(page.rerun, `${path}.rerun`, [
      "endpoint",
      "csrfToken",
      "failedJobsAvailable",
    ]);
    expectRouteField(rerun, "endpoint", `${path}.rerun`);
    expectString(rerun.csrfToken, `${path}.rerun.csrfToken`, 256, 1);
    expectBoolean(rerun.failedJobsAvailable, `${path}.rerun.failedJobsAvailable`);
  }
}

function validateResultCollection(
  value: unknown,
  path: string,
  maximumItems: number,
  validateItem: (value: unknown, path: string) => CollectionItemIdentity,
): void {
  const collection = expectObject(value, path, ["visibility", "items"]);
  expectOneOf(collection.visibility, `${path}.visibility`, ["full", "restricted"]);
  const itemsPath = `${path}.items`;
  const items = expectArray(collection.items, itemsPath, maximumItems);
  const seenIds = new Set<string>();
  const seenHrefs = new Set<string>();
  items.forEach((item, index) => {
    const itemPath = `${itemsPath}[${index}]`;
    const identity = validateItem(item, itemPath);
    expectUnique(seenIds, identity.id, `${itemPath}.id`);
    if (identity.href !== null) {
      expectUnique(
        seenHrefs,
        identity.href,
        `${itemPath}.${identity.hrefField}`,
      );
    }
  });
}

interface CollectionItemIdentity {
  readonly id: string;
  readonly href: string | null;
  readonly hrefField: "downloadHref" | "href";
}

function validateRunDetail(
  value: unknown,
  path: string,
  repository: RepositoryContext,
): void {
  const run = expectObject(value, path, [
    "number",
    "name",
    "workflowName",
    "workflowHref",
    "status",
    "priority",
    "sourceRef",
    "event",
    "actor",
    "commit",
    "createdAt",
    "durationLabel",
    "attempt",
  ]);
  validateRunNumber(run.number, `${path}.number`);
  expectTextField(run, "name", path);
  expectTextField(run, "workflowName", path);
  expectRouteField(run, "workflowHref", path);
  validateStatus(run.status, `${path}.status`);
  const priority = expectObject(run.priority, `${path}.priority`, [
    "level",
    "label",
    "mergeQueueManaged",
  ]);
  const priorityLevel = expectInteger(priority.level, `${path}.priority.level`, 0, 100);
  expectDisplayText(priority.label, `${path}.priority.label`);
  expectBoolean(priority.mergeQueueManaged, `${path}.priority.mergeQueueManaged`);
  if (priority.mergeQueueManaged !== (priorityLevel === 100)) invalid(`${path}.priority`, "merge-queue ownership must match reserved priority 100");
  validateSourceRef(run.sourceRef, `${path}.sourceRef`, repository);
  expectTextField(run, "event", path);
  if (run.actor !== null) {
    expectTextField(run, "actor", path);
  }
  validateCommit(run.commit, `${path}.commit`, repository);
  validateTimestamp(run.createdAt, `${path}.createdAt`);
  if (run.durationLabel !== null) {
    validateDurationLabel(run.durationLabel, `${path}.durationLabel`);
  }
  expectInteger(run.attempt, `${path}.attempt`, 1, 10_000);
}

function validateJob(value: unknown, path: string): CollectionItemIdentity {
  const job = expectObject(value, path, [
    "id",
    "name",
    "href",
    "runnerLabel",
    "status",
    "startedAt",
    "durationLabel",
  ]);
  const id = expectIdField(job, "id", path);
  expectTextField(job, "name", path);
  const href = expectNullableRoute(job.href, `${path}.href`);
  if (job.runnerLabel !== null) {
    expectTextField(job, "runnerLabel", path);
  }
  validateStatus(job.status, `${path}.status`);
  if (job.startedAt !== null) {
    validateTimestamp(job.startedAt, `${path}.startedAt`);
  }
  if (job.durationLabel !== null) {
    validateDurationLabel(job.durationLabel, `${path}.durationLabel`);
  }

  return { id, href, hrefField: "href" };
}

function validateDurationLabel(value: unknown, path: string): void {
  expectDisplayText(value, path, RENDER_REQUEST_LIMITS.shortTextLength);
}

function validateArtifact(value: unknown, path: string): CollectionItemIdentity {
  const artifact = expectObject(value, path, [
    "id",
    "name",
    "sizeLabel",
    "digest",
    "downloadHref",
    "expiresAt",
  ]);
  const id = expectIdField(artifact, "id", path);
  expectTextField(artifact, "name", path);
  expectTextField(artifact, "sizeLabel", path);
  const digest = expectString(artifact.digest, `${path}.digest`, 64, 64);
  if (!/^[a-f0-9]{64}$/u.test(digest)) {
    invalid(`${path}.digest`, "a canonical lowercase SHA-256 hex digest");
  }
  const href = expectNullableRoute(
    artifact.downloadHref,
    `${path}.downloadHref`,
  );
  if (artifact.expiresAt !== null) {
    validateTimestamp(artifact.expiresAt, `${path}.expiresAt`);
  }
  return { id, href, hrefField: "downloadHref" };
}
