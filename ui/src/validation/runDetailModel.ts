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
  expectInteger,
  expectLiteral,
  expectObject,
  expectOneOf,
  expectRouteField,
  expectString,
  expectTextField,
  expectUnique,
  hasOwn,
  invalid,
} from "./primitives";

export function validateRunDetailPage(value: unknown, path: string): void {
  const page = expectObject(value, path, [
    "kind",
    "shell",
    "repository",
    "run",
    "csrfToken",
    "operations",
    "jobs",
    "artifacts",
  ]);
  expectLiteral(page.kind, `${path}.kind`, "run-detail");
  validateShell(page.shell, `${path}.shell`);
  validateRepository(page.repository, `${path}.repository`);
  validateRunDetail(page.run, `${path}.run`);
  expectString(
    page.csrfToken,
    `${path}.csrfToken`,
    RENDER_REQUEST_LIMITS.csrfTokenLength,
    1,
  );

  const operationsPath = `${path}.operations`;
  const operations = expectArray(
    page.operations,
    operationsPath,
    RENDER_REQUEST_LIMITS.operationCount,
  );
  const seenOperations = new Set<string>();
  operations.forEach((operation, index) => {
    const itemPath = `${operationsPath}[${index}]`;
    const key = validateOperation(operation, itemPath);
    expectUnique(seenOperations, key, itemPath);
  });

  const jobsPath = `${path}.jobs`;
  const jobs = expectArray(page.jobs, jobsPath, RENDER_REQUEST_LIMITS.jobCount);
  const seenJobIds = new Set<string>();
  jobs.forEach((job, index) => {
    const itemPath = `${jobsPath}[${index}]`;
    const id = validateJob(job, itemPath);
    expectUnique(seenJobIds, id, `${itemPath}.id`);
  });

  const artifactsPath = `${path}.artifacts`;
  const artifacts = expectArray(
    page.artifacts,
    artifactsPath,
    RENDER_REQUEST_LIMITS.artifactCount,
  );
  const seenArtifactIds = new Set<string>();
  artifacts.forEach((artifact, index) => {
    const itemPath = `${artifactsPath}[${index}]`;
    const id = validateArtifact(artifact, itemPath);
    expectUnique(seenArtifactIds, id, `${itemPath}.id`);
  });
}

function validateRunDetail(value: unknown, path: string): void {
  const run = expectObject(value, path, [
    "id",
    "name",
    "workflowName",
    "workflowHref",
    "status",
    "branch",
    "branchHref",
    "event",
    "actor",
    "commit",
    "createdAt",
    "durationLabel",
    "attempt",
  ]);
  expectIdField(run, "id", path);
  expectTextField(run, "name", path);
  expectTextField(run, "workflowName", path);
  expectRouteField(run, "workflowHref", path);
  validateStatus(run.status, `${path}.status`);
  expectTextField(run, "branch", path);
  expectRouteField(run, "branchHref", path);
  expectTextField(run, "event", path);
  expectTextField(run, "actor", path);
  validateCommit(run.commit, `${path}.commit`);
  validateTimestamp(run.createdAt, `${path}.createdAt`);
  expectTextField(run, "durationLabel", path);
  expectInteger(run.attempt, `${path}.attempt`, 1, 10_000);
}

function validateOperation(value: unknown, path: string): string {
  const operation = expectObject(value, path, ["label", "action", "style"], ["confirmation"]);
  const label = expectTextField(operation, "label", path);
  const action = expectRouteField(operation, "action", path);
  expectOneOf(operation.style, `${path}.style`, ["primary", "danger", "secondary"]);
  if (hasOwn(operation, "confirmation")) {
    expectString(
      operation.confirmation,
      `${path}.confirmation`,
      RENDER_REQUEST_LIMITS.shortTextLength,
    );
  }
  return `${action}\u0000${label}`;
}

function validateJob(value: unknown, path: string): string {
  const job = expectObject(value, path, [
    "id",
    "name",
    "href",
    "runnerLabel",
    "status",
    "startedAt",
    "durationLabel",
    "steps",
  ]);
  const id = expectIdField(job, "id", path);
  expectTextField(job, "name", path);
  expectRouteField(job, "href", path);
  expectTextField(job, "runnerLabel", path);
  validateStatus(job.status, `${path}.status`);
  if (job.startedAt !== null) {
    validateTimestamp(job.startedAt, `${path}.startedAt`);
  }
  expectTextField(job, "durationLabel", path);

  const stepsPath = `${path}.steps`;
  const steps = expectArray(job.steps, stepsPath, RENDER_REQUEST_LIMITS.stepCount);
  const seenStepNumbers = new Set<number>();
  steps.forEach((step, index) => {
    const itemPath = `${stepsPath}[${index}]`;
    const number = validateStep(step, itemPath);
    expectUnique(seenStepNumbers, number, `${itemPath}.number`);
  });
  return id;
}

function validateStep(value: unknown, path: string): number {
  const step = expectObject(value, path, [
    "number",
    "name",
    "status",
    "durationLabel",
    "logHref",
  ]);
  const number = expectInteger(step.number, `${path}.number`, 1, 1_000_000);
  expectTextField(step, "name", path);
  validateStatus(step.status, `${path}.status`);
  expectTextField(step, "durationLabel", path);
  expectRouteField(step, "logHref", path);
  return number;
}

function validateArtifact(value: unknown, path: string): string {
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
  if (!/^[a-fA-F0-9]{64}$/u.test(digest)) {
    invalid(`${path}.digest`, "a 64-character SHA-256 hex digest");
  }
  expectRouteField(artifact, "downloadHref", path);
  validateTimestamp(artifact.expiresAt, `${path}.expiresAt`);
  return id;
}
