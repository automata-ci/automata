import type {
  JobLogPageModel,
  JobModel,
  RepositoryDirectoryPageModel,
  RepositorySecretsPageModel,
  RepositorySettingsPageModel,
  RunnerDirectoryPageModel,
  RunDetailPageModel,
  RunListItemModel,
  RunListPageModel,
} from "../models";
import type { LiveLogRecord } from "../logs/sse";
import {
  previewRepository,
  previewRunSamples,
  previewShell,
  previewWorkflows,
} from "./sampleData";
import type { PreviewJobSample, PreviewRunSample } from "./sampleData";
import { RENDER_REQUEST_LIMITS, utf8ByteLength } from "../validation";
import {
  hasForbiddenDisplayCharacter,
  hasVisibleDisplayCharacter,
} from "../unicode";
import { isRunStatusFilter } from "../runFilters";
import type { RunStatusFilter } from "../runFilters";

const HEAD_REF_PREFIX = "refs/heads/";
const TAG_REF_PREFIX = "refs/tags/";
const REF_PREFIX = "refs/";
const RUN_LIST_KEYS = new Set(["view", "workflow", "status", "branch"]);
const RUN_DETAIL_KEYS = new Set(["view", "run"]);
const JOB_LOG_KEYS = new Set(["view", "run", "job"]);
const VIEW_ONLY_KEYS = new Set(["view"]);

export function previewRepositoryDirectory(
  empty = false,
): RepositoryDirectoryPageModel {
  const repositories = empty
    ? []
    : [
        {
          owner: previewRepository.owner,
          name: previewRepository.name,
          sourceHref: previewRepository.sourceHref,
          actionsHref: previewRepository.runsHref,
          settingsHref: previewRepository.settingsHref,
        },
      ];
  return {
    kind: "repository-directory",
    shell: {
      ...previewShell,
      documentTitle: "Repositories · Automata",
      description: "Browse repositories available under your current access.",
      navigation: [
        { label: "Repositories", href: "?view=repositories", current: true },
        { label: "Runners", href: "?view=runners" },
        { label: "Access", href: "?view=users" },
      ],
    },
    heading: "Repositories",
    summary: "Browse repositories available under your current access.",
    repositories,
    pagination: {
      nextHref: null,
      label: `${repositories.length} ${repositories.length === 1 ? "repository" : "repositories"} on this page`,
    },
  };
}

export function previewRunnerDirectory(): RunnerDirectoryPageModel {
  return {
    kind: "runner-directory",
    shell: {
      ...previewShell,
      documentTitle: "Runners · Automata",
      description: "Review runner availability, scheduling state, labels, and capacity.",
      navigation: [
        { label: "Repositories", href: "?view=repositories" },
        { label: "Runners", href: "?view=runners", current: true },
        { label: "Access", href: "?view=users" },
      ],
    },
    heading: "Runners",
    summary: "Review runner availability, scheduling state, labels, and capacity.",
    visibility: "private",
    counts: { total: 3, online: 2, busySlots: 3, totalSlots: 12 },
    runners: [
      {
        name: "linux-01",
        group: "general",
        labels: ["self-hosted", "linux", "x64"],
        status: { label: "Online", tone: "success" },
        desiredState: "active",
        desiredStateLabel: "Accepting jobs",
        busySlots: 3,
        totalSlots: 4,
        lastSeenAt: { iso: "2026-08-18T01:30:00Z", label: "18 Aug 2026, 01:30 UTC" },
      },
      {
        name: "arm64-01",
        group: "release",
        labels: ["self-hosted", "linux", "arm64"],
        status: { label: "Online", tone: "success" },
        desiredState: "active",
        desiredStateLabel: "Accepting jobs",
        busySlots: 0,
        totalSlots: 4,
        lastSeenAt: { iso: "2026-08-18T01:29:00Z", label: "18 Aug 2026, 01:29 UTC" },
      },
      {
        name: "linux-02",
        group: "general",
        labels: ["self-hosted", "linux", "x64"],
        status: { label: "Offline", tone: "neutral" },
        desiredState: "draining",
        desiredStateLabel: "Draining",
        busySlots: 0,
        totalSlots: 4,
        lastSeenAt: { iso: "2026-08-18T01:20:00Z", label: "18 Aug 2026, 01:20 UTC" },
      },
    ],
  };
}

export function isPreviewRepositoryDirectoryStateSupported(
  searchParameters: URLSearchParams,
): boolean {
  return hasOnlyUniqueKeys(searchParameters, VIEW_ONLY_KEYS);
}

export function previewRunList(
  searchParameters = new URLSearchParams(),
): RunListPageModel {
  const selectedWorkflowId = selectedWorkflow(searchParameters.get("workflow"));
  const status = selectedStatus(searchParameters.get("status"));
  const branch = (searchParameters.get("branch") ?? "").trim();
  const exactCanonicalRef =
    branch.length === 0 || branch.startsWith("refs/")
      ? branch
      : `refs/heads/${branch}`;
  const workflowHref = previewWorkflows.find(
    (workflow) => workflow.id === selectedWorkflowId,
  )?.href;
  const visibleRuns = previewRunSamples
    .filter(
      ({ run }) =>
        (workflowHref === undefined || run.workflowHref === workflowHref) &&
        (exactCanonicalRef.length === 0 ||
          canonicalSourceRef(run) === exactCanonicalRef) &&
        matchesStatus(run, status),
    )
    .map(({ run }) => linkRun(run));
  const listHref = workflowListHref(selectedWorkflowId);

  return {
    kind: "run-list",
    shell: previewShell,
    repository: previewRepository,
    heading: "Workflow runs",
    summary: "Recent workflow activity for automata-ci/automata.",
    filters: {
      action: listHref,
      branch,
      status,
      clearHref: listHref,
    },
    workflowNavigation: {
      selectedWorkflow:
        previewWorkflows.find((workflow) => workflow.id === selectedWorkflowId) ??
        null,
      workflows: previewWorkflows,
      pagination: {
        previousHref: null,
        nextHref: null,
        label: `${previewWorkflows.length} workflows`,
      },
    },
    runs: visibleRuns,
    pagination: {
      previousHref: null,
      nextHref: null,
      label: `${visibleRuns.length} workflow ${visibleRuns.length === 1 ? "run" : "runs"}`,
    },
  };
}

export function isPreviewRunListStateSupported(
  searchParameters: URLSearchParams,
): boolean {
  if (
    !hasOnlyUniqueKeys(searchParameters, RUN_LIST_KEYS) ||
    !isBoundedBranchValue(searchParameters.get("branch"))
  ) {
    return false;
  }
  const workflow = searchParameters.get("workflow");
  const status = searchParameters.get("status");
  return (
    (workflow === null ||
      previewWorkflows.some(({ id }) => id === workflow)) &&
    (status === null || isRunStatusFilter(status))
  );
}

export function isPreviewRunDetailStateSupported(
  searchParameters: URLSearchParams,
): boolean {
  return hasOnlyUniqueKeys(searchParameters, RUN_DETAIL_KEYS);
}

export function isPreviewJobLogStateSupported(
  searchParameters: URLSearchParams,
): boolean {
  return hasOnlyUniqueKeys(searchParameters, JOB_LOG_KEYS);
}

export function isPreviewRepositorySettingsStateSupported(
  searchParameters: URLSearchParams,
): boolean {
  return hasOnlyUniqueKeys(searchParameters, VIEW_ONLY_KEYS);
}

export function isPreviewRepositorySecretsStateSupported(
  searchParameters: URLSearchParams,
): boolean {
  return hasOnlyUniqueKeys(searchParameters, VIEW_ONLY_KEYS);
}

export function previewRepositorySettings(): RepositorySettingsPageModel {
  return {
    kind: "repository-settings",
    shell: {
      ...previewShell,
      documentTitle: "Repository access settings · Automata",
      description:
        "Review access defaults for new workflow runs and their output.",
    },
    repository: {
      ...previewRepository,
      settingsHref: "?view=settings",
    },
    heading: "Repository access",
    summary:
      "Choose who can view new workflow runs and their output in automata-ci/automata.",
    settingsNavigation: {
      accessHref: "?view=settings",
      secretsHref: "?view=secrets",
      current: "access",
    },
    revision: "7",
    policy: {
      dashboard: "public",
      logs: "authenticated",
      artifacts: "private",
    },
    update: null,
  };
}

/** Read-only metadata preview: sample plaintext and mutation authority do not exist. */
export function previewRepositorySecrets(): RepositorySecretsPageModel {
  return {
    kind: "repository-secrets",
    shell: {
      ...previewShell,
      documentTitle: "Repository secrets · Automata",
      description: "Review value-free repository secret metadata.",
    },
    repository: {
      ...previewRepository,
      settingsHref: "?view=settings",
    },
    heading: "Repository secrets",
    summary:
      "Review encrypted secret metadata stored for automata-ci/automata.",
    settingsNavigation: {
      accessHref: "?view=settings",
      secretsHref: "?view=secrets",
      current: "secrets",
    },
    notice: null,
    maximumValueBytes: 65_536,
    provider: {
      id: "builtin",
      state: "active",
      health: "healthy",
      activation: null,
    },
    create: null,
    secrets: [
      {
        id: "77777777-7777-4777-8777-777777777777",
        name: "DEPLOY_TOKEN",
        providerId: "builtin",
        state: "active",
        currentVersion: "2",
        revision: "5",
        updatedAt: {
          iso: "2026-08-08T09:30:00Z",
          label: "8 Aug 2026, 09:30 UTC",
        },
        replace: null,
        delete: null,
      },
      {
        id: "88888888-8888-4888-8888-888888888888",
        name: "PACKAGE_SIGNING_KEY",
        providerId: "builtin",
        state: "disabled",
        currentVersion: "1",
        revision: "3",
        updatedAt: {
          iso: "2026-08-07T18:05:00Z",
          label: "7 Aug 2026, 18:05 UTC",
        },
        replace: null,
        delete: null,
      },
    ],
    pagination: {
      firstHref: null,
      nextHref: null,
      label: "2 secrets",
    },
  };
}

export function previewRunDetail(
  requestedRunId: string | null = null,
): RunDetailPageModel | null {
  const sample = selectRunSample(requestedRunId);
  return sample === undefined ? null : projectRunDetail(sample);
}

export function previewJobLog(
  requestedRunId: string | null = null,
  requestedJobId: string | null = null,
): JobLogPageModel | null {
  const sample = selectRunSample(requestedRunId);
  if (sample === undefined) {
    return null;
  }

  const routeRunId = sample.run.id;
  const selectedJobSample = selectJobSample(sample, requestedJobId);
  if (selectedJobSample === undefined) {
    return null;
  }

  const linkedJobs = sample.jobs.items.map(({ job }) =>
    linkJob(job, routeRunId),
  );
  const selectedJob = linkedJobs.find(
    (job) => job.id === selectedJobSample.job.id,
  );
  if (selectedJob === undefined) {
    return null;
  }

  const jobHref = jobLink(routeRunId, selectedJob.id);

  return {
    kind: "job-log",
    shell: {
      ...previewShell,
      documentTitle: `${selectedJob.name} logs · Automata`,
    },
    repository: previewRepository,
    run: {
      number: sample.run.number,
      name: sample.run.name,
      href: runLink(routeRunId),
      workflowName: sample.run.workflowName,
      workflowHref: sample.run.workflowHref,
      attempt: 1,
    },
    jobs: linkedJobs.map((job) => ({
      id: job.id,
      name: job.name,
      href: job.href,
      status: job.status,
    })),
    navigationPagination: {
      previousHref: null,
      nextHref: null,
      label: `${linkedJobs.length} jobs`,
    },
    job: {
      id: selectedJob.id,
      name: selectedJob.name,
      href: jobHref,
      attempt: 1,
      runnerLabel: selectedJob.runnerLabel,
      status: selectedJob.status,
      startedAt: selectedJob.startedAt,
      durationLabel: selectedJob.durationLabel,
    },
    logVisibility: "full",
    live: null,
    notice: selectedJob.startedAt === null ? logNotice(selectedJob) : null,
  };
}

export function previewJobLogRecords(
  requestedRunId: string | null = null,
  requestedJobId: string | null = null,
): readonly LiveLogRecord[] {
  const sample = selectRunSample(requestedRunId);
  return sample === undefined
    ? []
    : (selectJobSample(sample, requestedJobId)?.logRecords ?? []);
}

function hasOnlyUniqueKeys(
  searchParameters: URLSearchParams,
  allowedKeys: ReadonlySet<string>,
): boolean {
  const seen = new Set<string>();
  for (const key of searchParameters.keys()) {
    if (!allowedKeys.has(key) || seen.has(key)) {
      return false;
    }
    seen.add(key);
  }
  return true;
}

function isBoundedQueryValue(value: string | null): boolean {
  const trimmed = value?.trim() ?? "";
  return (
    value === null ||
    (utf8ByteLength(value) <= RENDER_REQUEST_LIMITS.shortTextLength &&
      !hasForbiddenDisplayCharacter(value) &&
      (trimmed.length === 0 || hasVisibleDisplayCharacter(trimmed)))
  );
}

function isBoundedBranchValue(value: string | null): boolean {
  if (!isBoundedQueryValue(value)) {
    return false;
  }
  const trimmed = value?.trim() ?? "";
  if (trimmed.length === 0) {
    return true;
  }
  const canonical = trimmed.startsWith(REF_PREFIX)
    ? trimmed
    : `${HEAD_REF_PREFIX}${trimmed}`;
  return utf8ByteLength(canonical) <= RENDER_REQUEST_LIMITS.shortTextLength;
}

function canonicalSourceRef(run: PreviewRunSample["run"]): string | null {
  const sourceRef = run.sourceRef;
  if (sourceRef === null) {
    return null;
  }
  switch (sourceRef.kind) {
    case "branch":
      return `${HEAD_REF_PREFIX}${sourceRef.name}`;
    case "tag":
      return `${TAG_REF_PREFIX}${sourceRef.name}`;
    case "ref":
      return `${REF_PREFIX}${sourceRef.name}`;
  }
}

function projectRunDetail(sample: PreviewRunSample): RunDetailPageModel {
  const routeRunId = sample.run.id;
  return {
    kind: "run-detail",
    shell: {
      ...previewShell,
      documentTitle: `${sample.run.name} · Automata`,
    },
    repository: previewRepository,
    run: {
      number: sample.run.number,
      name: sample.run.name,
      workflowName: sample.run.workflowName,
      workflowHref: sample.run.workflowHref,
      status: sample.run.status,
      priority: { level: 0, label: "Normal", mergeQueueManaged: false },
      sourceRef: sample.run.sourceRef,
      event: sample.run.event,
      actor: sample.run.actor,
      commit: sample.run.commit,
      createdAt: sample.run.createdAt,
      durationLabel: sample.run.durationLabel,
      attempt: 1,
    },
    jobs: {
      visibility: sample.jobs.visibility,
      items: sample.jobs.items.map(({ job }) => linkJob(job, routeRunId)),
    },
    jobPagination: {
      previousHref: null,
      nextHref: null,
      label: `${sample.jobs.items.length} jobs`,
    },
    artifacts: sample.artifacts,
    priorityUpdate: null,
    rerun: null,
  };
}

function linkRun(run: PreviewRunSample["run"]): RunListItemModel {
  return { ...run, href: runLink(run.id) };
}

function linkJob(job: PreviewJobSample["job"], routeRunId: string): JobModel {
  return { ...job, href: jobLink(routeRunId, job.id) };
}

function selectRunSample(
  requestedRunId: string | null,
): PreviewRunSample | undefined {
  return requestedRunId === null
    ? previewRunSamples[0]
    : previewRunSamples.find((sample) => sample.run.id === requestedRunId);
}

function selectJobSample(
  sample: PreviewRunSample,
  requestedJobId: string | null,
): PreviewJobSample | undefined {
  return requestedJobId === null
    ? sample.jobs.items[0]
    : sample.jobs.items.find(({ job }) => job.id === requestedJobId);
}

function selectedWorkflow(requestedWorkflowId: string | null): string | null {
  return previewWorkflows.some(
    (workflow) => workflow.id === requestedWorkflowId,
  )
    ? requestedWorkflowId
    : null;
}

function selectedStatus(requestedStatus: string | null): RunStatusFilter {
  return isRunStatusFilter(requestedStatus) ? requestedStatus : "all";
}

function matchesStatus(
  run: PreviewRunSample["run"],
  status: RunStatusFilter,
): boolean {
  if (status === "queued") {
    return run.status.tone === "queued";
  }
  if (status === "in_progress") {
    return run.status.tone === "running";
  }
  if (status === "completed") {
    return ["success", "failure", "warning", "neutral"].includes(
      run.status.tone,
    );
  }
  return true;
}

function logNotice(job: JobModel): string {
  if (job.status.tone === "queued") {
    return "This job has not started, so no log output is available yet.";
  }
  if (job.status.tone === "running") {
    return "No log output has been recorded yet.";
  }
  return "No log output was recorded for this job.";
}

function workflowListHref(workflowId: string | null): string {
  return workflowId === null
    ? "?view=runs"
    : `?view=runs&workflow=${encodeURIComponent(workflowId)}`;
}

function runLink(routeRunId: string): string {
  return `?view=run&run=${encodeURIComponent(routeRunId)}`;
}

function jobLink(routeRunId: string, jobId: string): string {
  return `?view=job&run=${encodeURIComponent(routeRunId)}&job=${encodeURIComponent(jobId)}`;
}
