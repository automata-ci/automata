import type {
  ArtifactModel,
  JobLogLineModel,
  JobModel,
  RepositoryModel,
  ResultCollectionModel,
  RunListItemModel,
  ShellModel,
  WorkflowNavigationItemModel,
} from "../models";

export const PREVIEW_PRIMARY_RUN_ID = "run-a4f69c2e";
export const PREVIEW_SECONDARY_RUN_ID = "run-b6d8120f";
export const PREVIEW_FAILED_RUN_ID = "run-d2a78f31";
export const PREVIEW_QUEUED_RUN_ID = "run-e803bc65";

const SOURCE_REPOSITORY_HREF = "https://github.com/automata-ci/automata";
const MAIN_SOURCE_REF = {
  name: "main",
  kind: "branch",
  href: `${SOURCE_REPOSITORY_HREF}/tree/main`,
} as const;
const CURRENT_COMMIT = "26713a895eb6744012da74726e59230a259357c4";
const DURABLE_EXECUTION_COMMIT = "3278d9e87d30ca91c5ec19bcef01cec33aa4182e";
const FOUNDATION_COMMIT = "1923ba3a2ab7c8596edad1ae1aa9641b9b4a15cd";

export interface PreviewJobSample {
  readonly job: Omit<JobModel, "href">;
  readonly logLines: readonly JobLogLineModel[];
}

export interface PreviewRunSample {
  readonly run: Omit<RunListItemModel, "href">;
  readonly jobs: ResultCollectionModel<PreviewJobSample>;
  readonly artifacts: ResultCollectionModel<ArtifactModel>;
}

export const previewShell: ShellModel = {
  productName: "Automata",
  homeHref: "?view=repositories",
  signIn: null,
  signOut: null,
  documentTitle: "Workflow runs · Automata",
  description: "Recent workflow activity for automata-ci/automata",
  viewer: { displayName: "Ada" },
  navigation: [
    { label: "Repositories", href: "?view=repositories" },
    { label: "Actions", href: "?view=runs", current: true },
    { label: "Access", href: "?view=users" },
  ],
};

export const previewRepository: RepositoryModel = {
  owner: "automata-ci",
  name: "automata",
  sourceHref: SOURCE_REPOSITORY_HREF,
  runsHref: "?view=runs",
  settingsHref: "?view=settings",
};

export const previewWorkflows: readonly WorkflowNavigationItemModel[] = [
  { id: "ci", name: "CI", href: "?view=runs&workflow=ci", enabled: true },
  {
    id: "release",
    name: "Release",
    href: "?view=runs&workflow=release",
    enabled: true,
  },
  {
    id: "nightly",
    name: "Nightly",
    href: "?view=runs&workflow=nightly",
    enabled: false,
  },
];

export const previewRunSamples: readonly PreviewRunSample[] = [
  {
    run: {
      id: PREVIEW_PRIMARY_RUN_ID,
      number: "1842",
      name: "Build and test release candidate",
      workflowName: "CI",
      workflowHref: "?view=runs&workflow=ci",
      status: { label: "In progress", tone: "running" },
      sourceRef: MAIN_SOURCE_REF,
      event: "push",
      actor: null,
      commit: {
        shortSha: CURRENT_COMMIT.slice(0, 7),
        message: "Make macro diagnostics cache-independent",
        href: `${SOURCE_REPOSITORY_HREF}/commit/${CURRENT_COMMIT}`,
      },
      createdAt: {
        iso: "2026-08-08T08:15:00Z",
        label: "8 Aug 2026, 08:15 UTC",
      },
      durationLabel: "3m 18s",
    },
    jobs: {
      visibility: "full",
      items: [
        jobSample({
          id: "job-1",
          name: "Linux release build",
          runnerLabel: null,
          status: { label: "In progress", tone: "running" },
          startedAt: {
            iso: "2026-08-08T08:15:05Z",
            label: "8 Aug 2026, 08:15 UTC",
          },
          durationLabel: "3m 13s",
        }),
        jobSample({
          id: "job-2",
          name: "Workspace tests",
          runnerLabel: "ubuntu-24.04",
          status: { label: "Succeeded", tone: "success" },
          startedAt: {
            iso: "2026-08-08T08:15:08Z",
            label: "8 Aug 2026, 08:15 UTC",
          },
          durationLabel: "2m 47s",
        }),
        jobSample({
          id: "job-3",
          name: "Package artifacts",
          runnerLabel: null,
          status: { label: "Queued", tone: "queued" },
          startedAt: null,
          durationLabel: null,
        }),
      ],
    },
    artifacts: {
      visibility: "full",
      items: [
        artifact(
          "artifact-1",
          "workspace-test-results",
          "2.8 MB",
          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ),
      ],
    },
  },
  {
    run: {
      id: PREVIEW_SECONDARY_RUN_ID,
      number: "1841",
      name: "Workflow compatibility suite",
      workflowName: "CI",
      workflowHref: "?view=runs&workflow=ci",
      status: { label: "Succeeded", tone: "success" },
      sourceRef: null,
      event: "pull_request",
      actor: null,
      commit: {
        shortSha: DURABLE_EXECUTION_COMMIT.slice(0, 7),
        message: null,
        href: `${SOURCE_REPOSITORY_HREF}/commit/${DURABLE_EXECUTION_COMMIT}`,
      },
      createdAt: {
        iso: "2026-08-08T07:44:00Z",
        label: "8 Aug 2026, 07:44 UTC",
      },
      durationLabel: "8m 02s",
    },
    jobs: {
      visibility: "full",
      items: [
        jobSample({
          id: "job-1",
          name: "Validate workflow syntax",
          runnerLabel: null,
          status: { label: "Succeeded", tone: "success" },
          startedAt: {
            iso: "2026-08-08T07:44:04Z",
            label: "8 Aug 2026, 07:44 UTC",
          },
          durationLabel: "1m 12s",
        }),
        jobSample({
          id: "job-2",
          name: "Run compatibility matrix",
          runnerLabel: null,
          status: { label: "Succeeded", tone: "success" },
          startedAt: {
            iso: "2026-08-08T07:45:18Z",
            label: "8 Aug 2026, 07:45 UTC",
          },
          durationLabel: "6m 28s",
        }),
      ],
    },
    artifacts: {
      visibility: "full",
      items: [
        artifact(
          "artifact-1",
          "compatibility-report",
          "684 KB",
          "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
        ),
      ],
    },
  },
  {
    run: {
      id: "run-c91e44ad",
      number: "1840",
      name: "Publish release artifacts",
      workflowName: "Release",
      workflowHref: "?view=runs&workflow=release",
      status: { label: "Succeeded", tone: "success" },
      sourceRef: MAIN_SOURCE_REF,
      event: "push",
      actor: null,
      commit: {
        shortSha: FOUNDATION_COMMIT.slice(0, 7),
        message: "Initial Automata foundation",
        href: `${SOURCE_REPOSITORY_HREF}/commit/${FOUNDATION_COMMIT}`,
      },
      createdAt: {
        iso: "2026-08-08T06:58:00Z",
        label: "8 Aug 2026, 06:58 UTC",
      },
      durationLabel: "5m 41s",
    },
    jobs: {
      visibility: "full",
      items: [
        jobSample({
          id: "job-1",
          name: "Build release packages",
          runnerLabel: "ubuntu-24.04",
          status: { label: "Succeeded", tone: "success" },
          startedAt: {
            iso: "2026-08-08T06:58:04Z",
            label: "8 Aug 2026, 06:58 UTC",
          },
          durationLabel: "4m 53s",
        }),
        jobSample({
          id: "job-2",
          name: "Publish GitHub release",
          runnerLabel: "ubuntu-24.04",
          status: { label: "Succeeded", tone: "success" },
          startedAt: {
            iso: "2026-08-08T07:02:58Z",
            label: "8 Aug 2026, 07:02 UTC",
          },
          durationLabel: "39s",
        }),
      ],
    },
    artifacts: {
      visibility: "full",
      items: [
        artifact(
          "artifact-1",
          "automata-x86_64-unknown-linux-musl",
          "18.4 MB",
          "23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
        ),
      ],
    },
  },
  {
    run: {
      id: PREVIEW_FAILED_RUN_ID,
      number: "1839",
      name: "Lint and workspace tests",
      workflowName: "CI",
      workflowHref: "?view=runs&workflow=ci",
      status: { label: "Failed", tone: "failure" },
      sourceRef: MAIN_SOURCE_REF,
      event: "pull_request",
      actor: null,
      commit: {
        shortSha: DURABLE_EXECUTION_COMMIT.slice(0, 7),
        message: "Build durable local GitHub Actions execution",
        href: `${SOURCE_REPOSITORY_HREF}/commit/${DURABLE_EXECUTION_COMMIT}`,
      },
      createdAt: {
        iso: "2026-08-08T06:30:00Z",
        label: "8 Aug 2026, 06:30 UTC",
      },
      durationLabel: "2m 19s",
    },
    jobs: {
      visibility: "restricted",
      items: [
        jobSample({
          id: "job-1",
          name: "Lint",
          runnerLabel: "ubuntu-24.04",
          status: { label: "Failed", tone: "failure" },
          startedAt: {
            iso: "2026-08-08T06:30:04Z",
            label: "8 Aug 2026, 06:30 UTC",
          },
          durationLabel: "2m 11s",
        }),
        jobSample({
          id: "job-2",
          name: "Workspace tests",
          runnerLabel: null,
          status: { label: "Skipped", tone: "neutral" },
          startedAt: null,
          durationLabel: null,
        }),
      ],
    },
    artifacts: {
      visibility: "restricted",
      items: [
        artifact(
          "artifact-1",
          "lint-diagnostics",
          "92 KB",
          "3456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012",
        ),
      ],
    },
  },
  {
    run: {
      id: PREVIEW_QUEUED_RUN_ID,
      number: "1838",
      name: "Nightly compatibility suite",
      workflowName: "Nightly",
      workflowHref: "?view=runs&workflow=nightly",
      status: { label: "Queued", tone: "queued" },
      sourceRef: MAIN_SOURCE_REF,
      event: "schedule",
      actor: null,
      commit: {
        shortSha: CURRENT_COMMIT.slice(0, 7),
        message: "Make macro diagnostics cache-independent",
        href: `${SOURCE_REPOSITORY_HREF}/commit/${CURRENT_COMMIT}`,
      },
      createdAt: {
        iso: "2026-08-08T06:02:00Z",
        label: "8 Aug 2026, 06:02 UTC",
      },
      durationLabel: null,
    },
    jobs: {
      visibility: "full",
      items: [
        jobSample({
          id: "job-1",
          name: "Run nightly compatibility matrix",
          runnerLabel: null,
          status: { label: "Queued", tone: "queued" },
          startedAt: null,
          durationLabel: null,
        }),
      ],
    },
    artifacts: { visibility: "full", items: [] },
  },
];

function jobSample(job: Omit<JobModel, "href">): PreviewJobSample {
  return {
    job,
    logLines:
      job.startedAt === null
        ? []
        : createLogLines(job.id, job.name, job.startedAt.iso, job.status.tone),
  };
}

function artifact(
  id: string,
  name: string,
  sizeLabel: string,
  digest: string,
): ArtifactModel {
  return {
    id,
    name,
    sizeLabel,
    digest,
    downloadHref: null,
    expiresAt: null,
  };
}

function createLogLines(
  jobId: string,
  jobName: string,
  startedAtIso: string,
  tone: JobModel["status"]["tone"],
): readonly JobLogLineModel[] {
  const finalChannel = tone === "failure" ? "stderr" : "stdout";
  const outcome =
    tone === "running"
      ? `${jobName} is still running`
      : tone === "failure"
        ? `${jobName} failed`
        : `${jobName} completed successfully`;
  const startTimestamp = logTimestamp(startedAtIso, 0);
  const environmentTimestamp = logTimestamp(startedAtIso, 2);
  const outcomeTimestamp = logTimestamp(startedAtIso, 15);

  return [
    {
      id: `${jobId}-log-0`,
      number: "0",
      timestamp: startTimestamp,
      channel: "system",
      text: `Starting ${jobName}`,
    },
    {
      id: `${jobId}-log-1`,
      number: "1",
      timestamp: environmentTimestamp,
      channel: "stdout",
      text: "Operating System: Ubuntu 24.04.3 LTS",
    },
    {
      id: `${jobId}-log-2-1`,
      number: "2.1",
      timestamp: outcomeTimestamp,
      channel: finalChannel,
      text: outcome,
    },
  ];
}

function logTimestamp(
  startedAtIso: string,
  offsetSeconds: number,
): JobLogLineModel["timestamp"] {
  const startedAtMilliseconds = Date.parse(startedAtIso);
  if (!Number.isFinite(startedAtMilliseconds)) {
    throw new Error("The preview job start timestamp is invalid");
  }
  const iso = new Date(startedAtMilliseconds + offsetSeconds * 1_000)
    .toISOString()
    .replace(/\.000Z$/u, "Z");
  return { iso, label: iso.slice(11, 19) };
}
