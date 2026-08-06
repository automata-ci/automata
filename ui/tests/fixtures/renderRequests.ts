import type { RenderRequest, ShellModel } from "../../src/models";

const shell: ShellModel = {
  productName: "Automata",
  homeHref: "/",
  signInHref: "/login",
  documentTitle: "Automata dogfood · Automata",
  description: "GitHub Actions-compatible workflow runs",
  viewer: { displayName: "Ada", profileHref: "/users/ada" },
  navigation: [
    { label: "Repositories", href: "/repositories" },
    { label: "Runs", href: "/runs", current: true },
    { label: "Runners", href: "/runners" },
  ],
};

const repository = {
  owner: "automata",
  name: "automata",
  href: "/automata/automata",
  runsHref: "/automata/automata/actions/runs",
} as const;

const common = {
  schemaVersion: 1,
  host: {
    locale: "en",
    assets: {
      clientEntry: "/assets/entry-client-abc123.js",
      stylesheets: ["/assets/entry-client-abc123.css"],
    },
  },
} as const;

export const runListRequest: RenderRequest = {
  ...common,
  page: {
    kind: "run-list",
    shell,
    repository,
    heading: "Workflow runs",
    summary: "CI runs for automata/automata, including the first dogfood build.",
    filters: {
      action: repository.runsHref,
      status: "all",
      branch: "main",
      statusOptions: [
        { value: "all", label: "All statuses" },
        { value: "in_progress", label: "In progress" },
        { value: "completed", label: "Completed" },
      ],
      clearHref: repository.runsHref,
    },
    runs: [
      {
        id: "1842",
        name: "Dogfood Automata <generation G1>",
        workflowName: "CI",
        href: "/automata/automata/actions/runs/1842",
        status: { label: "In progress", tone: "running" },
        branch: "main",
        event: "push",
        actor: "ada<script>alert(1)</script>",
        commit: {
          shortSha: "f35c0de",
          message: "Run Automata's own CI",
          href: "/automata/automata/commit/f35c0de",
        },
        startedAt: { iso: "2026-08-06T08:15:00Z", label: "6 Aug 2026, 08:15 UTC" },
        durationLabel: "3m 18s",
      },
      {
        id: "1841",
        name: "Compatibility corpus",
        workflowName: "CI",
        href: "/automata/automata/actions/runs/1841",
        status: { label: "Succeeded", tone: "success" },
        branch: "feature/parser",
        event: "pull_request",
        actor: "grace",
        commit: {
          shortSha: "ab12cd3",
          message: "Validate workflow syntax",
          href: "/automata/automata/commit/ab12cd3",
        },
        startedAt: { iso: "2026-08-06T07:44:00Z", label: "6 Aug 2026, 07:44 UTC" },
        durationLabel: "8m 02s",
      },
    ],
    pagination: { previousHref: null, nextHref: "?page=2", label: "2 of 38 runs" },
  },
};

export const runDetailRequest: RenderRequest = {
  ...common,
  host: { ...common.host, cspNonce: "nonce-value" },
  page: {
    kind: "run-detail",
    shell,
    repository,
    csrfToken: "csrf<&token",
    operations: [
      {
        label: "Cancel run",
        action: "/automata/automata/actions/runs/1842/cancel",
        style: "danger",
        confirmation: "Cancel this workflow run?",
      },
      {
        label: "Re-run jobs",
        action: "/automata/automata/actions/runs/1842/rerun",
        style: "secondary",
      },
    ],
    run: {
      id: "1842",
      name: "Dogfood Automata generation G1",
      workflowName: "CI",
      workflowHref: "/automata/automata/actions/workflows/ci.yml",
      status: { label: "In progress", tone: "running" },
      branch: "main",
      branchHref: "/automata/automata/tree/main",
      event: "push",
      actor: "ada",
      commit: {
        shortSha: "f35c0de",
        message: "Run Automata's own CI",
        href: "/automata/automata/commit/f35c0de",
      },
      createdAt: { iso: "2026-08-06T08:15:00Z", label: "6 Aug 2026, 08:15 UTC" },
      durationLabel: "3m 18s",
      attempt: 1,
    },
    jobs: [
      {
        id: "job-1",
        name: "Static Linux build",
        href: "/automata/automata/actions/runs/1842/jobs/job-1",
        runnerLabel: "ubuntu-24.04",
        status: { label: "In progress", tone: "running" },
        startedAt: { iso: "2026-08-06T08:15:05Z", label: "6 Aug 2026, 08:15 UTC" },
        durationLabel: "3m 13s",
        steps: [
          {
            number: 1,
            name: "Set up job",
            status: { label: "Succeeded", tone: "success" },
            durationLabel: "4s",
            logHref: "/automata/automata/actions/runs/1842/jobs/job-1#step-1",
          },
          {
            number: 2,
            name: "Build automata",
            status: { label: "In progress", tone: "running" },
            durationLabel: "3m 09s",
            logHref: "/automata/automata/actions/runs/1842/jobs/job-1#step-2",
          },
        ],
      },
    ],
    artifacts: [
      {
        id: "artifact-1",
        name: "automata-x86_64-unknown-linux-musl",
        sizeLabel: "18.4 MB",
        digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        downloadHref: "/automata/automata/actions/runs/1842/artifacts/artifact-1",
        expiresAt: { iso: "2026-11-04T08:15:00Z", label: "4 Nov 2026" },
      },
    ],
  },
};
