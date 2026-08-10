import { describe, expect, it } from "vitest";
import {
  isPreviewJobLogStateSupported,
  isPreviewRepositorySettingsStateSupported,
  isPreviewRunDetailStateSupported,
  isPreviewRunListStateSupported,
  previewJobLog,
  previewRepositoryDirectory,
  previewRepositorySettings,
  previewRunDetail,
  previewRunList,
} from "../../src/preview/models";
import {
  previewRepository,
  previewRunSamples,
  previewShell,
  previewWorkflows,
} from "../../src/preview/sampleData";
import {
  PREVIEW_DIRECT_BINDING_ID,
  previewDirectBindings,
  previewRbacPage,
  previewRoleDetail,
  previewUserDetail,
} from "../../src/preview/rbacModels";

const REAL_COMMIT_AUTHORED_AT = new Map<string, string>([
  [
    "https://github.com/automata-ci/automata/commit/26713a895eb6744012da74726e59230a259357c4",
    "2026-08-07T23:27:26Z",
  ],
  [
    "https://github.com/automata-ci/automata/commit/3278d9e87d30ca91c5ec19bcef01cec33aa4182e",
    "2026-08-07T22:51:09Z",
  ],
  [
    "https://github.com/automata-ci/automata/commit/1923ba3a2ab7c8596edad1ae1aa9641b9b4a15cd",
    "2026-08-06T23:26:00Z",
  ],
]);

describe("preview model projections", () => {
  it("projects an honest repository directory and its empty state", () => {
    const directory = previewRepositoryDirectory();
    expect(directory.kind).toBe("repository-directory");
    expect(directory.repositories).toEqual([
      {
        owner: previewRepository.owner,
        name: previewRepository.name,
        sourceHref: previewRepository.sourceHref,
        actionsHref: previewRepository.runsHref,
        settingsHref: previewRepository.settingsHref,
      },
    ]);
    expect(directory.pagination.label).toBe("1 repository on this page");
    expect(previewRepositoryDirectory(true).repositories).toEqual([]);
  });
  it("keeps list, run, job, and workflow routes mutually consistent", () => {
    const runIds = new Set<string>();

    for (const sample of previewRunSamples) {
      expect(runIds.has(sample.run.id)).toBe(false);
      runIds.add(sample.run.id);
      expect("href" in sample.run).toBe(false);

      const detail = previewRunDetail(sample.run.id);
      expect(detail).not.toBeNull();
      if (detail === null) {
        continue;
      }
      expect(detail.run.workflowHref).toBe(sample.run.workflowHref);
      expect(detail.run.actor).toBeNull();
      expect(
        detail.artifacts.items.every(
          (artifact) => artifact.downloadHref === null,
        ),
      ).toBe(true);
      expect(detail.jobs.visibility).toBe(sample.jobs.visibility);
      expect(detail.artifacts.visibility).toBe(sample.artifacts.visibility);

      for (const { job, logLines } of sample.jobs.items) {
        expect("href" in job).toBe(false);
        const expectedJobHref = `?view=job&run=${sample.run.id}&job=${job.id}`;
        expect(detail.jobs.items.find(({ id }) => id === job.id)?.href).toBe(
          expectedJobHref,
        );

        const log = previewJobLog(sample.run.id, job.id);
        expect(log).not.toBeNull();
        if (log === null) {
          continue;
        }
        expect(log.run.href).toBe(`?view=run&run=${sample.run.id}`);
        expect(log.job.href).toBe(expectedJobHref);
        expect(log.lines).toEqual(logLines);
        expect(new Set(log.lines.map(({ id }) => id)).size).toBe(
          log.lines.length,
        );
        expect(
          log.lines.every(({ timestamp }) =>
            /^\d{2}:\d{2}:\d{2}$/u.test(timestamp.label),
          ),
        ).toBe(true);
        for (let index = 1; index < log.lines.length; index += 1) {
          expect(Date.parse(log.lines[index]?.timestamp.iso ?? "")).toBeGreaterThan(
            Date.parse(log.lines[index - 1]?.timestamp.iso ?? ""),
          );
        }
      }
    }

    expect(previewRunDetail("missing")).toBeNull();
    expect(previewJobLog("missing", "job-1")).toBeNull();
    expect(
      previewJobLog(previewRunSamples[0]?.run.id ?? "", "missing"),
    ).toBeNull();

    const restricted = previewRunSamples.find(
      ({ jobs, artifacts }) =>
        jobs.visibility === "restricted" &&
        jobs.items.length > 0 &&
        artifacts.visibility === "restricted" &&
        artifacts.items.length > 0,
    );
    expect(restricted).toBeDefined();
    expect(
      restricted?.artifacts.items.some(
        (artifact) => artifact.downloadHref === null,
      ),
    ).toBe(true);
  });

  it("projects functional workflow, status, branch, and log-search state", () => {
    expect(
      isPreviewRunListStateSupported(
        new URLSearchParams("workflow=release&status=completed"),
      ),
    ).toBe(true);
    expect(
      isPreviewRunListStateSupported(new URLSearchParams("workflow=missing")),
    ).toBe(false);
    expect(
      isPreviewRunListStateSupported(new URLSearchParams("status=missing")),
    ).toBe(false);
    expect(
      isPreviewRunListStateSupported(
        new URLSearchParams(`branch=${"é".repeat(513)}`),
      ),
    ).toBe(false);
    expect(
      isPreviewRunListStateSupported(
        new URLSearchParams(`branch=${"x".repeat(1_013)}`),
      ),
    ).toBe(true);
    expect(
      isPreviewRunListStateSupported(
        new URLSearchParams(`branch=${"x".repeat(1_014)}`),
      ),
    ).toBe(false);
    expect(
      isPreviewRunListStateSupported(new URLSearchParams("branch=%E2%80%8B")),
    ).toBe(false);
    expect(
      isPreviewRunListStateSupported(
        new URLSearchParams("view=runs&branch=main&branch=release"),
      ),
    ).toBe(false);
    expect(
      isPreviewRunListStateSupported(new URLSearchParams("view=runs&unused=1")),
    ).toBe(false);
    expect(
      isPreviewRunDetailStateSupported(new URLSearchParams("view=run&run=known")),
    ).toBe(true);
    expect(
      isPreviewRunDetailStateSupported(
        new URLSearchParams("view=run&run=known&status=completed"),
      ),
    ).toBe(false);
    expect(
      isPreviewJobLogStateSupported(
        new URLSearchParams("view=job&run=known&job=job-1&q=build"),
      ),
    ).toBe(true);
    expect(
      isPreviewJobLogStateSupported(
        new URLSearchParams("view=job&run=known&job=job-1&q=line%0Abreak"),
      ),
    ).toBe(false);
    expect(
      isPreviewJobLogStateSupported(
        new URLSearchParams("view=job&run=known&job=job-1&q=%E2%80%8B"),
      ),
    ).toBe(false);
    expect(
      isPreviewJobLogStateSupported(
        new URLSearchParams("view=job&run=known&job=job-1&q=build%E2%80%AE"),
      ),
    ).toBe(false);
    expect(
      isPreviewRepositorySettingsStateSupported(
        new URLSearchParams("view=settings"),
      ),
    ).toBe(true);
    expect(
      isPreviewRepositorySettingsStateSupported(
        new URLSearchParams("view=settings&notice=saved"),
      ),
    ).toBe(false);
    expect(
      isPreviewRepositorySettingsStateSupported(
        new URLSearchParams("view=settings&revision=7"),
      ),
    ).toBe(false);
    const release = previewRunList(
      new URLSearchParams("view=runs&workflow=release&status=completed"),
    );
    expect(release.workflowNavigation?.selectedWorkflow?.id).toBe("release");
    expect(release.runs.map(({ workflowName }) => workflowName)).toEqual([
      "Release",
    ]);
    expect(
      release.runs.every(
        ({ workflowHref }) => workflowHref === "?view=runs&workflow=release",
      ),
    ).toBe(true);

    const runningMain = previewRunList(
      new URLSearchParams("view=runs&branch=main&status=in_progress"),
    );
    expect(runningMain.runs).toHaveLength(1);
    expect(runningMain.runs[0]?.sourceRef?.name).toBe("main");
    expect(
      previewRunList(
        new URLSearchParams("view=runs&branch=refs%2Fheads%2Fmain&status=in_progress"),
      ).runs,
    ).toHaveLength(1);
    expect(
      previewRunList(
        new URLSearchParams("view=runs&branch=MAIN&status=in_progress"),
      ).runs,
    ).toHaveLength(0);
    expect(
      previewRunList(
        new URLSearchParams("view=runs&branch=ma&status=in_progress"),
      ).runs,
    ).toHaveLength(0);
    expect(
      previewRunList(
        new URLSearchParams("view=runs&branch=mainline&status=in_progress"),
      ).runs,
    ).toHaveLength(0);

    const firstSample = previewRunSamples[0];
    const firstJob = firstSample?.jobs.items[0];
    expect(firstSample).toBeDefined();
    expect(firstJob).toBeDefined();
    if (firstSample === undefined || firstJob === undefined) {
      return;
    }
    const searched = previewJobLog(
      firstSample.run.id,
      firstJob.job.id,
      new URLSearchParams("q=Operating%20System"),
    );
    expect(searched?.search.query).toBe("Operating System");
    expect(searched?.lines).toHaveLength(firstJob.logLines.length);
    expect(searched?.pagination.label).toBe(
      `${firstJob.logLines.length} log ${
        firstJob.logLines.length === 1 ? "line" : "lines"
      }`,
    );
  });

  it("keeps the repository settings preview read-only and token-free", () => {
    const settings = previewRepositorySettings();

    expect(previewShell.viewer).toEqual({ displayName: "Ada" });
    expect(previewShell.signIn).toBeNull();
    expect(previewShell.signOut).toBeNull();
    expect(settings.repository.settingsHref).toBe("?view=settings");
    expect(settings.revision).toBe("7");
    expect(settings.policy).toEqual({
      dashboard: "public",
      logs: "authenticated",
      artifacts: "private",
    });
    expect(settings.update).toBeNull();
    expect(JSON.stringify(settings)).not.toContain("csrf");
  });

  it("keeps access-management previews read-only, token-free, and query-local", () => {
    const pages = [
      previewRbacPage("users", new URLSearchParams("view=users")),
      previewRbacPage(
        "user",
        new URLSearchParams("view=user&user=ada-lovelace"),
      ),
      previewRbacPage("roles", new URLSearchParams("view=roles")),
      previewRbacPage(
        "role",
        new URLSearchParams("view=role&role=release-reviewer"),
      ),
      previewRbacPage("bindings", new URLSearchParams("view=bindings")),
    ];

    expect(pages.map((page) => page?.kind)).toEqual([
      "user-list",
      "user-detail",
      "role-list",
      "role-detail",
      "direct-binding-list",
    ]);
    for (const page of pages) {
      expect(page).not.toBeNull();
      expect(page?.shell.homeHref).toBe("?view=repositories");
      expect(page?.shell.navigation).toEqual([
        { label: "Repositories", href: "?view=repositories" },
        { label: "Access", href: "?view=users", current: true },
      ]);
      expect(JSON.stringify(page)).not.toContain("csrf");
    }

    const user = pages[1];
    expect(user?.kind === "user-detail" ? user.statusUpdate : undefined).toBeNull();
    const roles = pages[2];
    expect(roles?.kind === "role-list" ? roles.create : undefined).toBeNull();
    const role = pages[3];
    expect(role?.kind === "role-detail" ? role.update : undefined).toBeNull();
    expect(role?.kind === "role-detail" ? role.delete : undefined).toBeNull();
    expect(role?.kind === "role-detail"
      ? role.permissions.every((permission) => permission.update === null)
      : false).toBe(true);
    const bindings = pages[4];
    expect(
      bindings?.kind === "direct-binding-list" ? bindings.grant : undefined,
    ).toBeNull();
    expect(
      bindings?.kind === "direct-binding-list"
        ? bindings.readOnlyReason
        : undefined,
    ).toBe("not-authorized");
    expect(
      bindings?.kind === "direct-binding-list"
        ? bindings.bindings.map((binding) => binding.revoke !== null)
        : null,
    ).toEqual([false, false]);

    expect(
      previewRbacPage(
        "users",
        new URLSearchParams("view=users&cursor=unsupported"),
      ),
    ).toBeNull();
    expect(
      previewRbacPage(
        "user",
        new URLSearchParams("view=user&user=missing"),
      ),
    ).toBeNull();
    expect(
      previewRbacPage(
        "role",
        new URLSearchParams("view=role&role=release-reviewer&role=duplicate"),
      ),
    ).toBeNull();

    const userDetail = previewUserDetail();
    expect(userDetail?.roleAssignments[0]?.bindingHref).toBe(
      "?view=bindings",
    );
    expect(previewUserDetail("missing")).toBeNull();
    expect(previewRoleDetail("missing")).toBeNull();
    expect(
      previewDirectBindings().bindings.map((binding) => binding.id),
    ).toContain(PREVIEW_DIRECT_BINDING_ID);
  });

  it("uses only real SCM destinations and dates samples after their commits", () => {
    expect(previewRepository.sourceHref).toBe(
      "https://github.com/automata-ci/automata",
    );
    expect(previewRepository.settingsHref).toBe("?view=settings");
    expect(previewWorkflows.every(({ href }) => href.startsWith("?view=runs"))).toBe(
      true,
    );

    for (const { run } of previewRunSamples) {
      expect(run.actor).toBeNull();
      expect(run.sourceRef?.href ?? "https://github.com").toMatch(
        /^https:\/\/github\.com(?:\/automata-ci\/automata\/tree\/main)?$/u,
      );
      const authoredAt = REAL_COMMIT_AUTHORED_AT.get(run.commit.href);
      expect(authoredAt).toBeDefined();
      expect(Date.parse(run.createdAt.iso)).toBeGreaterThan(
        Date.parse(authoredAt ?? ""),
      );
    }
  });
});
