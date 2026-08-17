import { act } from "react";
import { hydrateRoot } from "react-dom/client";
import { renderToString } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HtmlDocument } from "../../src/Document";
import { JobLogPage } from "../../src/pages/JobLogPage";
import type { LiveLogRecord } from "../../src/liveLogs";
import { render, renderPage } from "../../src/entry-server";
import type { RenderRequest } from "../../src/models";
import {
  PAGE_MODEL_ELEMENT_ID,
  readRenderRequest,
} from "../../src/serialization";
import {
  deepLinkSignInRequest,
  directBindingListRequest,
  jobLogRequest,
  PRIMARY_RUN_ID,
  RBAC_BINDING_ID,
  RBAC_ROLE_ID,
  RBAC_USER_ID,
  repositoryDirectoryRequest,
  repositorySecretsDirectoryRequest,
  repositorySettingsRequest,
  runnerDirectoryRequest,
  roleDetailRequest,
  roleListRequest,
  runDetailRequest,
  runListRequest,
  SHELL_CSRF_TOKEN,
  userDetailRequest,
  userListRequest,
} from "../fixtures/renderRequests";

describe("server rendering", () => {
  it("renders public runner health without internal runner identities", () => {
    const rendered = new DOMParser().parseFromString(
      renderPage(runnerDirectoryRequest),
      "text/html",
    );

    expect(rendered.title).toBe("Runners · Automata");
    expect(rendered.querySelector("main h1")?.textContent).toBe("Runners");
    expect(rendered.querySelector(".runner-directory__visibility")?.textContent).toContain(
      "Public directory",
    );
    expect(rendered.querySelectorAll(".runner-directory__item")).toHaveLength(2);
    expect(rendered.body.textContent).toContain("linux-01");
    expect(rendered.body.textContent).toContain("1 / 4 busy");
    expect(rendered.body.textContent).toContain("Draining");
    expect(rendered.body.textContent).not.toContain("runnerId");
    expect(rendered.body.textContent).not.toContain("sessionId");
  });

  it("renders the generic deep-link handoff with an exact POST return path", () => {
    const rendered = new DOMParser().parseFromString(
      renderPage(deepLinkSignInRequest),
      "text/html",
    );
    const form = rendered.querySelector('form[action="/auth/github/login"]');
    expect(rendered.body.textContent).toContain("Sign in to view this run");
    expect(form?.getAttribute("method")).toBe("post");
    expect(
      form?.querySelector<HTMLInputElement>('input[name="return_path"]')?.value,
    ).toBe(deepLinkSignInRequest.page.shell.signIn?.returnPath);
  });

  it("renders the repository directory with honest destinations and no repository header", () => {
    const rendered = new DOMParser().parseFromString(
      renderPage(repositoryDirectoryRequest),
      "text/html",
    );

    expect(rendered.title).toBe("Repositories · Automata");
    expect(rendered.querySelector("main")?.getAttribute("tabindex")).toBe("-1");
    expect(rendered.querySelector("main h1")?.textContent).toBe("Repositories");
    expect(rendered.querySelector(".repository-directory__name")?.textContent).toContain(
      "automata-ci/automata",
    );
    expect(
      rendered.querySelector<HTMLAnchorElement>(
        '.repository-directory__destinations a[href="/automata-ci/automata/actions"]',
      ),
    ).not.toBeNull();
    const signIn = rendered.querySelector<HTMLFormElement>(
      '.site-header form[action="/auth/github/login"]',
    );
    expect(signIn?.method).toBe("post");
    expect(
      signIn?.querySelector<HTMLInputElement>('input[name="return_path"]')
        ?.value,
    ).toBe("/repositories");
    expect(signIn?.querySelector("button")?.textContent).toBe("Sign in");
    expect(rendered.querySelector(".theme-toggle")).not.toBeNull();
    expect(rendered.querySelector(".repo-header")).toBeNull();
  });

  it("labels a secrets-only repository destination honestly", () => {
    const rendered = new DOMParser().parseFromString(
      renderPage(repositorySecretsDirectoryRequest),
      "text/html",
    );
    const destinations = rendered.querySelector(".repository-directory__destinations");
    const secrets = destinations?.querySelector<HTMLAnchorElement>(
      'a[href="/automata-ci/automata/settings/secrets"]',
    );

    expect(secrets?.textContent).toContain("Secrets");
    expect(destinations?.textContent).not.toContain("Actions");
    expect(destinations?.textContent).not.toContain("Settings");
  });

  it("labels the repository access destination honestly", () => {
    if (repositorySecretsDirectoryRequest.page.kind !== "repository-directory") {
      throw new Error("The repository-directory fixture is unavailable");
    }
    const request: RenderRequest = {
      ...repositorySecretsDirectoryRequest,
      page: {
        ...repositorySecretsDirectoryRequest.page,
        repositories: repositorySecretsDirectoryRequest.page.repositories.map(
          (repository) => ({
            ...repository,
            settingsHref: "/automata-ci/automata/settings/access",
          }),
        ),
      },
    };
    const rendered = new DOMParser().parseFromString(renderPage(request), "text/html");
    const access = rendered.querySelector<HTMLAnchorElement>(
      '.repository-directory__destinations a[href="/automata-ci/automata/settings/access"]',
    );

    expect(access?.textContent).toContain("Access");
    expect(access?.textContent).not.toContain("Settings");
  });

  it("renders the run list as a complete, useful document", () => {
    const html = renderPage(runListRequest);
    const rendered = new DOMParser().parseFromString(html, "text/html");
    const branchFilter = rendered.querySelector<HTMLInputElement>(
      'input[name="branch"]',
    );

    expect(html).toMatch(/^<!doctype html><html lang="en">/);
    expect(rendered.title).toBe("Workflow runs · Automata");
    expect(html).toContain("Workflow runs");
    expect(html).toContain("Build and test &lt;release candidate&gt;");
    expect(html).toContain(
      `href="/automata-ci/automata/actions/runs/${PRIMARY_RUN_ID}"`,
    );
    expect(html).toContain(
      'href="https://github.com/automata-ci/automata/tree/main"',
    );
    expect(html).toContain(
      'href="https://github.com/automata-ci/automata/commit/26713a895eb6744012da74726e59230a259357c4"',
    );
    expect(html).toContain('action="/automata-ci/automata/actions"');
    expect(html).toContain('name="branch"');
    expect(html).toContain("6 Aug 2026, 08:15 UTC");
    expect(html).toContain('src="/assets/entry-client-abc123.js"');
    expect(html).toContain('href="/assets/entry-client-abc123.css"');
    expect(branchFilter?.getAttribute("autocapitalize")).toBe("none");
    expect(branchFilter?.getAttribute("autocomplete")).toBe("off");
    expect(branchFilter?.getAttribute("autocorrect")).toBe("off");
  });

  it("renders sign-out as a native account disclosure and an exact POST form", () => {
    const rendered = new DOMParser().parseFromString(
      renderPage(runListRequest),
      "text/html",
    );
    const menu = rendered.querySelector<HTMLDetailsElement>(
      "details.viewer-menu",
    );
    const summary = menu?.querySelector<HTMLElement>(
      ":scope > summary.viewer-link",
    );
    const form = menu?.querySelector<HTMLFormElement>(
      'form[action="/auth/logout"]',
    );
    const token = form?.querySelector<HTMLInputElement>(
      'input[name="csrf_token"]',
    );
    const submit = form?.querySelector<HTMLButtonElement>(
      'button[type="submit"]',
    );

    expect(menu?.open).toBe(false);
    expect(summary?.textContent).toContain("Ada");
    expect(summary?.textContent).toContain("account menu");
    expect(summary?.querySelector(".ph-caret-down")).not.toBeNull();
    expect(form?.method).toBe("post");
    expect(token?.type).toBe("hidden");
    expect(token?.value).toBe(SHELL_CSRF_TOKEN);
    expect(submit?.textContent).toBe("Sign out");
    expect(submit?.querySelector(".ph-sign-out")).not.toBeNull();
    expect(menu?.querySelector("[role=menu]")).toBeNull();
    expect(menu?.querySelector("svg")).toBeNull();

    summary?.click();
    expect(menu?.open).toBe(true);
    summary?.click();
    expect(menu?.open).toBe(false);
  });

  it("renders independent, revision-fenced publication settings", () => {
    const rendered = new DOMParser().parseFromString(
      renderPage(repositorySettingsRequest),
      "text/html",
    );
    const form = rendered.querySelector<HTMLFormElement>(
      'form[action="/automata-ci/automata/settings/access"]',
    );

    expect(rendered.title).toBe("Repository access settings · Automata");
    expect(rendered.querySelector("main h1")?.textContent).toBe(
      "Repository access",
    );
    expect(
      rendered.querySelector("main .page-heading p")?.textContent,
    ).toContain("new workflow runs");
    expect(
      rendered.querySelector("#publication-settings-heading")?.textContent,
    ).toBe("Defaults for new runs");
    expect(
      rendered.querySelector("#publication-policy-guidance")?.textContent,
    ).toContain("Existing runs keep their current access");
    expect(rendered.querySelector("main")?.textContent).not.toContain(
      "Version 7",
    );
    expect(rendered.querySelector("main")?.textContent).not.toContain(
      "Policy revision",
    );
    expect(
      rendered.querySelector('.repo-nav a[aria-current="page"]')?.textContent,
    ).toContain("Settings");
    expect(form?.method).toBe("post");
    expect(
      form?.querySelector<HTMLButtonElement>('button[type="submit"]')
        ?.classList,
    ).toContain("button--primary");
    expect(
      form?.querySelector<HTMLButtonElement>('button[type="submit"]')
        ?.classList,
    ).toContain("repository-settings__save");
    expect(
      form?.querySelector<HTMLButtonElement>('button[type="submit"]')
        ?.textContent,
    ).toContain("Save changes");
    expect(
      form?.querySelector<HTMLInputElement>('[name="expected_revision"]')
        ?.value,
    ).toBe("7");
    expect(
      form?.querySelector<HTMLInputElement>('[name="csrf_token"]')?.value,
    ).toBe("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE");
    expect(
      form?.querySelector<HTMLInputElement>(
        '[name="dashboard_audience"][value="public"]',
      )?.checked,
    ).toBe(true);
    expect(
      form?.querySelector<HTMLInputElement>(
        '[name="log_audience"][value="authenticated"]',
      )?.checked,
    ).toBe(true);
    expect(
      form?.querySelector<HTMLInputElement>(
        '[name="artifact_audience"][value="private"]',
      )?.checked,
    ).toBe(true);
    expect(rendered.querySelectorAll("fieldset.audience-setting")).toHaveLength(
      3,
    );
    expect(
      [
        ...rendered.querySelectorAll<HTMLInputElement>(
          ".audience-setting input",
        ),
      ].every((input) => input.required),
    ).toBe(true);
    expect(rendered.querySelector("#main-content")?.textContent).not.toContain(
      "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
    );
  });

  it("renders unavailable settings mutation as semantically read-only", () => {
    if (repositorySettingsRequest.page.kind !== "repository-settings") {
      throw new Error("The repository-settings fixture is unavailable");
    }
    const request: RenderRequest = {
      ...repositorySettingsRequest,
      page: {
        ...repositorySettingsRequest.page,
        update: null,
      },
    };
    const rendered = new DOMParser().parseFromString(
      renderPage(request),
      "text/html",
    );
    expect(
      rendered.querySelector(
        'form[action="/automata-ci/automata/settings/access"]',
      ),
    ).toBeNull();
    expect(
      rendered.querySelector('.repository-settings [name="csrf_token"]'),
    ).toBeNull();
    expect(
      rendered.querySelector('form[action="/auth/logout"]'),
    ).not.toBeNull();
    expect(rendered.querySelector('[name="expected_revision"]')).toBeNull();
    expect(rendered.querySelectorAll("fieldset.audience-setting")).toHaveLength(
      0,
    );
    expect(rendered.querySelectorAll(".audience-option input")).toHaveLength(0);
    expect(rendered.querySelector('[role="note"]')?.textContent).toContain(
      "cannot be changed from this page",
    );
    expect(
      rendered.querySelector('[aria-label="Current access defaults"]'),
    ).not.toBeNull();
    expect(rendered.querySelectorAll(".audience-summary")).toHaveLength(3);
    expect(
      [...rendered.querySelectorAll(".audience-summary__current strong")].map(
        (current) =>
          current.textContent?.replace("Current access: ", "").trim(),
      ),
    ).toEqual(["Public", "Signed-in users", "Private"]);
    expect(
      rendered.querySelector<HTMLAnchorElement>(
        '.repository-settings__actions a[href="/automata-ci/automata/actions"]',
      )?.textContent,
    ).toContain("Back to workflow runs");
  });

  it("refuses to render a visually blank accessible page heading", () => {
    if (runListRequest.page.kind !== "run-list") {
      throw new Error("The run-list fixture is unavailable");
    }
    const request = {
      ...runListRequest,
      page: { ...runListRequest.page, heading: "\u200B\uFE0F" },
    };

    expect(() => renderPage(request)).toThrow("at $.page.heading");
  });

  it("applies the required CSP nonce to every executable script", () => {
    for (const request of [runListRequest, runDetailRequest]) {
      const rendered = new DOMParser().parseFromString(
        renderPage(request),
        "text/html",
      );
      const bootstrap = rendered.querySelector("head script:not([src])");
      expect(bootstrap?.textContent).toContain("automata-theme");
      expect(bootstrap?.getAttribute("nonce")).toBe(request.host.cspNonce);
      expect(
        [...rendered.querySelectorAll<HTMLScriptElement>("script")].every(
          (script) => script.getAttribute("nonce") === request.host.cspNonce,
        ),
      ).toBe(true);
    }
  });

  it("renders read-only run details, jobs, and artifacts", () => {
    const html = renderPage(runDetailRequest);
    const rendered = new DOMParser().parseFromString(html, "text/html");

    expect(rendered.title).toBe(
      "Build and test release candidate · CI · Automata",
    );
    expect(html).toContain("Build and test release candidate");
    expect(html).toContain("Linux release build");
    expect(html).toContain("automata-x86_64-unknown-linux-musl");
    expect(
      rendered.querySelector("a.job-summary-link")?.getAttribute("href"),
    ).toMatch(/\/jobs\/[0-9a-f-]{36}$/u);
    expect(rendered.querySelector(".steps")).toBeNull();
    expect(
      [
        ...rendered.querySelectorAll<HTMLFormElement>('form[method="post"]'),
      ].map((form) => form.getAttribute("action")),
    ).toEqual(["/auth/logout"]);
    expect(rendered.querySelector('main [name="csrf_token"]')).toBeNull();
    expect(rendered.querySelector("[data-confirm]")).toBeNull();
  });

  it("renders unavailable log destinations honestly without dead links", () => {
    if (runDetailRequest.page.kind !== "run-detail") {
      throw new Error("The run-detail fixture is unavailable");
    }
    const detail = structuredClone(runDetailRequest);
    if (detail.page.kind !== "run-detail") {
      throw new Error("The cloned run-detail fixture is unavailable");
    }
    const firstJob = detail.page.jobs.items[0];
    if (firstJob === undefined) {
      throw new Error("The run-detail fixture needs one job");
    }
    const unavailableDetail: RenderRequest = {
      ...detail,
      page: {
        ...detail.page,
        jobs: {
          ...detail.page.jobs,
          items: [
            { ...firstJob, href: null },
            ...detail.page.jobs.items.slice(1),
          ],
        },
      },
    };
    const detailDocument = new DOMParser().parseFromString(
      renderPage(unavailableDetail),
      "text/html",
    );
    expect(detailDocument.querySelector("a.job-summary-link")).toBeNull();
    expect(
      detailDocument.querySelector(".job-summary-link.is-unavailable")
        ?.textContent,
    ).toContain("Logs unavailable");

    const logDocument = new DOMParser().parseFromString(
      renderPage(jobLogRequest),
      "text/html",
    );
    const unavailable = [
      ...logDocument.querySelectorAll(".run-navigation__job"),
    ].find((item) => item.textContent?.includes("Workspace tests"));
    expect(unavailable?.tagName).toBe("SPAN");
    expect(unavailable?.textContent).toContain("logs unavailable");
  });

  it("distinguishes restricted results and unavailable artifact downloads", () => {
    if (runDetailRequest.page.kind !== "run-detail") {
      throw new Error("The run-detail fixture is unavailable");
    }

    const restricted = {
      ...runDetailRequest,
      page: {
        ...runDetailRequest.page,
        jobs: {
          ...runDetailRequest.page.jobs,
          visibility: "restricted" as const,
        },
        artifacts: {
          ...runDetailRequest.page.artifacts,
          visibility: "restricted" as const,
          items: runDetailRequest.page.artifacts.items.map((artifact) => ({
            ...artifact,
            downloadHref: null,
          })),
        },
      },
    };
    const rendered = new DOMParser().parseFromString(
      renderPage(restricted),
      "text/html",
    );
    const notices = [
      ...rendered.querySelectorAll(".results-visibility-notice"),
    ];
    expect(notices.map((notice) => notice.textContent)).toEqual([
      "Some jobs are hidden because you don’t have access to view them.",
      "Some artifacts are hidden because you don’t have access to view them.",
    ]);
    expect(
      rendered.querySelector("#jobs-heading")?.nextElementSibling?.textContent,
    ).toContain("1 visible job");
    expect(
      rendered.querySelector(".artifacts .panel__heading")?.textContent,
    ).toContain("1 visible artifact");
    expect(
      rendered.querySelector(".artifact-list__identity small")?.textContent,
    ).toBe("Download unavailable");
    expect(
      rendered.querySelector(".artifact-list__identity")?.closest("a"),
    ).toBeNull();

    const hidden = {
      ...restricted,
      page: {
        ...restricted.page,
        jobs: { visibility: "restricted" as const, items: [] },
        artifacts: { visibility: "restricted" as const, items: [] },
      },
    };
    const hiddenText = new DOMParser()
      .parseFromString(renderPage(hidden), "text/html")
      .querySelector("#main-content")?.textContent;
    expect(hiddenText).toContain(
      "Jobs for this run are unavailable with your current access.",
    );
    expect(hiddenText).toContain(
      "Artifacts for this run are unavailable with your current access.",
    );
    expect(hiddenText).not.toContain("No jobs were recorded");
    expect(hiddenText).not.toContain("did not produce any artifacts");
    expect(
      new DOMParser()
        .parseFromString(renderPage(hidden), "text/html")
        .querySelector(".run-navigation__desktop")?.textContent,
    ).toContain("Jobs are unavailable with your current access.");
  });

  it("renders the structured live job log shell", () => {
    const html = renderPage(jobLogRequest);
    const rendered = new DOMParser().parseFromString(html, "text/html");
    const headingText =
      rendered.querySelector(".log-page-heading")?.textContent;

    expect(html).toContain("Job logs");
    expect(headingText).toContain("Run attempt 1");
    expect(headingText).toContain("Job attempt 2");
    expect(html).toContain('placeholder="Search logs"');
    expect(html).toContain("Expand all");
    expect(html).toContain("Following");
    expect(html).not.toContain("Job log pages");
  });

  it("keeps log search local to the streamed document", () => {
    if (jobLogRequest.page.kind !== "job-log") {
      throw new Error("The job-log fixture is unavailable");
    }
    const model = { ...jobLogRequest.page, live: null };
    const rendered = new DOMParser().parseFromString(
      renderToString(<JobLogPage model={model} />),
      "text/html",
    );

    expect(rendered.querySelector('input[type="search"]')).not.toBeNull();
    expect(rendered.querySelector("form.log-search-form")).toBeNull();
  });

  it("labels terminal jobs without a stream as unavailable", () => {
    if (jobLogRequest.page.kind !== "job-log") {
      throw new Error("The job-log fixture is unavailable");
    }
    const page = jobLogRequest.page;
    const terminal = {
      ...page,
      live: null,
      notice: "Logs are unavailable for this job.",
      job: {
        ...page.job,
        status: { label: "Succeeded", tone: "success" } as const,
      },
      jobs: page.jobs.map((job) =>
        job.id === page.job.id
          ? { ...job, status: { label: "Succeeded", tone: "success" } as const }
          : job,
      ),
    };
    const rendered = new DOMParser().parseFromString(
      renderToString(<JobLogPage model={terminal} />),
      "text/html",
    );

    expect(rendered.querySelector(".log-stream-state")?.textContent).toBe("Unavailable");
    expect(rendered.querySelector(".log-empty")?.textContent).toBe(
      "Logs are unavailable for this job.",
    );
    expect(rendered.querySelector(".log-toolbar__actions")).toBeNull();
    expect(rendered.body.textContent).not.toContain("Waiting for log output");
  });

  it("gives distinct log panels injective accessible IDs", () => {
    if (jobLogRequest.page.kind !== "job-log") {
      throw new Error("The job-log fixture is unavailable");
    }
    const records: LiveLogRecord[] = ["step/a", "step-a"].map(
      (id, index) => ({
        streamId: "00000000-0000-4000-8000-000000000005",
        sequence: String(index + 1),
        fragment: null,
        emittedAtMs: 1_777_890_010_000 + index,
        type: "group_started",
        group: {
          id,
          parentId: null,
          name: id,
          kind: "step",
          ordinal: index,
        },
      }),
    );
    const model = { ...jobLogRequest.page, live: null };
    const rendered = new DOMParser().parseFromString(
      renderToString(<JobLogPage initialRecords={records} model={model} />),
      "text/html",
    );
    const controls = [...rendered.querySelectorAll(".log-group__summary")].map(
      (button) => button.getAttribute("aria-controls"),
    );
    const regions = [...rendered.querySelectorAll(".log-group__output")].map(
      (region) => region.id,
    );

    expect(new Set(controls).size).toBe(2);
    expect(regions).toEqual(controls);
  });

  it.each([
    ["queued", { label: "Queued", tone: "queued" }],
    ["terminal", { label: "Succeeded", tone: "success" }],
  ] as const)(
    "does not require snapshot refresh controls for a %s job",
    (_name, status) => {
      if (jobLogRequest.page.kind !== "job-log") {
        throw new Error("The job-log fixture is unavailable");
      }
      const page = jobLogRequest.page;
      const request = {
        ...jobLogRequest,
        page: {
          ...page,
          jobs: page.jobs.map((job) =>
            job.id === page.job.id ? { ...job, status } : job,
          ),
          job: {
            ...page.job,
            status,
            startedAt: status.tone === "queued" ? null : page.job.startedAt,
          },
          notice:
            status.tone === "queued"
              ? "This job is waiting to start. Refresh to check for updates."
              : null,
        },
      };
      const rendered = new DOMParser().parseFromString(
        renderPage(request),
        "text/html",
      );

      expect(rendered.querySelector(".log-page-heading > a.button")).toBeNull();
      if (status.tone === "queued") {
        const headingText =
          rendered.querySelector(".log-page-heading")?.textContent;
        expect(headingText).toContain("Waiting to start");
        expect(headingText).not.toContain("Not started");
      }
    },
  );

  it("keeps the page-model identity unique on the job log", () => {
    const html = renderPage(jobLogRequest);
    document.open();
    document.write(html);
    document.close();

    expect(document.querySelectorAll(`#${PAGE_MODEL_ELEMENT_ID}`)).toHaveLength(
      1,
    );
    expect(readRenderRequest(document)).toEqual(jobLogRequest);
  });

  it.each([
    ["run list", runListRequest],
    ["run detail", runDetailRequest],
    ["job log", jobLogRequest],
  ])(
    "renders the lossless run number, never the opaque ID, on the %s",
    (_name, request) => {
      const rendered = new DOMParser().parseFromString(
        renderPage(request),
        "text/html",
      );
      const visibleText =
        rendered.querySelector("#main-content")?.textContent ?? "";

      expect(visibleText).toContain("#1842");
      expect(visibleText).not.toContain(PRIMARY_RUN_ID);
    },
  );

  it("omits unavailable actor, runner, and artifact-expiry copy", () => {
    const listDocument = new DOMParser().parseFromString(
      renderPage(runListRequest),
      "text/html",
    );
    const secondaryRun = listDocument.querySelectorAll(".run-row")[1];
    expect(secondaryRun?.textContent).toContain("pull request");
    expect(secondaryRun?.textContent).not.toContain("by grace");
    expect(secondaryRun?.textContent).not.toContain("Validate workflow syntax");
    expect(secondaryRun?.textContent).not.toContain("feature/parser");

    const detailDocument = new DOMParser().parseFromString(
      renderPage(runDetailRequest),
      "text/html",
    );
    const detailText =
      detailDocument.querySelector("#main-content")?.textContent ?? "";
    expect(
      detailDocument.querySelector(".page-heading p")?.textContent,
    ).toContain("Triggered via push");
    expect(detailText).not.toContain("Triggered by");
    expect(detailText).not.toContain("Run Automata's own CI");
    expect(detailDocument.querySelector(".run-summary dt")?.textContent).toBe(
      "Branch",
    );
    expect(detailText).not.toContain("ubuntu-24.04");
    expect(detailText).not.toContain("Expires");

    const logDocument = new DOMParser().parseFromString(
      renderPage(jobLogRequest),
      "text/html",
    );
    const logHeadingText =
      logDocument.querySelector(".log-page-heading p")?.textContent ?? "";
    expect(logHeadingText).toContain(
      "Run #1842: Build and test release candidate",
    );
    expect(logHeadingText).not.toContain("ubuntu-24.04");
  });

  it("renders exact source and workflow links without changing browsing context", () => {
    const listDocument = new DOMParser().parseFromString(
      renderPage(runListRequest),
      "text/html",
    );
    const primaryRun = listDocument.querySelectorAll(".run-row")[0];
    if (runListRequest.page.kind !== "run-list") {
      throw new Error("The run-list fixture is unavailable");
    }
    const workflowHref = runListRequest.page.runs[0]?.workflowHref;
    expect(
      primaryRun?.querySelector(".run-row__context a")?.getAttribute("href"),
    ).toBe(workflowHref);
    expect(
      primaryRun?.querySelector(".run-row__source-ref")?.getAttribute("href"),
    ).toBe("https://github.com/automata-ci/automata/tree/main");
    expect(
      primaryRun?.querySelector(".run-row__commit")?.getAttribute("href"),
    ).toBe(
      "https://github.com/automata-ci/automata/commit/26713a895eb6744012da74726e59230a259357c4",
    );
    expect(
      primaryRun?.querySelector(".run-row__commit")?.getAttribute("aria-label"),
    ).toBe("Commit 26713a8: Run Automata's own CI");
    const runNumberLink = primaryRun?.querySelectorAll(
      ".run-row__context a",
    )[1];
    expect(runNumberLink?.getAttribute("href")).toBe(
      `/automata-ci/automata/actions/runs/${PRIMARY_RUN_ID}`,
    );
    expect(runNumberLink?.textContent).toBe("#1842");

    const detailDocument = new DOMParser().parseFromString(
      renderPage(runDetailRequest),
      "text/html",
    );
    const summaryLinks = [...detailDocument.querySelectorAll(".run-summary a")];
    expect(summaryLinks.map((link) => link.getAttribute("href"))).toEqual([
      "https://github.com/automata-ci/automata/tree/main",
      "https://github.com/automata-ci/automata/commit/26713a895eb6744012da74726e59230a259357c4",
    ]);
    expect(summaryLinks[1]?.getAttribute("aria-label")).toBe("Commit 26713a8");

    const logDocument = new DOMParser().parseFromString(
      renderPage(jobLogRequest),
      "text/html",
    );
    expect(
      logDocument.querySelectorAll(".breadcrumbs a")[1]?.getAttribute("href"),
    ).toBe(workflowHref);

    for (const link of [
      ...(primaryRun?.querySelectorAll("a") ?? []),
      ...summaryLinks,
      ...logDocument.querySelectorAll(".breadcrumbs a"),
    ]) {
      expect(link.hasAttribute("target")).toBe(false);
      expect(link.hasAttribute("rel")).toBe(false);
    }
  });

  it.each([
    ["branch", "Branch", "feature/clean-links", "ph-git-branch"],
    ["tag", "Tag", "v1.0.0", "ph-tag"],
    ["ref", "Ref", "pull/42/merge", "ph-git-pull-request"],
  ] as const)(
    "labels and icons a %s source ref honestly",
    (kind, label, name, icon) => {
      if (runDetailRequest.page.kind !== "run-detail") {
        throw new Error("The run-detail fixture is unavailable");
      }
      const request = {
        ...runDetailRequest,
        page: {
          ...runDetailRequest.page,
          run: {
            ...runDetailRequest.page.run,
            sourceRef: {
              kind,
              name,
              href:
                kind === "ref"
                  ? "https://github.com/automata-ci/automata/pull/42"
                  : `https://github.com/automata-ci/automata/tree/${encodeURIComponent(name)}`,
            },
          },
        },
      };
      const rendered = new DOMParser().parseFromString(
        renderPage(request),
        "text/html",
      );
      const firstSummaryItem = rendered.querySelector(".run-summary > div");

      expect(firstSummaryItem?.querySelector("dt")?.textContent).toBe(label);
      expect(firstSummaryItem?.querySelector("a")?.textContent).toBe(name);
      expect(firstSummaryItem?.querySelector(`.${icon}`)).not.toBeNull();
    },
  );

  it("renders only model-provided workflow destinations and marks the selection", () => {
    if (
      runListRequest.page.kind !== "run-list" ||
      runListRequest.page.workflowNavigation === null
    ) {
      throw new Error("The workflow navigation fixture is unavailable");
    }
    const release = runListRequest.page.workflowNavigation.workflows[1];
    if (release === undefined) {
      throw new Error("The release workflow fixture is unavailable");
    }
    const selectedRequest = {
      ...runListRequest,
      page: {
        ...runListRequest.page,
        filters: {
          ...runListRequest.page.filters,
          action: release.href,
          clearHref: release.href,
        },
        workflowNavigation: {
          ...runListRequest.page.workflowNavigation,
          selectedWorkflow: release,
          workflows: runListRequest.page.workflowNavigation.workflows.slice(0, 1),
          pagination: {
            previousHref: null,
            nextHref: `${release.href}?status=completed&cursor=run-page&workflow_cursor=workflow-page`,
            label: "1 workflow",
          },
        },
      },
    };

    const rendered = new DOMParser().parseFromString(
      renderPage(selectedRequest),
      "text/html",
    );
    expect(
      [...rendered.querySelectorAll("a")]
        .find((link) => link.getAttribute("href") === release.href)
        ?.getAttribute("aria-current"),
    ).toBe("page");
    const disabledWorkflowLinks = [
      ...rendered.querySelectorAll<HTMLAnchorElement>(
        `.workflow-navigation__workflow[href="${release.href}"]`,
      ),
    ];
    expect(disabledWorkflowLinks.length).toBeGreaterThan(0);
    expect(
      disabledWorkflowLinks.every(
        (link) =>
          link
            .querySelector(".workflow-navigation__workflow-state")
            ?.getAttribute("aria-label") === "Disabled for new events",
      ),
    ).toBe(true);
    expect(
      rendered
        .querySelector('nav[aria-label="Workflow pages"] a[rel="next"]')
        ?.getAttribute("href"),
    ).toContain("workflow_cursor=workflow-page");
    expect(rendered.querySelector("nav nav")).toBeNull();
    expect(
      rendered
        .querySelector<HTMLFormElement>(
          'form[aria-label="Filter workflow runs"]',
        )
        ?.getAttribute("action"),
    ).toBe(release.href);
    expect(
      rendered
        .querySelector(
          'nav[aria-label="Actions navigation"] a[href$="/actions"]',
        )
      ?.hasAttribute("aria-current"),
    ).toBe(false);
  });

  it("keeps capacity pagination outside navigation and renders the run pager once", () => {
    if (runDetailRequest.page.kind !== "run-detail") {
      throw new Error("The run-detail fixture is unavailable");
    }
    const runHref = `/automata-ci/automata/actions/runs/${PRIMARY_RUN_ID}`;
    const previousHref = `${runHref}?job_cursor=previous`;
    const nextHref = `${runHref}?job_cursor=next`;
    const request: RenderRequest = {
      ...runDetailRequest,
      page: {
        ...runDetailRequest.page,
        jobPagination: {
          previousHref,
          nextHref,
          label: "200 of 4096 jobs",
        },
      },
    };
    const rendered = new DOMParser().parseFromString(
      renderPage(request),
      "text/html",
    );
    const pagers = rendered.querySelectorAll(
      'nav[aria-label="Run job pages"]',
    );

    expect(pagers).toHaveLength(1);
    expect(
      pagers[0]?.querySelector('a[rel="prev"]')?.getAttribute("href"),
    ).toBe(previousHref);
    expect(
      pagers[0]?.querySelector('a[rel="next"]')?.getAttribute("href"),
    ).toBe(nextHref);
    expect(rendered.querySelector("nav nav")).toBeNull();
  });

  it("renders native browser rerun choices only when the server grants them", () => {
    if (runDetailRequest.page.kind !== "run-detail") {
      throw new Error("The run-detail fixture is unavailable");
    }
    const endpoint = `/automata-ci/automata/actions/runs/${PRIMARY_RUN_ID}/reruns`;
    const request: RenderRequest = {
      ...runDetailRequest,
      page: {
        ...runDetailRequest.page,
        rerun: {
          endpoint,
          csrfToken: SHELL_CSRF_TOKEN,
          failedJobsAvailable: true,
        },
      },
    };
    const rendered = new DOMParser().parseFromString(
      renderPage(request),
      "text/html",
    );
    const controls = rendered.querySelector('[aria-label="Rerun controls"]');
    expect(controls?.textContent).toContain("Re-run all jobs");
    expect(controls?.textContent).toContain("Re-run failed jobs");
    expect(runDetailRequest.page.rerun).toBeNull();
  });

  it("keeps decorative icons hidden and icon-only statuses accessible", () => {
    const listDocument = new DOMParser().parseFromString(
      renderPage(runListRequest),
      "text/html",
    );
    const detailDocument = new DOMParser().parseFromString(
      renderPage(runDetailRequest),
      "text/html",
    );

    expect(listDocument.querySelectorAll("i.icon.ph").length).toBeGreaterThan(
      0,
    );
    expect(
      listDocument.querySelector("i.icon.ph")?.getAttribute("aria-hidden"),
    ).toBe("true");
    expect(
      listDocument
        .querySelector(".run-row__status .status")
        ?.getAttribute("aria-hidden"),
    ).toBe("true");
    expect(
      listDocument.querySelector(".run-row__result")?.textContent,
    ).toContain("In progress");
    expect(listDocument.querySelector(".viewer-link")?.textContent).toContain(
      "Ada",
    );
    expect(listDocument.querySelector("a.viewer-link")).toBeNull();
    expect(
      detailDocument
        .querySelector(".job__title .status")
        ?.getAttribute("aria-label"),
    ).toBe("In progress");
    expect(
      detailDocument.querySelector(".job__title .status")?.getAttribute("role"),
    ).toBe("img");
    expect(
      detailDocument.querySelector(".heading-status .status__label")
        ?.textContent,
    ).toBe("In progress");
    expect(
      detailDocument.querySelector(".theme-toggle")?.getAttribute("aria-label"),
    ).toBe("Color theme");
    expect(
      detailDocument.querySelector('head script[nonce="nonce-value"]')
        ?.textContent,
    ).toContain("automata-theme");
    expect(
      listDocument.querySelector(".repo-header__identity .sr-only")
        ?.textContent,
    ).toBe("/");
  });

  it("keeps compact job metadata separated in the accessibility tree", () => {
    if (runDetailRequest.page.kind !== "run-detail") {
      throw new Error("The run-detail fixture is unavailable");
    }
    const request = {
      ...runDetailRequest,
      page: {
        ...runDetailRequest.page,
        jobs: {
          ...runDetailRequest.page.jobs,
          items: runDetailRequest.page.jobs.items.map((job) => ({
            ...job,
            runnerLabel: "ubuntu-24.04",
          })),
        },
      },
    };
    const rendered = new DOMParser().parseFromString(
      renderPage(request),
      "text/html",
    );

    expect(
      rendered.querySelector(".job__title small .sr-only")?.textContent,
    ).toBe(",");
  });

  it("skips an invisible prefix and keeps the viewer avatar to one code point", () => {
    if (runListRequest.page.kind !== "run-list") {
      throw new Error("The run-list fixture is unavailable");
    }
    const request = {
      ...runListRequest,
      page: {
        ...runListRequest.page,
        shell: {
          ...runListRequest.page.shell,
          viewer: {
            displayName: "\u200Bßeta",
          },
        },
      },
    };
    const rendered = new DOMParser().parseFromString(
      renderPage(request),
      "text/html",
    );

    expect(rendered.querySelector(".viewer-link__avatar")?.textContent).toBe(
      "S",
    );
  });

  it("escapes visible values and the embedded hydration payload", () => {
    const html = renderPage(runListRequest);

    expect(html).not.toContain("ada<script>alert(1)</script>");
    expect(html).toContain("ada&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).not.toContain("</script><script>alert(1)</script>");
    expect(html).toContain(
      "ada\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
    );
  });

  it("accepts the serialized stable renderer boundary", () => {
    const html = render(JSON.stringify(runDetailRequest));
    expect(html).toContain("<!doctype html>");
    expect(html).toContain("Build and test release candidate");
  });

  it.each([
    ["a non-script element", "div", null],
    ["a script with the wrong MIME type", "script", "text/javascript"],
  ] as const)(
    "rejects page-model JSON embedded in %s",
    (_name, tagName, type) => {
      const rendered = new DOMParser().parseFromString(
        "<!doctype html><html><body></body></html>",
        "text/html",
      );
      const element = rendered.createElement(tagName);
      element.id = PAGE_MODEL_ELEMENT_ID;
      if (type !== null) {
        element.setAttribute("type", type);
      }
      element.textContent = JSON.stringify(runListRequest);
      rendered.body.append(element);

      expect(() => readRenderRequest(rendered)).toThrow(
        "Automata page model is missing from the document",
      );
    },
  );
});

describe("hydration", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("disables rerun controls while submitting and recovers from rejection", async () => {
    if (runDetailRequest.page.kind !== "run-detail") {
      throw new Error("The run-detail fixture is unavailable");
    }
    const endpoint = `/automata-ci/automata/actions/runs/${PRIMARY_RUN_ID}/reruns`;
    const request: RenderRequest = {
      ...runDetailRequest,
      page: {
        ...runDetailRequest.page,
        rerun: {
          endpoint,
          csrfToken: SHELL_CSRF_TOKEN,
          failedJobsAvailable: true,
        },
      },
    };
    const fetchMock = vi.fn().mockResolvedValue({ ok: false });
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
    document.open();
    document.write(renderPage(request));
    document.close();
    const parsedRequest = readRenderRequest(document);

    let root: ReturnType<typeof hydrateRoot> | undefined;
    await act(async () => {
      root = hydrateRoot(document, <HtmlDocument request={parsedRequest} />);
    });
    const rerun = document.querySelector<HTMLButtonElement>(
      '[aria-label="Rerun controls"] .button--primary',
    );
    await act(async () => rerun?.click());

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(endpoint, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "content-type": "application/json",
        "x-automata-csrf-token": SHELL_CSRF_TOKEN,
      },
      body: expect.stringContaining('"selection":{"mode":"entire_workflow"}'),
    });
    expect(rerun?.disabled).toBe(false);
    expect(rerun?.textContent).toContain("Re-run all jobs");
    expect(document.querySelector('[role="alert"]')?.textContent).toContain(
      "The rerun could not be started",
    );

    await act(async () => root?.unmount());
  });

  it.each([
    ["run list", runListRequest, "Workflow runs"],
    ["run detail", runDetailRequest, "Build and test release candidate"],
    ["job log", jobLogRequest, "Linux release build"],
    ["repository settings", repositorySettingsRequest, "Repository access"],
  ])(
    "hydrates the %s document without recoverable mismatch errors",
    async (_name, request, heading) => {
      document.open();
      document.write(renderPage(request));
      document.close();
      const parsedRequest = readRenderRequest(document);
      const errors: unknown[] = [];
      vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);

      let root: ReturnType<typeof hydrateRoot> | undefined;
      await act(async () => {
        root = hydrateRoot(document, <HtmlDocument request={parsedRequest} />, {
          onRecoverableError: (error) => errors.push(error),
        });
      });

      expect(errors).toEqual([]);
      expect(document.querySelector("h1")?.textContent).toBe(heading);

      await act(async () => root?.unmount());
    },
  );

  it.each([
    [
      "all jobs after an HTTP rejection",
      "Re-run all jobs",
      "entire_workflow",
      () => new Response(null, { status: 503 }),
    ],
    [
      "failed jobs after an invalid success response",
      "Re-run failed jobs",
      "failed_jobs_and_dependents",
      () =>
        new Response(JSON.stringify({ run_id: "not-a-run-uuid" }), {
          headers: { "Content-Type": "application/json" },
        }),
    ],
  ] as const)(
    "recovers rerun controls for %s",
    async (_case, buttonLabel, mode, response) => {
      if (runDetailRequest.page.kind !== "run-detail") {
        throw new Error("The run-detail fixture is unavailable");
      }
      const endpoint = `/automata-ci/automata/actions/runs/${PRIMARY_RUN_ID}/reruns`;
      const request: RenderRequest = {
        ...runDetailRequest,
        page: {
          ...runDetailRequest.page,
          rerun: {
            endpoint,
            csrfToken: SHELL_CSRF_TOKEN,
            failedJobsAvailable: true,
          },
        },
      };
      const operationId = "11111111-1111-4111-8111-111111111111";
      const fetchMock = vi.fn(async () => response());
      vi.spyOn(globalThis.crypto, "randomUUID").mockReturnValue(operationId);
      vi.stubGlobal("fetch", fetchMock);
      vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
      document.open();
      document.write(renderPage(request));
      document.close();
      const parsedRequest = readRenderRequest(document);

      let root: ReturnType<typeof hydrateRoot> | undefined;
      await act(async () => {
        root = hydrateRoot(document, <HtmlDocument request={parsedRequest} />);
      });
      const button = [
        ...document.querySelectorAll<HTMLButtonElement>(
          '[aria-label="Rerun controls"] button',
        ),
      ].find((candidate) => candidate.textContent === buttonLabel);
      expect(button).toBeDefined();

      await act(async () => {
        button?.click();
      });

      expect(fetchMock).toHaveBeenCalledWith(endpoint, {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "content-type": "application/json",
          "x-automata-csrf-token": SHELL_CSRF_TOKEN,
        },
        body: JSON.stringify({
          operation_id: operationId,
          selection: { mode },
        }),
      });
      expect(document.querySelector('[role="alert"]')?.textContent).toBe(
        "The rerun could not be started. Refresh and try again.",
      );
      expect(button?.disabled).toBe(false);

      await act(async () => root?.unmount());
    },
  );

  it("preserves only server-authorized mutation controls during hydration", async () => {
    document.open();
    document.write(renderPage(runDetailRequest));
    document.close();
    const parsedRequest = readRenderRequest(document);
    const postActionsBefore = [
      ...document.querySelectorAll<HTMLFormElement>('form[method="post"]'),
    ].map((form) => form.getAttribute("action"));
    vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);

    let root: ReturnType<typeof hydrateRoot> | undefined;
    await act(async () => {
      root = hydrateRoot(document, <HtmlDocument request={parsedRequest} />);
    });

    const postActionsAfter = [
      ...document.querySelectorAll<HTMLFormElement>('form[method="post"]'),
    ].map((form) => form.getAttribute("action"));
    expect(postActionsBefore).toEqual(["/auth/logout"]);
    expect(postActionsAfter).toEqual(postActionsBefore);
    expect(
      document.querySelector<HTMLInputElement>(
        'form[action="/auth/logout"] [name="csrf_token"]',
      )?.value,
    ).toBe(SHELL_CSRF_TOKEN);
    expect(
      document.querySelector('form[action$="/settings/access"]'),
    ).toBeNull();
    expect(document.querySelector("[data-confirm]")).toBeNull();

    await act(async () => root?.unmount());
  });

  it("progressively saves only changed repository access defaults", async () => {
    document.open();
    document.write(renderPage(repositorySettingsRequest));
    document.close();
    const form = document.querySelector<HTMLFormElement>(
      'form[action="/automata-ci/automata/settings/access"]',
    );
    const save = form?.querySelector<HTMLButtonElement>(
      'button[type="submit"]',
    );

    expect(save?.disabled).toBe(false);
    expect(save?.textContent).toContain("Save changes");

    const parsedRequest = readRenderRequest(document);
    const errors: unknown[] = [];
    vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
    let root: ReturnType<typeof hydrateRoot> | undefined;
    await act(async () => {
      root = hydrateRoot(document, <HtmlDocument request={parsedRequest} />, {
        onRecoverableError: (error) => errors.push(error),
      });
    });

    expect(errors).toEqual([]);
    expect(save?.disabled).toBe(true);
    expect(form?.hasAttribute("aria-busy")).toBe(false);

    const privateDashboard = form?.querySelector<HTMLInputElement>(
      '[name="dashboard_audience"][value="private"]',
    );
    const publicDashboard = form?.querySelector<HTMLInputElement>(
      '[name="dashboard_audience"][value="public"]',
    );
    await act(async () => privateDashboard?.click());
    expect(privateDashboard?.checked).toBe(true);
    expect(save?.disabled).toBe(false);

    await act(async () => publicDashboard?.click());
    expect(publicDashboard?.checked).toBe(true);
    expect(save?.disabled).toBe(true);

    await act(async () => privateDashboard?.click());
    await act(async () => {
      form?.dispatchEvent(
        new Event("submit", { bubbles: true, cancelable: true }),
      );
    });
    expect(form?.getAttribute("aria-busy")).toBe("true");
    expect(save?.disabled).toBe(true);
    expect(save?.textContent).toContain("Saving…");

    const reload = vi
      .spyOn(window.history, "go")
      .mockImplementation(() => undefined);
    const restored = new Event("pageshow");
    Object.defineProperty(restored, "persisted", { value: true });
    await act(async () => window.dispatchEvent(restored));
    expect(reload).toHaveBeenCalledWith(0);
    reload.mockRestore();

    await act(async () => root?.unmount());
  });

  it("tolerates the intentional pre-hydration theme attribute", async () => {
    document.open();
    document.write(renderPage(runListRequest));
    document.close();
    document.documentElement.dataset.theme = "dark";
    const parsedRequest = readRenderRequest(document);
    const errors: unknown[] = [];
    const consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => undefined);
    vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);

    let root: ReturnType<typeof hydrateRoot> | undefined;
    await act(async () => {
      root = hydrateRoot(document, <HtmlDocument request={parsedRequest} />, {
        onRecoverableError: (error) => errors.push(error),
      });
    });

    expect(errors).toEqual([]);
    expect(consoleError).not.toHaveBeenCalled();
    await act(async () => root?.unmount());
    consoleError.mockRestore();
  });

  it("returns to the system theme when stored preferences are cleared", async () => {
    const media = {
      matches: true,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    } as unknown as MediaQueryList;
    vi.stubGlobal(
      "matchMedia",
      vi.fn(() => media),
    );
    const themeStorage = emptyStorage();
    const unrelatedStorage = emptyStorage();
    vi.stubGlobal("localStorage", themeStorage);

    document.open();
    document.write(renderPage(runListRequest));
    document.close();
    const parsedRequest = readRenderRequest(document);
    vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);

    let root: ReturnType<typeof hydrateRoot> | undefined;
    await act(async () => {
      root = hydrateRoot(document, <HtmlDocument request={parsedRequest} />);
    });
    expect(document.documentElement.dataset.theme).toBe("dark");

    await act(async () => {
      window.dispatchEvent(
        storageEvent(unrelatedStorage, "automata-theme", "light"),
      );
    });
    expect(document.documentElement.dataset.theme).toBe("dark");

    await act(async () => {
      window.dispatchEvent(
        storageEvent(themeStorage, "automata-theme", "light"),
      );
    });
    expect(document.documentElement.dataset.theme).toBe("light");

    await act(async () => {
      window.dispatchEvent(storageEvent(themeStorage, null, null));
    });
    expect(document.documentElement.dataset.theme).toBe("dark");

    await act(async () => root?.unmount());
  });

  it.each([
    ["users", userListRequest],
    ["user detail", userDetailRequest],
    ["roles", roleListRequest],
    ["role detail", roleDetailRequest],
    ["direct bindings", directBindingListRequest],
  ])(
    "renders the authenticated %s management page with one heading and exact navigation",
    (_name, request) => {
      const rendered = new DOMParser().parseFromString(
        renderPage(request),
        "text/html",
      );

      expect(rendered.querySelectorAll("main h1")).toHaveLength(1);
      expect(
        rendered.querySelectorAll(
          '.rbac-management__navigation a[aria-current="page"]',
        ),
      ).toHaveLength(1);
      expect(rendered.querySelector("main#main-content")).not.toBeNull();
      expect(
        rendered.querySelector(
          "main#main-content .rbac-management__navigation",
        ),
      ).toBeNull();
      expect(rendered.querySelector(".repo-header")).toBeNull();
      expect(
        rendered.querySelector('form[action="/auth/logout"]'),
      ).not.toBeNull();
      expect(rendered.querySelectorAll("main form")).toHaveLength(0);
      expect(
        rendered.querySelectorAll("table caption").length,
      ).toBeGreaterThanOrEqual(1);
      expect(
        rendered.querySelectorAll("table thead th").length,
      ).toBeGreaterThanOrEqual(1);
      for (const region of rendered.querySelectorAll(".rbac-table-region")) {
        expect(region.getAttribute("role")).toBe("region");
        expect(region.getAttribute("tabindex")).toBeNull();
        const labelledBy = region.getAttribute("aria-labelledby");
        expect(labelledBy).not.toBeNull();
        expect(rendered.getElementById(labelledBy ?? "")).not.toBeNull();
        expect(
          region.closest("section")?.getAttribute("aria-labelledby"),
        ).toBeNull();
        expect(
          [...rendered.querySelectorAll('[role="region"]')].filter(
            (candidate) =>
              candidate.getAttribute("aria-labelledby") === labelledBy,
          ),
        ).toHaveLength(1);
      }
    },
  );

  it("keeps an empty RBAC panel named when no table region is rendered", () => {
    if (userListRequest.page.kind !== "user-list") {
      throw new Error("The user-list fixture must retain its exact page kind");
    }
    const emptyRequest: RenderRequest = {
      ...userListRequest,
      page: {
        ...userListRequest.page,
        users: [],
        pagination: {
          previousHref: null,
          nextHref: null,
          label: "0 members",
        },
      },
    };
    const rendered = new DOMParser().parseFromString(
      renderPage(emptyRequest),
      "text/html",
    );

    expect(rendered.querySelector(".rbac-table-region")).toBeNull();
    expect(
      rendered.querySelector(
        'section[aria-labelledby="users-heading"] .rbac-empty',
      )?.textContent,
    ).toContain("No members");
  });

  it("renders a concise user identity and read-only role assignments", () => {
    const rendered = new DOMParser().parseFromString(
      renderPage(userDetailRequest),
      "text/html",
    );

    expect(rendered.querySelector(".rbac-status--active")?.textContent).toBe(
      "Active",
    );
    expect(rendered.querySelector('a[href$="/sessions"]')).toBeNull();
    expect(rendered.querySelector("main form")).toBeNull();
    expect(
      rendered.querySelector('time[datetime="2026-09-01T00:00:00Z"]')
        ?.textContent,
    ).toBe("1 Sep 2026, 00:00 UTC");
    expect(rendered.querySelector("#main-content")?.textContent).toContain(
      "ada-lovelace",
    );
    expect(rendered.querySelector("#main-content")?.textContent).toContain(
      "GitHub",
    );
    expect(rendered.querySelector("#main-content")?.textContent).not.toContain(
      RBAC_USER_ID,
    );
  });

  it("renders role details and grants without dormant operation controls", () => {
    const rendered = new DOMParser().parseFromString(
      renderPage(roleDetailRequest),
      "text/html",
    );

    expect(rendered.querySelector("main form")).toBeNull();
    expect(
      rendered.querySelector("#role-permissions-heading")?.textContent,
    ).toBe("Permissions");
    expect(
      rendered.querySelectorAll(
        '.rbac-table-region[aria-labelledby="role-permissions-heading"] thead th',
      ),
    ).toHaveLength(2);
    expect(rendered.querySelector("#main-content")?.textContent).not.toContain(
      "Operation",
    );
    expect(rendered.querySelector("#main-content")?.textContent).not.toContain(
      "Unavailable",
    );
    expect(rendered.querySelector(".rbac-read-only")?.textContent).toContain(
      "aren’t available",
    );
  });

  it("retains role deletion after the role revision can no longer advance", () => {
    if (roleDetailRequest.page.kind !== "role-detail") {
      throw new Error(
        "the role-detail fixture must retain its exact page kind",
      );
    }
    const maximumRevision = "9223372036854775807";
    const deleteOnlyRequest: RenderRequest = {
      ...roleDetailRequest,
      page: {
        ...roleDetailRequest.page,
        delete: {
          action: `/settings/access/roles/${RBAC_ROLE_ID}/delete`,
          csrfToken: SHELL_CSRF_TOKEN,
          expectedAuthorizationRevision: "7",
          expectedRevision: maximumRevision,
        },
      },
    };
    const rendered = new DOMParser().parseFromString(
      renderPage(deleteOnlyRequest),
      "text/html",
    );

    expect(
      rendered.querySelector(
        `form[action="/settings/access/roles/${RBAC_ROLE_ID}"]`,
      ),
    ).toBeNull();
    expect(
      rendered.querySelectorAll('form[action*="/permissions/"]'),
    ).toHaveLength(0);
    const deletion = rendered.querySelector<HTMLFormElement>(
      `form[action="/settings/access/roles/${RBAC_ROLE_ID}/delete"]`,
    );
    expect(deletion?.method).toBe("post");
    expect(
      deletion?.querySelector<HTMLInputElement>(
        'input[name="expected_revision"]',
      )?.value,
    ).toBe(maximumRevision);
    expect(rendered.querySelector(".rbac-read-only")?.textContent).toContain(
      "can still be deleted",
    );
  });

  it("renders direct and provider-observed bindings as stable read-only rows", () => {
    const rendered = new DOMParser().parseFromString(
      renderPage(directBindingListRequest),
      "text/html",
    );
    const rows = [
      ...rendered.querySelectorAll(".rbac-table--bindings tbody tr"),
    ];
    const providerRow = rows.find((row) =>
      row.textContent?.includes("Provider observed"),
    );
    const directRow = rows.find((row) => row.textContent?.includes("Direct"));

    expect(providerRow?.querySelector("form")).toBeNull();
    expect(directRow?.querySelector("form")).toBeNull();
    expect(rendered.getElementById(RBAC_BINDING_ID)).toBe(directRow);
    expect(directRow?.getAttribute("tabindex")).toBe("-1");
    expect(rendered.querySelector("#main-content")?.textContent).not.toContain(
      "Unavailable",
    );
    expect(rendered.querySelector("#main-content")?.textContent).not.toContain(
      "Revision",
    );
    expect(rendered.querySelector(".rbac-read-only")?.textContent).toBe(
      "Direct binding management is temporarily unavailable.",
    );
  });

  it("renders every RBAC mutation as an exact native POST form", () => {
    if (
      userDetailRequest.page.kind !== "user-detail" ||
      roleListRequest.page.kind !== "role-list" ||
      roleDetailRequest.page.kind !== "role-detail" ||
      directBindingListRequest.page.kind !== "direct-binding-list"
    ) {
      throw new Error("RBAC fixtures must retain their exact page kinds");
    }
    const authority = {
      csrfToken: SHELL_CSRF_TOKEN,
      expectedAuthorizationRevision: "7",
    } as const;
    const userRequest: RenderRequest = {
      ...userDetailRequest,
      page: {
        ...userDetailRequest.page,
        statusUpdate: {
          ...authority,
          action: `/settings/access/users/${RBAC_USER_ID}/status`,
          expectedRevision: "3",
          operation: "disable",
        },
      },
    };
    const roleListMutationRequest: RenderRequest = {
      ...roleListRequest,
      page: {
        ...roleListRequest.page,
        create: {
          ...authority,
          action: "/settings/access/roles",
        },
      },
    };
    const roleRevision = { ...authority, expectedRevision: "5" } as const;
    const roleDetailMutationRequest: RenderRequest = {
      ...roleDetailRequest,
      page: {
        ...roleDetailRequest.page,
        update: {
          ...roleRevision,
          action: `/settings/access/roles/${RBAC_ROLE_ID}`,
        },
        delete: {
          ...roleRevision,
          action: `/settings/access/roles/${RBAC_ROLE_ID}/delete`,
        },
        permissions: roleDetailRequest.page.permissions.map((permission) => ({
          ...permission,
          update: {
            ...roleRevision,
            action: `/settings/access/roles/${RBAC_ROLE_ID}/permissions/${permission.name}`,
            operation: permission.granted
              ? ("remove" as const)
              : ("add" as const),
          },
        })),
      },
    };
    const directBindingMutationRequest: RenderRequest = {
      ...directBindingListRequest,
      page: {
        ...directBindingListRequest.page,
        grant: {
          ...authority,
          action: "/settings/access/direct-bindings",
          principals: [{ value: RBAC_USER_ID, label: "Ada Lovelace" }],
          roles: [{ value: RBAC_ROLE_ID, label: "Release reviewer" }],
          scopes: [{ value: "tenant", label: "Production tenant" }],
        },
        readOnlyReason: null,
        bindings: directBindingListRequest.page.bindings.map((binding) => ({
          ...binding,
          revoke:
            binding.id === RBAC_BINDING_ID
              ? {
                  ...authority,
                  expectedRevision: binding.revision,
                  action: `/settings/access/direct-bindings/${RBAC_BINDING_ID}/revoke`,
                }
              : null,
        })),
      },
    };

    const user = new DOMParser().parseFromString(
      renderPage(userRequest),
      "text/html",
    );
    const status = user.querySelector<HTMLFormElement>(
      `form[action="/settings/access/users/${RBAC_USER_ID}/status"]`,
    );
    expect(status?.method).toBe("post");
    expect(
      status?.querySelector<HTMLInputElement>('input[name="csrf_token"]')
        ?.value,
    ).toBe(SHELL_CSRF_TOKEN);
    expect(
      status?.querySelector<HTMLInputElement>(
        'input[name="expected_authorization_revision"]',
      )?.value,
    ).toBe("7");
    expect(
      status?.querySelector<HTMLInputElement>('input[name="expected_revision"]')
        ?.value,
    ).toBe("3");
    expect(
      status?.querySelector<HTMLInputElement>('input[name="operation"]')?.value,
    ).toBe("disable");
    expect(
      status?.querySelector<HTMLInputElement>('input[name="reason"]')?.required,
    ).toBe(true);

    const roles = new DOMParser().parseFromString(
      renderPage(roleListMutationRequest),
      "text/html",
    );
    expect(
      roles.querySelector<HTMLFormElement>(
        'form[action="/settings/access/roles"]',
      )?.method,
    ).toBe("post");

    const role = new DOMParser().parseFromString(
      renderPage(roleDetailMutationRequest),
      "text/html",
    );
    const permissionOperations = [
      ...role.querySelectorAll<HTMLInputElement>(
        'form[action*="/permissions/"] input[name="operation"]',
      ),
    ].map((input) => input.value);
    expect(permissionOperations).toEqual(["remove", "add"]);
    const permissionActionLabels = [
      ...role.querySelectorAll<HTMLButtonElement>(
        'form[action*="/permissions/"] button[type="submit"]',
      ),
    ].map((button) => button.getAttribute("aria-label"));
    expect(permissionActionLabels).toEqual([
      "Remove runs:read permission from role Release reviewer",
      "Grant artifacts:download permission to role Release reviewer",
    ]);
    const deleteDisclosure = role.querySelector<HTMLDetailsElement>(
      "details.rbac-delete-disclosure",
    );
    const deleteForm = role.querySelector<HTMLFormElement>(
      `form[action="/settings/access/roles/${RBAC_ROLE_ID}/delete"]`,
    );
    expect(deleteDisclosure?.open).toBe(false);
    expect(deleteDisclosure?.querySelector("summary")?.textContent).toBe(
      "Delete role",
    );
    expect(deleteForm?.closest("details")).toBe(deleteDisclosure);
    expect(deleteForm?.method).toBe("post");
    expect(
      deleteForm?.querySelector<HTMLInputElement>('input[name="csrf_token"]')
        ?.value,
    ).toBe(SHELL_CSRF_TOKEN);
    expect(
      deleteForm?.querySelector<HTMLInputElement>(
        'input[name="expected_authorization_revision"]',
      )?.value,
    ).toBe("7");
    expect(
      deleteForm?.querySelector<HTMLInputElement>(
        'input[name="expected_revision"]',
      )?.value,
    ).toBe("5");
    expect(
      deleteForm?.querySelector('button[type="submit"]')?.textContent?.trim(),
    ).toBe("Confirm delete");

    const bindings = new DOMParser().parseFromString(
      renderPage(directBindingMutationRequest),
      "text/html",
    );
    const grant = bindings.querySelector<HTMLFormElement>(
      'form[action="/settings/access/direct-bindings"]',
    );
    expect(grant?.method).toBe("post");
    expect(
      grant?.querySelector<HTMLSelectElement>('select[name="principal_id"]')
        ?.value,
    ).toBe(RBAC_USER_ID);
    expect(
      grant?.querySelector<HTMLSelectElement>('select[name="role_id"]')?.value,
    ).toBe(RBAC_ROLE_ID);
    expect(
      grant?.querySelector<HTMLSelectElement>('select[name="scope"]')?.value,
    ).toBe("tenant");
    const validUntil = grant?.querySelector<HTMLInputElement>(
      'input[name="valid_until"]',
    );
    expect(validUntil?.type).toBe("datetime-local");
    expect(validUntil?.step).toBe("60");
    expect(validUntil?.required).toBe(false);
    expect(validUntil?.getAttribute("aria-labelledby")).toBe(
      "direct-binding-valid-until-label",
    );
    expect(validUntil?.getAttribute("aria-describedby")).toBe(
      "direct-binding-valid-until-hint",
    );
    expect(
      bindings.querySelector("#direct-binding-valid-until-label")?.textContent,
    ).toBe("Valid until (UTC)");
    expect(
      bindings
        .querySelector("#direct-binding-valid-until-hint")
        ?.textContent?.trim(),
    ).toBe("Leave blank for no expiry.");
    expect(grant?.textContent).not.toContain("Unix seconds");
    expect(bindings.querySelectorAll('form[action$="/revoke"]')).toHaveLength(
      1,
    );
    expect(
      bindings
        .querySelector<HTMLButtonElement>(
          'form[action$="/revoke"] button[type="submit"]',
        )
        ?.getAttribute("aria-label"),
    ).toBe(
      "Revoke Release reviewer role from Ada Lovelace for automata-ci/automata",
    );
    expect(
      bindings.querySelector('tr:nth-child(2) form[action$="/revoke"]'),
    ).toBeNull();
  });
});

function storageEvent(
  storageArea: Storage,
  key: string | null,
  newValue: string | null,
): StorageEvent {
  const event = new Event("storage") as StorageEvent;
  Object.defineProperties(event, {
    key: { value: key },
    newValue: { value: newValue },
    storageArea: { value: storageArea },
  });
  return event;
}

function emptyStorage(): Storage {
  return {
    length: 0,
    clear: () => undefined,
    getItem: () => null,
    key: () => null,
    removeItem: () => undefined,
    setItem: () => undefined,
  };
}
