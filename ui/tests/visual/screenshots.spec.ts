import { mkdir } from "node:fs/promises";
import path from "node:path";
import { expect, test } from "@playwright/test";
import type { Locator, Page } from "@playwright/test";
import {
  PREVIEW_FAILED_RUN_ID as FAILED_RUN_ID,
  PREVIEW_PRIMARY_RUN_ID as PRIMARY_RUN_ID,
  PREVIEW_QUEUED_RUN_ID as QUEUED_RUN_ID,
  PREVIEW_SECONDARY_RUN_ID as SECONDARY_RUN_ID,
} from "../../src/preview/sampleData";
import { PREVIEW_DIRECT_BINDING_ID } from "../../src/preview/rbacModels";
import {
  authorizedManagementFixtures,
  installAuthorizedManagementFixture,
} from "./authorizedManagementFixtures";

const screenshotDirectory = path.resolve(
  process.cwd(),
  "dist/preview/screenshots",
);

const previewPages = [
  {
    name: "repositories",
    url: "./?view=repositories",
    heading: "Repositories",
  },
  {
    name: "repositories-empty",
    url: "./?view=repositories-empty",
    heading: "Repositories",
  },
  {
    name: "workflow-runs",
    url: "./?view=runs",
    heading: "Workflow runs",
  },
  {
    name: "runners",
    url: "./?view=runners",
    heading: "Runners",
  },
  {
    name: "run-summary",
    url: "./?view=run",
    heading: "Build and test release candidate",
  },
  {
    name: "job-logs",
    url: "./?view=job&job=job-1",
    heading: "Linux release build",
  },
  {
    name: "repository-access-settings",
    url: "./?view=settings",
    heading: "Repository access",
  },
  {
    name: "repository-secrets",
    url: "./?view=secrets",
    heading: "Repository secrets",
  },
  {
    name: "access-users",
    url: "./?view=users",
    heading: "Members",
  },
  {
    name: "access-user-detail",
    url: "./?view=user&user=ada-lovelace",
    heading: "Ada Lovelace",
  },
  {
    name: "access-roles",
    url: "./?view=roles",
    heading: "Roles",
  },
  {
    name: "access-role-detail",
    url: "./?view=role&role=release-reviewer",
    heading: "Release reviewer",
  },
  {
    name: "access-direct-bindings",
    url: "./?view=bindings",
    heading: "Direct bindings",
  },
] as const;

test("repository directory exposes only honest destinations and the same-kind empty state", async ({
  page,
}) => {
  await page.goto("./?view=repositories");
  const main = page.getByRole("main");
  await expect(main.getByRole("heading", { level: 1 })).toHaveText("Repositories");
  const row = main.getByRole("listitem");
  await expect(row.locator(".repository-directory__name")).toHaveAttribute(
    "href",
    "https://github.com/automata-ci/automata",
  );
  await expect(row.getByRole("link", { name: "Actions" })).toHaveAttribute(
    "href",
    "?view=runs",
  );
  await expect(row.getByRole("link", { name: "Access" })).toHaveAttribute(
    "href",
    "?view=settings",
  );
  await row.getByRole("link", { name: "Actions" }).click();
  await expect(page).toHaveURL(/\?view=runs$/u);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Workflow runs");
  await page.getByRole("link", { name: "Repositories" }).click();
  await expect(page).toHaveURL(/\?view=repositories$/u);

  await page.goto("./?view=repositories-empty");
  await expect(page.getByRole("heading", { name: "No repositories available" })).toBeVisible();
  await expect(main.getByRole("listitem")).toHaveCount(0);
  await expectNoDocumentOverflow(page);
});

const presentationModes = [
  { name: "desktop", viewport: { width: 1440, height: 1000 } },
  { name: "tablet", viewport: { width: 768, height: 1024 } },
  { name: "mobile", viewport: { width: 390, height: 844 } },
] as const;

const colorSchemes = ["light", "dark"] as const;

const themePresentationContracts = {
  dark: {
    background: "rgb(13, 17, 23)",
    toggleName: "Use light theme",
  },
  light: {
    background: "rgb(255, 255, 255)",
    toggleName: "Use dark theme",
  },
} as const;

for (const previewPage of previewPages) {
  for (const presentation of presentationModes) {
    for (const colorScheme of colorSchemes) {
      const viewportLabel =
        presentation.name === "desktop" ? "" : `-${presentation.name}`;
      const screenshotName = `${previewPage.name}${viewportLabel}-${colorScheme}`;

      test(`presentation contract ${screenshotName}`, async ({ page }) => {
        await mkdir(screenshotDirectory, { recursive: true });
        const runtimeIssues = collectRuntimeIssues(page);
        await observeLayoutShifts(page);
        await page.setViewportSize(presentation.viewport);
        await page.emulateMedia({ colorScheme, reducedMotion: "reduce" });
        try {
          await page.goto(previewPage.url, { waitUntil: "networkidle" });
          await waitForStableRender(page, previewPage.heading);

          expect(await cumulativeLayoutShift(page)).toBeLessThanOrEqual(0.01);
          await expectNoDocumentOverflow(page);
          await expectPreviewPresentation(
            page,
            presentation.viewport,
            colorScheme,
          );
          expect(runtimeIssues).toEqual([]);
        } finally {
          // These are Pages and human-review artifacts, not pixel baselines.
          // Capturing in the failure path preserves the page that explains a
          // deterministic contract failure without coupling the gate to host-
          // dependent font and rasterization output.
          await page.screenshot({
            animations: "disabled",
            fullPage: true,
            path: path.join(screenshotDirectory, `${screenshotName}.png`),
          });
        }
      });
    }
  }
}

test("the built preview remains self-contained at its Pages project path", async ({
  page,
}) => {
  const runtimeIssues = collectRuntimeIssues(page);
  await page.goto("./?view=runs", { waitUntil: "networkidle" });
  await waitForStableRender(page, "Workflow runs");

  expect(new URL(page.url()).pathname).toBe("/automata/");
  const assetPaths = await page.evaluate(() =>
    performance
      .getEntriesByType("resource")
      .map((entry) => new URL(entry.name).pathname)
      .filter((path) => path.includes("/assets/")),
  );
  expect(assetPaths.length).toBeGreaterThan(0);
  expect(assetPaths.every((path) => path.startsWith("/automata/assets/"))).toBe(
    true,
  );

  await page
    .getByRole("main")
    .getByRole("link", { name: "Build and test release candidate" })
    .click();
  await expect(page).toHaveURL(
    new RegExp(`/automata/\\?view=run&run=${PRIMARY_RUN_ID}$`, "u"),
  );
  expect(runtimeIssues).toEqual([]);
});

test("visible text controls use the shared application skin", async ({ page }) => {
  let visibleControlCount = 0;
  for (const previewPage of previewPages) {
    await page.goto(previewPage.url);
    await waitForStableRender(page, previewPage.heading);
    const controls = await visibleTextControlPresentation(page.locator("body"));

    visibleControlCount += controls.length;
    for (const control of controls) {
      expect(control.height, previewPage.name).toBeGreaterThanOrEqual(32);
      expect(control.borderRadius, previewPage.name).toBeGreaterThanOrEqual(6);
      expect(control.borderWidth, previewPage.name).toBeGreaterThanOrEqual(1);
      expect(control.background, previewPage.name).not.toBe("rgba(0, 0, 0, 0)");
      expect(control.fontFamily, previewPage.name).toBe(control.inheritedFontFamily);
    }
  }
  expect(visibleControlCount).toBeGreaterThanOrEqual(3);
});

test("the global shell keeps its footer at the document edge without repository chrome", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1_440, height: 1_000 });
  await page.goto("./?view=runs");
  await waitForStableRender(page, "Workflow runs");
  const metrics = await page.evaluate(() => {
    document.querySelector(".repo-header")?.remove();
    const main = document.querySelector("main");
    const footer = document.querySelector(".site-footer");
    if (main === null || footer === null) {
      throw new Error("The shell landmarks are missing");
    }
    main.replaceChildren();
    return {
      documentHeight: document.documentElement.scrollHeight,
      footerBottom: footer.getBoundingClientRect().bottom + window.scrollY,
      viewportHeight: window.innerHeight,
    };
  });

  expect(metrics.documentHeight).toBeGreaterThanOrEqual(metrics.viewportHeight);
  expect(Math.abs(metrics.footerBottom - metrics.documentHeight)).toBeLessThanOrEqual(1);
});

test("preview navigation opens a run and its job logs", async ({ page }) => {
  await page.goto("./?view=runs");
  const main = page.getByRole("main");
  await main
    .getByRole("link", { name: "Build and test release candidate" })
    .click();

  await expect(page).toHaveURL(
    new RegExp(`\\?view=run&run=${PRIMARY_RUN_ID}$`, "u"),
  );
  await expect(main).toContainText("#1842");
  await expect(main).not.toContainText(PRIMARY_RUN_ID);
  await expect(main.getByRole("heading", { level: 1 })).toHaveText(
    "Build and test release candidate",
  );

  await main
    .getByRole("navigation", { name: "Run navigation" })
    .getByRole("link", { name: /Linux release build/u })
    .click();
  await expect(page).toHaveURL(
    new RegExp(`\\?view=job&run=${PRIMARY_RUN_ID}&job=job-1$`, "u"),
  );
  await expect(main.getByRole("heading", { name: "Job logs" })).toBeVisible();
  await expect(page).toHaveTitle("Linux release build logs · Automata");
  await expect(main.getByRole("button", { name: "Following" })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
});

test("repository access preview is independently selected and safely read-only", async ({
  page,
}) => {
  await page.goto("./?view=runs");
  await page
    .getByRole("navigation", { name: "Repository navigation" })
    .getByRole("link", { name: "Settings" })
    .click();
  await expect(page).toHaveURL(/\?view=settings$/u);

  const main = page.getByRole("main");
  await expect(main.getByRole("heading", { level: 1 })).toHaveText(
    "Repository access",
  );
  await expect(main).not.toContainText("Policy revision");
  await expect(main).not.toContainText("Version 7");
  await expect(main).toContainText("Existing runs keep their current access");
  await expect(
    page.getByRole("note", {
      name: "Sample data — preview only; no backend workflows were executed.",
    }),
  ).toBeVisible();
  await expect(main.locator('form[method="post"]')).toHaveCount(0);
  await expect(main.locator('[name="csrf_token"]')).toHaveCount(0);
  await expect(main.locator('[name="expected_revision"]')).toHaveCount(0);

  await expect(main.locator(".audience-option input")).toHaveCount(0);
  const defaults = main.getByRole("list", { name: "Current access defaults" });
  await expect(defaults.getByRole("listitem")).toHaveCount(3);
  await expect(defaults).toContainText("Public");
  await expect(defaults).toContainText("Signed-in users");
  await expect(defaults).toContainText("Private");
  await expect(
    main.getByRole("link", { name: "Back to workflow runs" }),
  ).toHaveAttribute("href", "?view=runs");
  await expect(
    page
      .getByRole("navigation", { name: "Repository navigation" })
      .getByRole("link", { name: "Settings" }),
  ).toHaveAttribute("aria-current", "page");
  expect(await page.content()).not.toContain("csrfToken");
});

test("repository secrets preview is value-free, read-only, and linked from settings", async ({
  page,
}) => {
  await page.goto("./?view=settings");
  const settingsNavigation = page.getByRole("navigation", {
    name: "Repository settings",
  });
  await settingsNavigation.getByRole("link", { name: "Secrets" }).click();
  await expect(page).toHaveURL(/\?view=secrets$/u);

  const main = page.getByRole("main");
  await expect(main.getByRole("heading", { level: 1 })).toHaveText(
    "Repository secrets",
  );
  await expect(
    main.getByRole("navigation", { name: "Repository settings" })
      .getByRole("link", { name: "Secrets" }),
  ).toHaveAttribute("aria-current", "page");
  await expect(main.getByRole("note")).toContainText(
    "secret values and mutation controls are not available",
  );
  await expect(main.locator('form[method="post"]')).toHaveCount(0);
  await expect(main.locator('input[type="password"]')).toHaveCount(0);
  await expect(main.locator('[name="csrf_token"]')).toHaveCount(0);
  await expect(main.locator('[name="mutation_id"]')).toHaveCount(0);
  await expect(main.locator(".repository-secret-row")).toHaveCount(2);
  await expect(main).toContainText("DEPLOY_TOKEN");
  await expect(main).toContainText("PACKAGE_SIGNING_KEY");
  await expect(main).toContainText("Encrypted storage");
  await expect(main).not.toContainText("Manage");
  await expect(main).not.toContainText("Create secret");
  expect(await page.content()).not.toMatch(/csrfToken|mutationId/u);

  await settingsNavigation.getByRole("link", { name: "Access" }).click();
  await expect(page).toHaveURL(/\?view=settings$/u);
});

test("access management preview is read-only, cohesive, and query-local", async ({
  context,
}) => {
  const routes = [
    ["./?view=users", "Members"],
    ["./?view=user&user=ada-lovelace", "Ada Lovelace"],
    ["./?view=roles", "Roles"],
    ["./?view=role&role=release-reviewer", "Release reviewer"],
    ["./?view=bindings", "Direct bindings"],
  ] as const;

  for (const [url, heading] of routes) {
    const routePage = await context.newPage();
    try {
      await routePage.goto(url, { waitUntil: "networkidle" });
      const main = routePage.getByRole("main");
      await expect(main.getByRole("heading", { level: 1 })).toHaveText(heading);
      await expect(main.locator("form")).toHaveCount(0);
      await expect(main.locator('[name="csrf_token"]')).toHaveCount(0);
      const destinations = await routePage.locator("a[href]").evaluateAll((links) =>
        links.map((link) => link.getAttribute("href")),
      );
      expect(
        destinations.every(
          (destination) =>
            destination !== null &&
            (destination.startsWith("?") || destination.startsWith("#")),
        ),
      ).toBe(true);
    } finally {
      await routePage.close();
    }
  }

  const page = await context.newPage();
  await page.goto("./?view=users");
  await page
    .getByRole("main")
    .getByRole("link", { name: "Ada Lovelace" })
    .click();
  await expect(page).toHaveURL(/\?view=user&user=ada-lovelace$/u);
  await page.getByRole("link", { name: "Direct", exact: true }).click();
  await expect(page).toHaveURL(/\?view=bindings$/u);
  const target = page.locator(`#${PREVIEW_DIRECT_BINDING_ID}`);
  await expect(target).toBeInViewport({ ratio: 1 });

  await page.setViewportSize({ width: 390, height: 844 });
  const roleCell = target.locator('td[data-label="Role"]');
  const [roleLinkBox, roleNameBox] = await Promise.all([
    roleCell.getByRole("link").boundingBox(),
    roleCell.locator("small").boundingBox(),
  ]);
  expect(roleLinkBox).not.toBeNull();
  expect(roleNameBox).not.toBeNull();
  expect(Math.abs((roleLinkBox?.x ?? 0) - (roleNameBox?.x ?? 0)))
    .toBeLessThanOrEqual(1);
  await expectNoDocumentOverflow(page);
});

test("direct-binding revoke controls stay usable in narrow production cards", async ({
  browser,
}) => {
  for (const width of [320, 390]) {
    const context = await browser.newContext({
      hasTouch: true,
      isMobile: true,
      viewport: { width, height: 844 },
    });
    try {
      const page = await context.newPage();
      await page.goto("./?view=bindings", { waitUntil: "networkidle" });
      const actionCell = page
        .locator(`#${PREVIEW_DIRECT_BINDING_ID}`)
        .locator('td[data-label="Action"]');
      await actionCell.evaluate((cell) => {
        const form = document.createElement("form");
        form.className = "rbac-inline-revoke";
        const label = document.createElement("label");
        const labelText = document.createElement("span");
        labelText.className = "sr-only";
        labelText.textContent = "Revocation reason";
        const input = document.createElement("input");
        input.className = "form-control form-control--compact";
        input.setAttribute(
          "aria-label",
          "Reason for revoking Release reviewer from Ada Lovelace",
        );
        input.placeholder = "Reason";
        input.required = true;
        const button = document.createElement("button");
        button.className = "button button--compact button--danger";
        button.textContent = "Revoke";
        button.type = "button";
        label.append(labelText, input);
        form.append(label, button);
        cell.replaceChildren(form);
      });

      const controls = actionCell.locator("input, button");
      await expect(controls).toHaveCount(2);
      const bounds = await actionCell.evaluate((cell) => {
        const cellBounds = cell.getBoundingClientRect();
        return [...cell.querySelectorAll("input, button")].map((control) => {
          const controlBounds = control.getBoundingClientRect();
          return {
            left: controlBounds.left,
            right: controlBounds.right,
            cellLeft: cellBounds.left,
            cellRight: cellBounds.right,
          };
        });
      });
      for (const bound of bounds) {
        expect(bound.left).toBeGreaterThanOrEqual(bound.cellLeft);
        expect(bound.right).toBeLessThanOrEqual(bound.cellRight);
      }
      await controls.last().focus();
      await expect(controls.last()).toBeInViewport({ ratio: 0.99 });
      await expectNoDocumentOverflow(page);
    } finally {
      await context.close();
    }
  }
});

test("binding presentation follows its content width without hiding actions", async ({
  page,
}) => {
  const layouts = [
    { width: 390, tableDisplay: "block", rowDisplay: "block" },
    { width: 768, tableDisplay: "block", rowDisplay: "grid" },
    { width: 1_000, tableDisplay: "block", rowDisplay: "grid" },
    { width: 1_280, tableDisplay: "table", rowDisplay: "table-row" },
  ] as const;

  for (const layout of layouts) {
    await page.setViewportSize({ width: layout.width, height: 900 });
    await page.goto("./?view=bindings", { waitUntil: "networkidle" });

    const region = page.locator(".rbac-table-region");
    const table = region.locator(".rbac-table--bindings");
    const firstRow = table.locator("tbody tr").first();
    const actionCell = firstRow.locator('td[data-label="Action"]');
    const metrics = await region.evaluate((element) => {
      const regionBounds = element.getBoundingClientRect();
      const action = element.querySelector('td[data-label="Action"]');
      if (!(action instanceof HTMLElement)) {
        throw new Error("The binding action cell is missing");
      }
      const actionBounds = action.getBoundingClientRect();
      return {
        hiddenWidth: element.scrollWidth - element.clientWidth,
        actionInside:
          actionBounds.left >= regionBounds.left - 1 &&
          actionBounds.right <= regionBounds.right + 1,
      };
    });

    expect(metrics.hiddenWidth).toBeLessThanOrEqual(1);
    expect(metrics.actionInside).toBe(true);
    await expect(table).toHaveCSS("display", layout.tableDisplay);
    await expect(firstRow).toHaveCSS("display", layout.rowDisplay);
    await expect(actionCell).toContainText("Read-only");
    await expectNoDocumentOverflow(page);
  }

  const readOnlyNotice = page.locator(".rbac-read-only--standalone");
  await expect(readOnlyNotice).toHaveCSS("border-bottom-width", "1px");
  await expect(readOnlyNotice).toHaveCSS("border-left-width", "1px");
  await expect(readOnlyNotice).toHaveCSS("border-radius", "6px");
  await expect(readOnlyNotice).toHaveCSS("margin-bottom", "16px");

  await page.goto("./?view=roles");
  await expect(page.getByRole("main")).toContainText("Built-in");
  await expect(page.getByRole("main")).not.toContainText("Built in");
  await page.goto("./?view=user&user=ada-lovelace");
  await expect(
    page.getByRole("columnheader", { name: "Valid until" }),
  ).toBeAttached();
});

test("authorized form fixtures stay bounded without preview capabilities", async ({
  page,
}) => {
  let visibleTextControlCount = 0;
  for (const colorScheme of colorSchemes) {
    await page.emulateMedia({ colorScheme, reducedMotion: "reduce" });
    for (const viewport of [
      { width: 768, height: 1_024 },
      { width: 390, height: 844 },
    ]) {
      await page.setViewportSize(viewport);
      for (const fixture of authorizedManagementFixtures) {
        await page.goto(fixture.previewUrl, { waitUntil: "networkidle" });
        await installAuthorizedManagementFixture(page, fixture);

        const main = page.getByRole("main");
        const forms = main.locator('form[method="post"]');
        expect(await forms.count(), fixture.name).toBeGreaterThan(0);
        const controlBounds = await main
          .locator('input:not([type="hidden"]), select, textarea, button')
          .evaluateAll((controls) => {
            const main = document.querySelector("main");
            if (!(main instanceof HTMLElement)) {
              throw new Error("The management main landmark is missing");
            }
            const mainBounds = main.getBoundingClientRect();
            return controls.flatMap((control) => {
              const bounds = control.getBoundingClientRect();
              return bounds.width === 0 && bounds.height === 0
                ? []
                : [{
                    left: bounds.left,
                    right: bounds.right,
                    mainLeft: mainBounds.left,
                    mainRight: mainBounds.right,
                  }];
            });
          });
        for (const bounds of controlBounds) {
          expect(bounds.left, fixture.name).toBeGreaterThanOrEqual(
            bounds.mainLeft - 1,
          );
          expect(bounds.right, fixture.name).toBeLessThanOrEqual(
            bounds.mainRight + 1,
          );
        }

        const textControls = await visibleTextControlPresentation(main);
        visibleTextControlCount += textControls.length;
        for (const control of textControls) {
          expect(control.height, fixture.name).toBeGreaterThanOrEqual(32);
          expect(control.borderRadius, fixture.name).toBeGreaterThanOrEqual(6);
          expect(control.borderWidth, fixture.name).toBeGreaterThanOrEqual(1);
          expect(control.background, fixture.name).not.toBe("rgba(0, 0, 0, 0)");
          expect(control.fontFamily, fixture.name).toBe(control.inheritedFontFamily);
        }

        const firstControl = main
          .locator(
            'input:not([type="hidden"]):visible, select:visible, ' +
            'textarea:visible, button:visible',
          )
          .first();
        await firstControl.focus();
        expect(await hasVisibleOutline(firstControl), fixture.name).toBe(true);
        await expectNoDocumentOverflow(page);
      }
    }
  }
  expect(visibleTextControlCount).toBeGreaterThan(0);
});

test("access management skip navigation bypasses management tabs", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("./?view=users");
  await waitForStableRender(page, "Members");
  const skipLink = page.getByRole("link", { name: "Skip to content" });
  await page.keyboard.press("Tab");
  await expect(skipLink).toBeFocused();
  await page.keyboard.press("Enter");

  const main = page.getByRole("main");
  await expect(main).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(main.getByRole("link", { name: "Ada Lovelace" })).toBeFocused();
  await expect(main.locator(".rbac-table-region")).not.toHaveAttribute("tabindex", "0");
  await expect(
    page
      .getByRole("navigation", { name: "Access management" })
      .getByRole("link", { name: "Members" }),
  ).not.toBeFocused();

  await page.setViewportSize({ width: 768, height: 1_024 });
  await page.goto("./?view=users");
  await waitForStableRender(page, "Members");
  const overflowingRegion = page.getByRole("region", { name: "Members" });
  await overflowingRegion.locator("table").evaluate((table) => {
    table.style.minWidth = "1200px";
  });
  await expect(overflowingRegion).toHaveAttribute("tabindex", "0");
  const intermediateSkipLink = page.getByRole("link", { name: "Skip to content" });
  await page.keyboard.press("Tab");
  await expect(intermediateSkipLink).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(main).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(overflowingRegion).toBeFocused();
});

test("compact job links open structured panels with in-memory search", async ({
  page,
}) => {
  await page.goto(`./?view=run&run=${PRIMARY_RUN_ID}`);
  const main = page.getByRole("main");
  const jobs = main.getByRole("region", { name: "Jobs" });
  await expect(jobs.locator("details, .steps")).toHaveCount(0);
  await jobs
    .getByRole("link", { name: /Linux release build/u })
    .click();

  await expect(page).toHaveURL(
    new RegExp(`\\?view=job&run=${PRIMARY_RUN_ID}&job=job-1$`, "u"),
  );
  const output = main.getByRole("region", {
    name: "Linux release build output",
  });
  await expect(
    output.getByRole("button", { name: /Runner diagnostics/u }),
  ).toHaveAttribute("aria-expanded", "false");
  await expect(
    output.getByRole("button", { name: /Checkout repository/u }),
  ).toHaveAttribute("aria-expanded", "false");
  await expect(
    output.getByRole("button", { name: /Linux release build/u }),
  ).toHaveAttribute("aria-expanded", "true");
  await expect(
    output.getByRole("link", { name: "Link to log line 8" }),
  ).toHaveText("8");

  await main
    .getByRole("searchbox", { name: "Search job logs" })
    .fill("Operating System");
  await expect(
    output.getByRole("link", { name: /^Link to log line/u }),
  ).toHaveCount(1);
  await expect(
    output.getByRole("link", { name: "Link to log line 7" }),
  ).toHaveText("7");
  await expect(page).not.toHaveURL(/[?&]q=/u);

  await main.getByRole("searchbox", { name: "Search job logs" }).fill("");
  await main.getByRole("button", { name: "Expand all" }).click();
  await expect(
    output.getByRole("link", { name: "Link to log line 4" }),
  ).toHaveText("4");
});

test("preview filters are functional and source navigation is allowlisted", async ({
  page,
}) => {
  for (const previewPage of previewPages) {
    await page.goto(previewPage.url);
    const destinations = await page
      .locator("a[href], form[action]")
      .evaluateAll((elements) =>
        elements
          .map((element) =>
            element.getAttribute(
              element instanceof HTMLFormElement ? "action" : "href",
            ),
          )
          .filter((destination): destination is string => destination !== null),
      );
    for (const destination of destinations) {
      if (!destination.startsWith("https://")) {
        expect(destination.startsWith("/")).toBe(false);
        continue;
      }
      const sourceUrl = new URL(destination);
      expect(sourceUrl.origin).toBe("https://github.com");
      expect(sourceUrl.pathname.startsWith("/automata-ci/automata")).toBe(true);
    }
  }

  await page.goto("./?view=runs");
  const main = page.getByRole("main");
  await expect(page.getByRole("note")).toContainText("Sample data");
  await main
    .getByRole("searchbox", { name: "Filter runs by branch or Git ref" })
    .fill("main");
  await main
    .getByRole("combobox", { name: "Filter by status" })
    .selectOption("in_progress");
  await main.getByRole("button", { name: "Filter" }).click();

  const runs = getRunList(main);
  await expect(runs.getByRole("listitem")).toHaveCount(1);
  await expect(
    runs.getByRole("link", { name: "Build and test release candidate" }),
  ).toBeVisible();

  const workflowNavigation = main.getByRole("navigation", {
    name: "Actions navigation",
  });
  await workflowNavigation
    .getByRole("link", { name: "Release", exact: true })
    .click();
  await expect(page).toHaveURL(/workflow=release/u);
  await expect(
    workflowNavigation.getByRole("link", { name: "Release", exact: true }),
  ).toHaveAttribute("aria-current", "page");
  await expect(
    main.getByRole("region", { name: "Release workflow runs" }),
  ).toBeVisible();
  await expect(runs.getByRole("listitem")).toHaveCount(1);
  await expect(
    runs.getByRole("link", { name: "Publish release artifacts" }),
  ).toBeVisible();

  await main
    .getByRole("combobox", { name: "Filter by status" })
    .selectOption("completed");
  await main.getByRole("button", { name: "Filter" }).click();
  await expect(page).toHaveURL(/workflow=release/u);
  await expect(runs.getByRole("listitem")).toHaveCount(1);

  await main.getByRole("link", { name: "Clear filters" }).click();
  await expect
    .poll(() =>
      page.evaluate(() => {
        const parameters = new URL(window.location.href).searchParams;
        return {
          branch: parameters.get("branch"),
          status: parameters.get("status"),
          workflow: parameters.get("workflow"),
        };
      }),
    )
    .toEqual({ branch: null, status: null, workflow: "release" });
  await expect(runs.getByRole("listitem")).toHaveCount(1);

  await workflowNavigation
    .getByRole("link", { name: /^Nightly/u })
    .click();
  await main
    .getByRole("combobox", { name: "Filter by status" })
    .selectOption("completed");
  await main.getByRole("button", { name: "Filter" }).click();
  const nightlyRuns = main.getByRole("region", {
    name: "Nightly workflow runs",
  });
  await expect(nightlyRuns.getByRole("list")).toHaveCount(0);
  await expect(
    nightlyRuns.getByRole("heading", {
      name: "No Nightly workflow runs match these filters",
    }),
  ).toBeVisible();
  await expect(nightlyRuns).toContainText(
    "Try changing the branch, tag, or status filter for Nightly.",
  );
});

test("preview rejects unknown deep links and exposes only functional destinations", async ({
  page,
}) => {
  await page.goto("./?view=unknown");
  await expect(
    page.getByRole("heading", { name: "Page not found" }),
  ).toBeVisible();

  await page.goto("./?view=run&run=missing");
  await expect(
    page.getByRole("heading", { name: "Run not found" }),
  ).toBeVisible();

  await page.goto(`./?view=job&run=${PRIMARY_RUN_ID}&job=missing`);
  await expect(
    page.getByRole("heading", { name: "Job not found" }),
  ).toBeVisible();

  await page.goto("./?view=settings&notice=saved");
  await expect(
    page.getByRole("heading", { name: "Page not found" }),
  ).toBeVisible();

  await page.goto("./?view=settings&revision=7");
  await expect(
    page.getByRole("heading", { name: "Page not found" }),
  ).toBeVisible();

  await page.goto("./?view=secrets&notice=created");
  await expect(
    page.getByRole("heading", { name: "Page not found" }),
  ).toBeVisible();

  await page.goto("./?view=runs");
  const main = page.getByRole("main");
  const primaryRun = getRunList(main).getByRole("listitem").first();
  const runDestinations = await primaryRun
    .getByRole("link")
    .evaluateAll((links) => links.map((link) => link.getAttribute("href")));
  expect(new Set(runDestinations)).toEqual(
    new Set([
      `?view=run&run=${PRIMARY_RUN_ID}`,
      "?view=runs&workflow=ci",
      "https://github.com/automata-ci/automata/tree/main",
      "https://github.com/automata-ci/automata/commit/26713a895eb6744012da74726e59230a259357c4",
    ]),
  );
  const sourceRefLink = primaryRun.getByRole("link", {
    name: "Branch main",
    exact: true,
  });
  const commitLink = primaryRun.getByRole("link", { name: /26713a8/u });
  await expect(sourceRefLink).toHaveAttribute(
    "href",
    "https://github.com/automata-ci/automata/tree/main",
  );
  await commitLink.focus();
  await expect(commitLink).toBeFocused();
  expect(await hasVisibleOutline(commitLink)).toBe(true);

  await primaryRun
    .getByRole("link", { name: "Build and test release candidate" })
    .click();
  await expect(
    main.getByRole("region", { name: "Run summary" }).getByRole("link"),
  ).toHaveCount(2);
  await expect(
    main.getByRole("region", { name: "Run summary" }).getByRole("link", {
      name: "Branch main",
      exact: true,
    }),
  ).toHaveAttribute(
    "href",
    "https://github.com/automata-ci/automata/tree/main",
  );
  await expect(
    main.getByRole("region", { name: "Run summary" }).getByRole("link", {
      name: /26713a8/u,
    }),
  ).toHaveAttribute(
    "href",
    "https://github.com/automata-ci/automata/commit/26713a895eb6744012da74726e59230a259357c4",
  );
  await expect(
    main.getByRole("region", { name: "Artifacts" }).getByRole("link"),
  ).toHaveCount(0);
});

test("preview omits unavailable durable metadata without placeholder copy", async ({
  page,
}) => {
  await page.goto("./?view=runs");
  const main = page.getByRole("main");
  const secondaryRun = getRunList(main).getByRole("listitem").nth(1);
  await expect(secondaryRun).toContainText("pull request");
  await expect(secondaryRun).not.toContainText("pull_request");
  await expect(secondaryRun).not.toContainText("by grace");
  await expect(secondaryRun).not.toContainText("Validate workflow syntax");
  await expect(secondaryRun).not.toContainText("feature/parser");

  await page.goto(`./?view=run&run=${SECONDARY_RUN_ID}`);
  await expect(main).toContainText("Triggered via pull request");
  await expect(main).not.toContainText("Triggered by");
  await expect(main).not.toContainText("ubuntu-24.04");
  await expect(main).not.toContainText("Expires");

  await page.goto(`./?view=job&run=${PRIMARY_RUN_ID}&job=job-1`);
  await expect(main).not.toContainText("ubuntu-24.04");
  await expect(main).not.toContainText("null");
});

test("preview run details stay coherent with each selected run state", async ({
  page,
}) => {
  const main = page.getByRole("main");

  await page.goto(`./?view=run&run=${SECONDARY_RUN_ID}`);
  await expect(main.getByRole("heading", { level: 1 })).toHaveText(
    "Workflow compatibility suite",
  );
  const successfulJobs = main.locator(".job-summary-link");
  await expect(successfulJobs).toHaveCount(2);
  for (const job of await successfulJobs.all()) {
    await expect(job).not.toContainText("Start time not recorded");
    await expect(job.locator("time")).toHaveCount(1);
  }

  await page.goto(`./?view=run&run=${FAILED_RUN_ID}`);
  const skippedJob = main
    .locator(".job-summary-link")
    .filter({ hasText: "Workspace tests" });
  await expect(skippedJob).toContainText("Duration not recorded");
  await expect(skippedJob).not.toContainText("Start time not recorded");
  await expect(skippedJob).not.toContainText("Waiting to start");

  await page.goto(`./?view=run&run=${QUEUED_RUN_ID}`);
  await expect(main.getByRole("heading", { level: 1 })).toHaveText(
    "Nightly compatibility suite",
  );
  const artifacts = main.getByRole("region", { name: "Artifacts" });
  await expect(artifacts.getByRole("list")).toHaveCount(0);
  await expect(artifacts).toContainText(
    "Artifacts will appear after this run starts.",
  );
  const queuedJob = main.locator(".job-summary-link").first();
  await expect(queuedJob).toContainText("Not started");
  await expect(queuedJob).not.toContainText("Waiting to start");
  await expect(main.locator("details.job, .steps")).toHaveCount(0);
});

test("restricted result notices and unavailable artifacts stay honest and bounded", async ({
  page,
}) => {
  for (const width of [1440, 390, 320]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto(`./?view=run&run=${FAILED_RUN_ID}`);
    const main = page.getByRole("main");
    const jobs = main.getByRole("region", { name: "Jobs" });
    const artifacts = main.getByRole("region", { name: "Artifacts" });

    await expect(jobs).toContainText("2 visible jobs");
    await expect(jobs.locator(".results-visibility-notice")).toHaveText(
      "Some jobs are hidden because you don’t have access to view them.",
    );
    await expect(jobs.getByRole("link")).toHaveCount(2);
    await expect(artifacts).toContainText("1 visible artifact");
    await expect(artifacts.locator(".results-visibility-notice")).toHaveText(
      "Some artifacts are hidden because you don’t have access to view them.",
    );
    const unavailableArtifact = artifacts.locator(".artifact-list__identity");
    await expect(unavailableArtifact).toContainText("lint-diagnostics");
    await expect(unavailableArtifact).toContainText("Download unavailable");
    await expect(artifacts.getByRole("link")).toHaveCount(0);
    await expectNoDocumentOverflow(page);
  }
});

test("theme follows the system and persists an explicit override", async ({
  browser,
}) => {
  const context = await browser.newContext({ colorScheme: "dark" });

  try {
    const page = await context.newPage();
    await page.goto("./?view=runs");
    await expect(
      page.getByRole("button", { name: "Use light theme" }),
    ).toBeVisible();
    await expect.poll(() => bodyBackground(page)).toBe("rgb(13, 17, 23)");

    await page.getByRole("button", { name: "Use light theme" }).click();
    await expect.poll(() => activeTheme(page)).toBe("light");
    await expect.poll(() => bodyBackground(page)).toBe("rgb(255, 255, 255)");

    await page.reload();
    await expect.poll(() => activeTheme(page)).toBe("light");
    await expect(
      page.getByRole("button", { name: "Use dark theme" }),
    ).toBeVisible();

    const secondPage = await context.newPage();
    await secondPage.goto("./?view=run");
    await expect.poll(() => activeTheme(secondPage)).toBe("light");
    await expect(
      secondPage.getByRole("button", { name: "Use dark theme" }),
    ).toBeVisible();
  } finally {
    await context.close();
  }
});

test("theme toggle keeps balanced content spacing", async ({ page }) => {
  for (const colorScheme of colorSchemes) {
    await page.emulateMedia({ colorScheme, reducedMotion: "reduce" });
    await page.goto("./?view=runs", { waitUntil: "networkidle" });
    await waitForStableRender(page, "Workflow runs");

    const spacing = await page.locator(".theme-toggle").evaluate((button) => {
      const icon = button.querySelector(".icon");
      const label = button.querySelector("span");
      if (!(icon instanceof HTMLElement) || !(label instanceof HTMLElement)) {
        throw new Error("Theme toggle content is missing");
      }

      const buttonBounds = button.getBoundingClientRect();
      const iconBounds = icon.getBoundingClientRect();
      const labelBounds = label.getBoundingClientRect();
      return {
        leadingInset: iconBounds.left - buttonBounds.left,
        trailingInset: buttonBounds.right - labelBounds.right,
        width: buttonBounds.width,
      };
    });

    expect(
      Math.abs(spacing.leadingInset - spacing.trailingInset),
    ).toBeLessThanOrEqual(1);
    expect(spacing.width).toBeLessThanOrEqual(80);
  }
});

test("small badges and primary actions retain WCAG AA contrast in both themes", async ({
  page,
}) => {
  for (const colorScheme of colorSchemes) {
    await page.emulateMedia({ colorScheme });
    await page.goto("./?view=runs");
    expect(await contrastRatio(page.locator(".demo-badge"))).toBeGreaterThanOrEqual(
      4.5,
    );

    await page.goto("./?view=users");
    for (const status of await page.locator(".rbac-status").all()) {
      expect(await contrastRatio(status)).toBeGreaterThanOrEqual(4.5);
    }

    const primaryAction = page.locator(".button--primary");
    await page.getByRole("main").evaluate((main) => {
      const button = document.createElement("button");
      button.className = "button button--primary";
      button.textContent = "Save";
      main.append(button);
    });
    expect(await contrastRatio(primaryAction)).toBeGreaterThanOrEqual(4.5);
  }
});

test("coarse pointers receive usable targets without widening mobile pages", async ({
  browser,
}) => {
  const context = await browser.newContext({
    colorScheme: "dark",
    hasTouch: true,
    isMobile: true,
    viewport: { width: 320, height: 720 },
  });

  try {
    const page = await context.newPage();
    await page.goto("./?view=runs", { waitUntil: "networkidle" });
    await expectNoDocumentOverflow(page);

    for (const target of [
      page.getByRole("link", { name: "Automata home" }),
      page.getByRole("link", { name: "Actions", exact: true }).first(),
      page.getByRole("button", { name: /^Use (?:light|dark) theme$/u }),
      page.getByRole("searchbox", { name: "Filter runs by branch or Git ref" }),
      page.getByRole("combobox", { name: "Filter by status" }),
      page.getByRole("button", { name: "Filter" }),
    ]) {
      expect((await target.boundingBox())?.height ?? 0).toBeGreaterThanOrEqual(
        40,
      );
    }

    const firstRun = getRunList(page.getByRole("main"))
      .getByRole("listitem")
      .first();
    for (const target of [
      firstRun.getByRole("link", {
        name: "Build and test release candidate",
      }),
      firstRun.getByRole("link", { name: "CI", exact: true }),
      firstRun.getByRole("link", { name: "Branch main", exact: true }),
      firstRun.getByRole("link", { name: /26713a8/u }),
    ]) {
      expect((await target.boundingBox())?.height ?? 0).toBeGreaterThanOrEqual(
        24,
      );
    }
    await expectNoDocumentOverflow(page);
  } finally {
    await context.close();
  }
});

test("account and theme controls remain usable together at 320px", async ({
  page,
}) => {
  await page.setViewportSize({ width: 320, height: 720 });
  await page.goto("./?view=users");
  await page.evaluate(() => {
    document.querySelector(".demo-badge")?.remove();
    const viewer = document.querySelector(".site-header__tools > .viewer-link");
    if (viewer === null) {
      throw new Error("Expected the read-only preview identity");
    }
    const menu = document.createElement("details");
    menu.className = "viewer-menu";
    menu.innerHTML = [
      '<summary class="viewer-link">',
      '<span class="viewer-link__avatar" aria-hidden="true">A</span>',
      '<i aria-hidden="true" class="ph ph-caret-down icon icon--14 viewer-menu__chevron"></i>',
      '<span class="sr-only">Ada account menu</span>',
      "</summary>",
      '<div class="viewer-menu__popover">',
      '<p class="viewer-menu__identity">Signed in as <strong>Ada</strong></p>',
      '<button class="viewer-menu__sign-out" type="button">Sign out</button>',
      "</div>",
    ].join("");
    viewer.replaceWith(menu);
  });

  await expectNoDocumentOverflow(page);
  for (const linkName of ["Repositories", "Runners", "Access"] as const) {
    await expect(
      page
        .getByRole("navigation", { name: "Primary navigation" })
        .getByRole("link", { name: linkName, exact: true }),
    ).toBeInViewport({ ratio: 1 });
  }

  const theme = page.getByRole("button", { name: /^Use (?:light|dark) theme$/u });
  const account = page.locator(".viewer-menu > summary");
  const [themeBox, accountBox] = await Promise.all([
    theme.boundingBox(),
    account.boundingBox(),
  ]);
  expect(themeBox).not.toBeNull();
  expect(accountBox).not.toBeNull();
  expect((accountBox?.x ?? 0) - ((themeBox?.x ?? 0) + (themeBox?.width ?? 0)))
    .toBeGreaterThanOrEqual(4);

  await account.click();
  const popover = page.locator(".viewer-menu__popover");
  await expect(popover).toBeVisible();
  const popoverBox = await popover.boundingBox();
  expect(popoverBox).not.toBeNull();
  expect((popoverBox?.x ?? 0) + (popoverBox?.width ?? 0)).toBeLessThanOrEqual(320);
});

test("the shell compacts cleanly through the 641px transition", async ({
  page,
}) => {
  for (const layout of [
    { width: 640, compact: true },
    { width: 641, compact: false },
  ]) {
    await page.setViewportSize({ width: layout.width, height: 800 });
    await page.goto("./?view=users", { waitUntil: "networkidle" });

    const navigation = page.getByRole("navigation", {
      name: "Primary navigation",
    });
    const navigationWidths = await navigation.evaluate((element) => ({
      client: element.clientWidth,
      scroll: element.scrollWidth,
    }));
    expect(navigationWidths.scroll - navigationWidths.client).toBeLessThanOrEqual(1);
    for (const label of ["Repositories", "Runners", "Access"]) {
      await expect(
        navigation.getByRole("link", { name: label, exact: true }),
      ).toBeInViewport({ ratio: 1 });
    }

    const wordmarkLabel = page.locator(".wordmark__label");
    const themeLabel = page.locator(".theme-toggle span");
    if (layout.compact) {
      await expect(wordmarkLabel).toBeHidden();
      await expect(themeLabel).toBeHidden();
      await expect(page.locator(".demo-badge__compact")).toBeVisible();
    } else {
      await expect(wordmarkLabel).toBeVisible();
      await expect(themeLabel).toBeVisible();
      await expect(page.locator(".demo-badge__wide")).toBeVisible();
    }
    await expectNoDocumentOverflow(page);
  }
});

test("keyboard users can bypass chrome and keep focused mobile navigation visible", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });

  for (const previewPage of previewPages) {
    await page.goto(previewPage.url);
    const skipLink = page.getByRole("link", { name: "Skip to content" });
    await expect(skipLink, previewPage.name).toBeVisible();
    await page.keyboard.press("Tab");
    await expect(skipLink).toBeFocused();
    await expect(skipLink).toBeInViewport({ ratio: 1 });
    expect(await hasVisibleOutline(skipLink)).toBe(true);

    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/#main-content$/u);
    const content = page.locator("#main-content");
    await expect(content).toBeFocused();
    const firstContentControl = content.locator([
      'a[href]:visible',
      'button:not([disabled]):visible',
      'input:not([disabled]):not([type="hidden"]):visible',
      'select:not([disabled]):visible',
      'textarea:not([disabled]):visible',
      'summary:visible',
      '[tabindex="0"]:visible',
    ].join(", ")).first();
    if (await firstContentControl.isVisible()) {
      await page.keyboard.press("Tab");
      await expect
        .poll(() =>
          page.evaluate(() => {
            const content = document.querySelector("#main-content");
            return content?.contains(document.activeElement) === true;
          }),
        )
        .toBe(true);
    }
  }

  await page.goto("./?view=runs");
  const workflowDisclosure = getNativeDisclosure(page, "Workflows");
  await tabUntilFocused(page, workflowDisclosure);
  await page.keyboard.press("Enter");
  await expect
    .poll(() => nativeDisclosureIsOpen(workflowDisclosure))
    .toBe(true);
  const releaseLink = page
    .getByRole("navigation", { name: "Actions navigation" })
    .getByRole("link", { name: "Release", exact: true });
  await tabUntilFocused(page, releaseLink);
  await expect(releaseLink).toBeInViewport({ ratio: 1 });
  expect(await hasVisibleOutline(releaseLink)).toBe(true);
});

test("responsive navigation exposes one landmark and an operable mobile disclosure", async ({
  page,
}) => {
  const navigationCases = [
    {
      url: "./?view=runs",
      disclosureName: "Workflows",
      navigationName: "Actions navigation",
      linkName: "Release",
    },
    {
      url: "./?view=run",
      disclosureName: "Workflow run",
      navigationName: "Run navigation",
      linkName: /Linux release build/u,
    },
    {
      url: "./?view=job&job=job-1",
      disclosureName: "Workflow run",
      navigationName: "Run navigation",
      linkName: /Workspace tests/u,
    },
  ] as const;

  for (const viewport of [
    { width: 1440, height: 900 },
    { width: 768, height: 1024 },
  ]) {
    await page.setViewportSize(viewport);
    for (const navigationCase of navigationCases) {
      await page.goto(navigationCase.url);
      await expect(
        page.getByRole("navigation", { name: navigationCase.navigationName }),
      ).toHaveCount(1);
      await expect(
        getNativeDisclosure(page, navigationCase.disclosureName),
      ).toHaveCount(0);
    }
  }

  await page.setViewportSize({ width: 390, height: 844 });
  for (const navigationCase of navigationCases) {
    await page.goto(navigationCase.url);
    const disclosure = getNativeDisclosure(page, navigationCase.disclosureName);
    const navigation = page.getByRole("navigation", {
      name: navigationCase.navigationName,
    });
    await expect(disclosure).toHaveCount(1);
    expect(await nativeDisclosureIsOpen(disclosure)).toBe(false);
    await expect(navigation).toHaveCount(0);

    await disclosure.click();
    expect(await nativeDisclosureIsOpen(disclosure)).toBe(true);
    await expect(navigation).toHaveCount(1);
    await expect(
      navigation.getByRole("link", { name: navigationCase.linkName }),
    ).toBeVisible();

    await disclosure.click();
    expect(await nativeDisclosureIsOpen(disclosure)).toBe(false);
    await expect(navigation).toHaveCount(0);
  }
});

test("capacity pagers remain visible, singular, and outside navigation landmarks", async ({
  page,
}) => {
  const cases = [
    {
      url: "./?view=runs",
      label: "Workflow pages",
      target: ".workflow-navigation",
    },
    {
      url: "./?view=run",
      label: "Run job pages",
      target: "#jobs-heading",
    },
    {
      url: "./?view=job&job=job-1",
      label: "Run job pages",
      target: ".run-navigation",
    },
  ] as const;

  for (const width of [1_440, 390, 320]) {
    await page.setViewportSize({ width, height: 844 });
    for (const capacityCase of cases) {
      await page.goto(capacityCase.url, { waitUntil: "networkidle" });
      const target = page.locator(capacityCase.target).first();
      await target.evaluate(
        (element, { markup, selectParent }) => {
          const container = selectParent ? element.parentElement : element;
          if (container === null) {
            throw new Error("The capacity-pagination container is missing");
          }
          container.insertAdjacentHTML("beforeend", markup);
        },
        {
          markup: capacityPaginationMarkup(capacityCase.label),
          selectParent: capacityCase.target === "#jobs-heading",
        },
      );

      const pager = page.getByRole("navigation", {
        name: capacityCase.label,
      });
      await expect(pager).toHaveCount(1);
      await expect(pager).toBeVisible();
      await expect(page.locator("nav nav")).toHaveCount(0);
      const next = pager.getByRole("link", { name: "Next" });
      await next.focus();
      await expect(next).toBeFocused();
      expect(await hasVisibleOutline(next)).toBe(true);
      await expectNoDocumentOverflow(page);
    }
  }
});

test("narrow and 200%-equivalent layouts keep overflow inside local regions", async ({
  page,
}) => {
  for (const width of [640, 390, 320]) {
    await page.setViewportSize({ width, height: 720 });
    for (const previewPage of previewPages) {
      await page.goto(previewPage.url, { waitUntil: "networkidle" });
      await waitForStableRender(page, previewPage.heading);
      await expectNoDocumentOverflow(page);
    }
  }
});

test("run summaries fill their container with and without source metadata", async ({
  page,
}) => {
  const layouts = [
    { width: 1440, rowsWithSource: 1, rowsWithoutSource: 1 },
    { width: 1012, rowsWithSource: 2, rowsWithoutSource: 2 },
    { width: 768, rowsWithSource: 2, rowsWithoutSource: 2 },
    { width: 390, rowsWithSource: 4, rowsWithoutSource: 3 },
  ] as const;

  for (const layout of layouts) {
    await page.setViewportSize({ width: layout.width, height: 800 });
    for (const run of [
      { id: PRIMARY_RUN_ID, rows: layout.rowsWithSource },
      { id: SECONDARY_RUN_ID, rows: layout.rowsWithoutSource },
    ]) {
      await page.goto(`./?view=run&run=${run.id}`);
      const summaryLayout = await runSummaryLayout(page);
      expect(summaryLayout.rows).toBe(run.rows);
      expect(summaryLayout.trailingGap).toBeLessThanOrEqual(1);
      await expectNoDocumentOverflow(page);
    }
  }
});

test("job log controls respond to available content width", async ({ page }) => {
  const layouts = [
    { width: 1012, direction: "row" },
    { width: 768, direction: "column" },
    { width: 767, direction: "row" },
    { width: 390, direction: "column" },
  ] as const;

  for (const layout of layouts) {
    await page.setViewportSize({ width: layout.width, height: 800 });
    await page.goto("./?view=job&job=job-1");

    const toolbar = page.locator(".log-toolbar");
    await expect(toolbar).toHaveCSS("flex-direction", layout.direction);
    if (layout.direction === "column") {
      const searchBox = await page
        .getByRole("searchbox", { name: "Search job logs" })
        .boundingBox();
      const expandButton = await page
        .getByRole("button", { name: "Expand all", exact: true })
        .boundingBox();
      expect(searchBox).not.toBeNull();
      expect(expandButton).not.toBeNull();
    }
    await expectNoDocumentOverflow(page);
  }
});

for (const width of [1440, 390, 320]) {
  test(`validator-scale unbroken content cannot widen the ${width}px document`, async ({
    page,
  }) => {
    const label = "L".repeat(1_024);
    const longCopy = "C".repeat(4_096);
    const hexadecimalIdentifier = "a".repeat(64);
    const digest = "b".repeat(64);

    await page.setViewportSize({ width, height: 720 });

    await page.goto("./?view=runs", { waitUntil: "networkidle" });
    await openNavigationIfCollapsed(page, "Workflows");
    const runsMain = page.getByRole("main");
    const primaryRun = getRunList(runsMain).getByRole("listitem").first();
    await replaceText(page.locator(".wordmark__label"), label);
    await replaceText(
      page.locator(".repo-header__identity a > span:first-child"),
      label,
    );
    await replaceText(page.locator(".site-footer span"), label);
    await replaceText(
      runsMain
        .getByRole("navigation", { name: "Actions navigation" })
        .getByRole("link", {
          name: "Release",
          exact: true,
        }),
      label,
    );
    await replaceText(
      primaryRun.getByRole("link", {
        name: "Build and test release candidate",
      }),
      label,
    );
    await replaceText(primaryRun.getByText("main", { exact: true }), label);
    await replaceText(
      primaryRun.getByText("26713a8", { exact: true }),
      hexadecimalIdentifier,
    );
    await replaceText(
      primaryRun.getByText("Make macro diagnostics cache-independent", {
        exact: true,
      }),
      longCopy,
    );
    await expectNoDocumentOverflow(page);

    await page.goto("./?view=run", { waitUntil: "networkidle" });
    await openNavigationIfCollapsed(page, "Workflow run");
    const runMain = page.getByRole("main");
    const runSummary = runMain.getByRole("region", { name: "Run summary" });
    const jobs = runMain.getByRole("region", { name: "Jobs" });
    const artifacts = runMain.getByRole("region", { name: "Artifacts" });
    await replaceText(runMain.getByRole("heading", { level: 1 }), label);
    await replaceText(runMain.locator(".heading-status .status__label"), label);
    await replaceText(
      runMain.locator(".heading-status > span:last-child"),
      longCopy,
    );
    await replaceText(
      runMain
        .getByRole("navigation", { name: "Run navigation" })
        .getByText("Linux release build", { exact: true }),
      label,
    );
    await replaceText(
      jobs.getByText("Linux release build", { exact: true }),
      label,
    );
    await replaceText(runSummary.getByText("main", { exact: true }), label);
    await replaceText(
      runSummary.getByText("26713a8", { exact: true }),
      hexadecimalIdentifier,
    );
    await replaceText(
      runSummary.getByText("Make macro diagnostics cache-independent", {
        exact: true,
      }),
      longCopy,
    );
    await replaceText(
      artifacts.getByText("workspace-test-results", { exact: true }),
      label,
    );
    await replaceText(artifacts.getByText(/^SHA-256 /u), `SHA-256 ${digest}`);
    await replaceText(artifacts.locator(".artifact-list > li > span"), label);
    await expectNoDocumentOverflow(page);

    await page.goto("./?view=job&job=job-1", { waitUntil: "networkidle" });
    const jobMain = page.getByRole("main");
    await replaceText(jobMain.getByRole("heading", { level: 1 }), label);
    await replaceText(jobMain.locator(".heading-status .status__label"), label);
    await replaceText(
      jobMain.locator(".heading-status > span:last-child"),
      longCopy,
    );
    await replaceText(
      jobMain.getByRole("link", {
        name: "Run #1842: Build and test release candidate",
      }),
      label,
    );
    await replaceText(jobMain.locator(".log-toolbar > div:first-child > span"), label);
    await replaceText(jobMain.locator(".log-group__output code").first(), longCopy);
    await expectNoDocumentOverflow(page);
  });
}

test("reduced motion removes continuous animation and long transitions", async ({
  page,
}) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("./?view=run", { waitUntil: "networkidle" });

  await expect
    .poll(() =>
      page.evaluate(
        () => matchMedia("(prefers-reduced-motion: reduce)").matches,
      ),
    )
    .toBe(true);
  const motion = await page.evaluate(() =>
    [...document.querySelectorAll("*")]
      .map((element) => {
        const style = getComputedStyle(element);
        return {
          animationDuration: style.animationDuration,
          animationIterationCount: style.animationIterationCount,
          animationName: style.animationName,
          transitionDuration: style.transitionDuration,
        };
      })
      .filter(
        (style) =>
          style.animationName !== "none" ||
          style.transitionDuration
            .split(",")
            .some((duration) => duration.trim() !== "0s"),
      ),
  );

  for (const style of motion) {
    expect(style.animationIterationCount).not.toContain("infinite");
    expect(
      longestDurationInMilliseconds(style.animationDuration),
    ).toBeLessThanOrEqual(10);
    expect(
      longestDurationInMilliseconds(style.transitionDuration),
    ).toBeLessThanOrEqual(10);
  }
});

test("forced colors preserves landmarks, controls, and visible keyboard focus", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.emulateMedia({ forcedColors: "active", reducedMotion: "reduce" });

  for (const previewPage of previewPages) {
    await page.goto(previewPage.url, { waitUntil: "networkidle" });
    await expect(page.getByRole("main")).toBeVisible();
    await expect
      .poll(() =>
        page.evaluate(() => matchMedia("(forced-colors: active)").matches),
      )
      .toBe(true);
    await expectNoDocumentOverflow(page);

    const skipLink = page.getByRole("link", { name: "Skip to content" });
    await expect(skipLink).toBeVisible();
    await page.keyboard.press("Tab");
    await expect(skipLink).toBeFocused();
    await expect(skipLink).toBeInViewport({ ratio: 1 });
    expect(await hasVisibleOutline(skipLink)).toBe(true);
  }

  await page.goto("./?view=runs", { waitUntil: "networkidle" });
  const filter = page.getByRole("searchbox", {
    name: "Filter runs by branch or Git ref",
  });
  await filter.focus();
  expect(await hasVisibleOutline(filter)).toBe(true);
});

test("authorized RBAC controls preserve keyboard focus in forced colors", async ({
  page,
}) => {
  await page.emulateMedia({ forcedColors: "active", reducedMotion: "reduce" });
  await page.goto("./?view=bindings", { waitUntil: "networkidle" });
  await page.getByRole("main").evaluate((main) => {
    const nativeForm = document.createElement("form");
    nativeForm.className = "rbac-native-form";
    const input = document.createElement("input");
    input.setAttribute("aria-label", "Role display name");
    const select = document.createElement("select");
    select.setAttribute("aria-label", "Role scope");
    select.append(new Option("Entire tenant", "tenant"));
    const textarea = document.createElement("textarea");
    textarea.setAttribute("aria-label", "Reason for disabling");
    nativeForm.append(input, select, textarea);

    const revokeForm = document.createElement("form");
    revokeForm.className = "rbac-inline-revoke";
    const revokeReason = document.createElement("input");
    revokeReason.setAttribute("aria-label", "Revocation reason");
    revokeForm.append(revokeReason);
    main.append(nativeForm, revokeForm);
  });
  for (const control of [
    page.getByRole("textbox", { name: "Role display name" }),
    page.getByRole("combobox", { name: "Role scope" }),
    page.getByRole("textbox", { name: "Reason for disabling" }),
    page.getByRole("textbox", { name: "Revocation reason" }),
  ]) {
    await control.focus();
    expect(await hasVisibleOutline(control)).toBe(true);
  }
});

test("clipped log regions keep focus rings visible and keyboard scrolling local", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("./?view=job&job=job-1", { waitUntil: "networkidle" });
  const output = page.getByRole("region", {
    name: "Linux release build log output",
  });
  await output.focus();
  await expect(output).toBeFocused();
  await expect(output).toHaveCSS("outline-offset", "-2px");
  expect(await horizontalScrollMetrics(output)).toMatchObject({ scrollLeft: 0 });

  for (let count = 0; count < 5; count += 1) {
    await page.keyboard.press("ArrowRight");
  }
  await expect
    .poll(async () => (await horizontalScrollMetrics(output)).scrollLeft)
    .toBeGreaterThan(0);
  await expectNoDocumentOverflow(page);

  const lineLink = output.getByRole("link", { name: "Link to log line 7" });
  await lineLink.focus();
  await expect(lineLink).toBeFocused();
  await expect(lineLink).toHaveCSS("outline-offset", "-2px");
  expect(await hasVisibleOutline(lineLink)).toBe(true);
});

test("bidirectional log text stays isolated in its message cell", async ({
  page,
}) => {
  await page.goto("./?view=job&job=job-1", { waitUntil: "networkidle" });
  const firstLine = page.locator(".log-line").first();
  const timestamp = firstLine.locator("time");
  const message = firstLine.locator("code");
  await replaceText(message, "بدء مهمة إصدار لينكس");

  await expect(message).toHaveCSS("direction", "ltr");
  await expect(message).toHaveCSS("unicode-bidi", "plaintext");
  const timestampBox = await timestamp.boundingBox();
  const messageBox = await message.boundingBox();
  expect(timestampBox).not.toBeNull();
  expect(messageBox).not.toBeNull();
  expect(messageBox?.x ?? 0).toBeGreaterThanOrEqual(
    (timestampBox?.x ?? 0) + (timestampBox?.width ?? 0) - 1,
  );
  await expectNoDocumentOverflow(page);
});

test("RBAC landmarks stay unique and role deletion requires explicit confirmation", async ({
  page,
}) => {
  await page.goto("./?view=role&role=release-reviewer", {
    waitUntil: "networkidle",
  });
  await expect(
    page.getByRole("main").getByRole("region", { name: "Permissions" }),
  ).toHaveCount(1);

  const main = page.getByRole("main");
  await main.evaluate((mainElement) => {
    const formStack = document.createElement("div");
    formStack.className = "rbac-form-stack";
    formStack.innerHTML = `
      <details class="rbac-delete-disclosure">
        <summary>Delete role</summary>
        <div class="rbac-delete-disclosure__confirmation">
          <p>Delete <strong>Release reviewer</strong>? This can’t be undone.</p>
          <form action="/settings/access/roles/test-role/delete" class="rbac-native-form" method="post">
            <button class="button button--danger" type="submit">Confirm delete</button>
          </form>
        </div>
      </details>
    `;
    const roleDetails = mainElement.querySelector("#role-details-heading")
      ?.closest("section");
    if (roleDetails === null || roleDetails === undefined) {
      throw new Error("The role-details panel is missing");
    }
    roleDetails.querySelector(".rbac-read-only")?.remove();
    roleDetails.append(formStack);
  });

  const disclosure = main.locator("details.rbac-delete-disclosure");
  const summary = disclosure.locator("summary");
  const form = disclosure.locator('form[action$="/delete"]');
  const confirm = form.getByRole("button", { name: "Confirm delete" });
  await form.evaluate((element) => {
    element.addEventListener("submit", (event) => {
      event.preventDefault();
      const submissions = Number(element.dataset.testSubmissions ?? "0") + 1;
      element.dataset.testSubmissions = String(submissions);
    });
  });

  await expect(disclosure).not.toHaveAttribute("open", "");
  await expect(form).toBeHidden();
  await summary.focus();
  expect(await hasVisibleOutline(summary)).toBe(true);
  await summary.click();
  await expect(disclosure).toHaveAttribute("open", "");
  await expect(form).toBeVisible();
  await expect(form).not.toHaveAttribute("data-test-submissions", "1");

  await confirm.click();
  await expect(form).toHaveAttribute("data-test-submissions", "1");
});

test("primary routes do not emit console, page, or request errors", async ({
  page,
}) => {
  const runtimeIssues = collectRuntimeIssues(page);

  for (const previewPage of previewPages) {
    await page.goto(previewPage.url, { waitUntil: "networkidle" });
    await waitForStableRender(page, previewPage.heading);
  }

  expect(runtimeIssues).toEqual([]);
});

function getRunList(main: Locator): Locator {
  return main
    .getByRole("region", { name: /workflow runs$/u })
    .getByRole("list");
}

function collectRuntimeIssues(page: Page): string[] {
  const issues: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") {
      issues.push(`console: ${message.text()}`);
    }
  });
  page.on("pageerror", (error) => issues.push(`page: ${error.message}`));
  page.on("requestfailed", (request) => {
    issues.push(
      `request: ${request.url()} (${request.failure()?.errorText ?? "unknown failure"})`,
    );
  });
  return issues;
}

async function waitForStableRender(page: Page, heading: string): Promise<void> {
  await page.evaluate(async () => document.fonts.ready);
  await expect(page.getByRole("main")).toBeVisible();
  await expect(
    page.getByRole("heading", { level: 1, name: heading }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: /^Use (?:light|dark) theme$/u }),
  ).toBeEnabled();
  await page.evaluate(
    () =>
      new Promise<void>((resolve) => {
        requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
      }),
  );
}

async function expectNoDocumentOverflow(page: Page): Promise<void> {
  await expect
    .poll(() =>
      page.evaluate(
        () =>
          document.documentElement.scrollWidth -
          document.documentElement.clientWidth,
      ),
    )
    .toBeLessThanOrEqual(1);
}

async function expectPreviewPresentation(
  page: Page,
  viewport: { readonly width: number; readonly height: number },
  colorScheme: (typeof colorSchemes)[number],
): Promise<void> {
  const themeContract = themePresentationContracts[colorScheme];
  await expect.poll(() => activeTheme(page)).toBe(colorScheme);
  await expect.poll(() => bodyBackground(page)).toBe(themeContract.background);
  await expect(
    page.getByRole("button", { name: themeContract.toggleName }),
  ).toBeVisible();

  for (const selector of [".site-header", "#main-content", ".site-footer"]) {
    const landmark = page.locator(selector);
    await expect(landmark).toHaveCount(1);
    await expect(landmark).toBeVisible();
  }

  const layout = await page.evaluate(() => {
    const bounds = (selector: string) => {
      const element = document.querySelector(selector);
      if (!(element instanceof HTMLElement)) {
        throw new Error(`Missing presentation landmark: ${selector}`);
      }
      const rectangle = element.getBoundingClientRect();
      return {
        bottom: rectangle.bottom,
        height: rectangle.height,
        left: rectangle.left,
        right: rectangle.right,
        top: rectangle.top,
        width: rectangle.width,
      };
    };

    return {
      content: bounds("#main-content"),
      footer: bounds(".site-footer"),
      header: bounds(".site-header"),
      viewportHeight: window.innerHeight,
      viewportWidth: window.innerWidth,
    };
  });

  expect(layout.viewportWidth).toBe(viewport.width);
  expect(layout.viewportHeight).toBe(viewport.height);
  for (const landmark of [layout.header, layout.content, layout.footer]) {
    expect(landmark.height).toBeGreaterThan(0);
    expect(landmark.width).toBeGreaterThan(0);
    expect(landmark.left).toBeGreaterThanOrEqual(-1);
    expect(landmark.right).toBeLessThanOrEqual(viewport.width + 1);
  }
  expect(layout.header.top).toBeGreaterThanOrEqual(-1);
  expect(layout.content.top).toBeGreaterThanOrEqual(layout.header.bottom - 1);
  expect(layout.footer.top).toBeGreaterThanOrEqual(layout.content.bottom - 1);
}

async function hasVisibleOutline(locator: Locator): Promise<boolean> {
  return locator.evaluate((element) => {
    const style = getComputedStyle(element);
    return (
      style.outlineStyle !== "none" &&
      Number.parseFloat(style.outlineWidth) >= 2
    );
  });
}

async function visibleTextControlPresentation(root: Locator): Promise<readonly {
  readonly background: string;
  readonly borderRadius: number;
  readonly borderWidth: number;
  readonly fontFamily: string;
  readonly height: number;
  readonly inheritedFontFamily: string;
}[]> {
  return root
    .locator(
      'input:not([type="hidden"]):not([type="checkbox"]):not([type="radio"]), select, textarea',
    )
    .evaluateAll((elements) =>
      elements.flatMap((element) => {
        if (!(element instanceof HTMLElement) || element.offsetParent === null) {
          return [];
        }
        const style = getComputedStyle(element);
        const bodyStyle = getComputedStyle(document.body);
        return [{
          background: style.backgroundColor,
          borderRadius: Number.parseFloat(style.borderTopLeftRadius),
          borderWidth: Number.parseFloat(style.borderTopWidth),
          fontFamily: style.fontFamily,
          height: element.getBoundingClientRect().height,
          inheritedFontFamily: bodyStyle.fontFamily,
        }];
      }),
    );
}

async function replaceText(
  locator: Locator,
  replacement: string,
): Promise<void> {
  await locator.evaluate((element, text) => {
    element.textContent = text;
  }, replacement);
}

async function nativeDisclosureIsOpen(disclosure: Locator): Promise<boolean> {
  return disclosure.evaluate((element) => {
    const details = element.closest("details");
    return details instanceof HTMLDetailsElement && details.open;
  });
}

async function openNavigationIfCollapsed(
  page: Page,
  disclosureName: string,
): Promise<void> {
  const disclosure = getNativeDisclosure(page, disclosureName);
  if (
    (await disclosure.count()) === 1 &&
    !(await nativeDisclosureIsOpen(disclosure))
  ) {
    await disclosure.click();
  }
}

function getNativeDisclosure(page: Page, name: string): Locator {
  return page
    .locator("details > summary:visible")
    .filter({ hasText: new RegExp(`^${name}`, "u") });
}

async function tabUntilFocused(page: Page, locator: Locator): Promise<void> {
  for (let tabCount = 0; tabCount < 30; tabCount += 1) {
    if (
      await locator.evaluate((element) => element === document.activeElement)
    ) {
      return;
    }
    await page.keyboard.press("Tab");
  }
  await expect(locator).toBeFocused();
}

async function bodyBackground(page: Page): Promise<string> {
  return page.evaluate(() => getComputedStyle(document.body).backgroundColor);
}

async function activeTheme(page: Page): Promise<string | undefined> {
  return page.evaluate(() => document.documentElement.dataset.theme);
}

async function contrastRatio(locator: Locator): Promise<number> {
  const colors = await locator.evaluate((element) => {
    const style = getComputedStyle(element);
    return { background: style.backgroundColor, foreground: style.color };
  });
  const foreground = relativeLuminance(parseRgb(colors.foreground));
  const background = relativeLuminance(parseRgb(colors.background));

  return (
    (Math.max(foreground, background) + 0.05) /
    (Math.min(foreground, background) + 0.05)
  );
}

function parseRgb(color: string): readonly [number, number, number] {
  const channels = color.match(/[\d.]+/gu)?.slice(0, 3).map(Number);
  if (channels?.length !== 3) {
    throw new Error(`expected an opaque RGB color, received ${color}`);
  }
  const normalizedChannels = color.startsWith("color(srgb ")
    ? channels.map((channel) => channel * 255)
    : channels;
  return normalizedChannels as unknown as readonly [number, number, number];
}

function relativeLuminance(channels: readonly number[]): number {
  const [red = 0, green = 0, blue = 0] = channels.map((channel) => {
    const normalized = channel / 255;
    return normalized <= 0.04045
      ? normalized / 12.92
      : ((normalized + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * red + 0.7152 * green + 0.0722 * blue;
}

async function runSummaryLayout(
  page: Page,
): Promise<{ readonly rows: number; readonly trailingGap: number }> {
  return page.locator(".run-summary").evaluate((summary) => {
    const summaryBox = summary.getBoundingClientRect();
    const itemBoxes = [...summary.children].map((item) =>
      item.getBoundingClientRect(),
    );
    const finalItem = itemBoxes.at(-1);

    return {
      rows: new Set(itemBoxes.map((item) => Math.round(item.top * 10) / 10))
        .size,
      trailingGap:
        finalItem === undefined ? summaryBox.width : summaryBox.right - finalItem.right,
    };
  });
}

async function horizontalScrollMetrics(
  locator: Locator,
): Promise<{
  readonly clientWidth: number;
  readonly scrollLeft: number;
  readonly scrollWidth: number;
}> {
  return locator.evaluate((element) => ({
    clientWidth: element.clientWidth,
    scrollLeft: element.scrollLeft,
    scrollWidth: element.scrollWidth,
  }));
}

function longestDurationInMilliseconds(durationList: string): number {
  return Math.max(
    ...durationList.split(",").map((duration) => {
      const value = Number.parseFloat(duration);
      return duration.trim().endsWith("ms") ? value : value * 1000;
    }),
  );
}

function capacityPaginationMarkup(label: string): string {
  return [
    `<nav aria-label="${label}" class="pagination">`,
    '<span aria-disabled="true" class="button button--quiet">Previous</span>',
    '<a class="button button--quiet" href="#next-capacity-page" rel="next">Next</a>',
    "</nav>",
  ].join("");
}

async function cumulativeLayoutShift(page: Page): Promise<number> {
  return page.evaluate(() =>
    (
      window as unknown as Window & {
        readonly __automataLayoutShifts: readonly number[];
      }
    ).__automataLayoutShifts.reduce((total, value) => total + value, 0),
  );
}

async function observeLayoutShifts(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const layoutShifts: number[] = [];
    Object.defineProperty(window, "__automataLayoutShifts", {
      value: layoutShifts,
    });
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        const shift = entry as PerformanceEntry & {
          readonly hadRecentInput: boolean;
          readonly value: number;
        };
        if (!shift.hadRecentInput) {
          layoutShifts.push(shift.value);
        }
      }
    }).observe({ buffered: true, type: "layout-shift" });
  });
}
