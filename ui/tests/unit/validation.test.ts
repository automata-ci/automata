import { describe, expect, it } from "vitest";
import type { RenderRequest } from "../../src/models";
import { parseRenderRequest } from "../../src/serialization";
import {
  MAX_SERIALIZED_RENDER_REQUEST_BYTES,
  RENDER_REQUEST_LIMITS,
  utf8ByteLength,
  validateRenderRequest,
} from "../../src/validation";
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

type PathSegment = string | number;

interface UrlFieldCase {
  readonly request: RenderRequest;
  readonly path: readonly PathSegment[];
  readonly expectedErrorPath: string;
}

const routeFields: readonly UrlFieldCase[] = [
  routeCase(runListRequest, ["page", "shell", "homeHref"]),
  routeCase(repositoryDirectoryRequest, ["page", "shell", "signIn", "action"]),
  routeCase(repositoryDirectoryRequest, ["page", "shell", "signIn", "returnPath"]),
  routeCase(repositoryDirectoryRequest, ["page", "repositories", 0, "actionsHref"]),
  routeCase(repositorySecretsDirectoryRequest, [
    "page",
    "repositories",
    0,
    "settingsHref",
  ]),
  routeCase(repositoryDirectoryRequest, ["page", "pagination", "nextHref"]),
  routeCase(runListRequest, ["page", "shell", "signOut", "action"]),
  routeCase(runListRequest, ["page", "shell", "navigation", 0, "href"]),
  routeCase(runListRequest, ["page", "repository", "runsHref"]),
  routeCase(runListRequest, ["page", "filters", "action"]),
  routeCase(runListRequest, ["page", "filters", "clearHref"]),
  routeCase(runListRequest, [
    "page",
    "workflowNavigation",
    "workflows",
    0,
    "href",
  ]),
  routeCase(runListRequest, [
    "page",
    "workflowNavigation",
    "pagination",
    "nextHref",
  ]),
  routeCase(runListRequest, ["page", "runs", 0, "workflowHref"]),
  routeCase(runListRequest, ["page", "runs", 0, "href"]),
  routeCase(runListRequest, ["page", "pagination", "previousHref"]),
  routeCase(runListRequest, ["page", "pagination", "nextHref"]),
  routeCase(runDetailRequest, ["page", "run", "workflowHref"]),
  routeCase(runDetailRequest, ["page", "jobs", "items", 0, "href"]),
  routeCase(runDetailRequest, ["page", "jobPagination", "nextHref"]),
  routeCase(runDetailRequest, [
    "page",
    "artifacts",
    "items",
    0,
    "downloadHref",
  ]),
  routeCase(jobLogRequest, ["page", "run", "href"]),
  routeCase(jobLogRequest, ["page", "run", "workflowHref"]),
  routeCase(jobLogRequest, ["page", "jobs", 0, "href"]),
  routeCase(jobLogRequest, ["page", "navigationPagination", "nextHref"]),
  routeCase(jobLogRequest, ["page", "job", "href"]),
  routeCase(jobLogRequest, ["page", "live", "ticketHref"]),
  routeCase(repositorySettingsRequest, ["page", "repository", "settingsHref"]),
  routeCase(repositorySettingsRequest, ["page", "update", "action"]),
  routeCase(userListRequest, ["page", "managementNav", "usersHref"]),
  routeCase(userListRequest, ["page", "users", 0, "href"]),
  routeCase(userDetailRequest, ["page", "roleAssignments", 0, "bindingHref"]),
  routeCase(userDetailRequest, ["page", "roleAssignments", 0, "roleHref"]),
  routeCase(roleListRequest, ["page", "roles", 0, "href"]),
  routeCase(directBindingListRequest, [
    "page",
    "bindings",
    0,
    "principal",
    "href",
  ]),
  routeCase(directBindingListRequest, ["page", "bindings", 0, "role", "href"]),
];

const fuzzableStringFields: readonly (readonly PathSegment[])[] = [
  ["host", "locale"],
  ["page", "shell", "productName"],
  ["page", "shell", "documentTitle"],
  ["page", "repository", "owner"],
  ["page", "repository", "name"],
  ["page", "run", "name"],
  ["page", "run", "number"],
  ["page", "run", "status", "label"],
  ["page", "jobs", "items", 0, "name"],
  ["page", "artifacts", "items", 0, "name"],
];

function rejectsNoncurrentRenderRequestSchema(): void {
  const input = cloneRequest(runDetailRequest);
  setPath(input, ["schemaVersion"], 2);
  expect(() => validateRenderRequest(input)).toThrow("at $.schemaVersion");
}

describe("render request validation", () => {
  it(
    "rejects a noncurrent render-request schema",
    rejectsNoncurrentRenderRequestSchema,
  );

  it.each([
    ["repository-directory", repositoryDirectoryRequest],
    ["runner-directory", runnerDirectoryRequest],
    ["repository-directory-secrets", repositorySecretsDirectoryRequest],
    ["run-list", runListRequest],
    ["run-detail", runDetailRequest],
    ["job-log", jobLogRequest],
    ["deep-link-sign-in", deepLinkSignInRequest],
    ["repository-settings", repositorySettingsRequest],
  ])("deeply accepts the complete %s contract", (_kind, request) => {
    expect(parseRenderRequest(JSON.stringify(request))).toEqual(request);
    expect(validateRenderRequest(structuredClone(request))).toEqual(request);
  });

  it("binds repository-directory rows to exact source and authorized destinations", () => {
    const codeOnly = cloneRequest(repositoryDirectoryRequest);
    setPath(codeOnly, ["page", "repositories", 0, "actionsHref"], null);
    expect(() => validateRenderRequest(codeOnly)).not.toThrow();

    const wrongSource = cloneRequest(repositoryDirectoryRequest);
    setPath(
      wrongSource,
      ["page", "repositories", 0, "sourceHref"],
      "https://example.test/automata-ci/automata",
    );
    expect(() => validateRenderRequest(wrongSource)).toThrow(
      "at $.page.repositories[0].sourceHref",
    );

    const wrongActions = cloneRequest(repositoryDirectoryRequest);
    setPath(
      wrongActions,
      ["page", "repositories", 0, "actionsHref"],
      "/automata-ci/automata/settings/access",
    );
    expect(() => validateRenderRequest(wrongActions)).toThrow(
      "at $.page.repositories[0].actionsHref",
    );

    const anonymousSettings = cloneRequest(repositoryDirectoryRequest);
    setPath(
      anonymousSettings,
      ["page", "repositories", 0, "settingsHref"],
      "/automata-ci/automata/settings/access",
    );
    expect(() => validateRenderRequest(anonymousSettings)).toThrow(
      "at $.page.repositories[0].settingsHref",
    );

    const wrongSettings = cloneRequest(repositorySecretsDirectoryRequest);
    setPath(
      wrongSettings,
      ["page", "repositories", 0, "settingsHref"],
      "/automata-ci/automata/settings/provider",
    );
    expect(() => validateRenderRequest(wrongSettings)).toThrow(
      "at $.page.repositories[0].settingsHref",
    );
  });

  it("rejects repository-directory duplicates and non-page pagination copy", () => {
    const duplicate = cloneRequest(repositoryDirectoryRequest);
    getArray(duplicate, ["page", "repositories"]).push({
      owner: "AUTOMATA-CI",
      name: "AUTOMATA",
      sourceHref: "https://github.com/AUTOMATA-CI/AUTOMATA",
      actionsHref: "/AUTOMATA-CI/AUTOMATA/actions",
      settingsHref: null,
    });
    setPath(
      duplicate,
      ["page", "pagination", "label"],
      "2 repositories on this page",
    );
    expect(() => validateRenderRequest(duplicate)).toThrow(
      "at $.page.repositories[1].name",
    );

    const totalClaim = cloneRequest(repositoryDirectoryRequest);
    setPath(totalClaim, ["page", "pagination", "label"], "1 repository");
    expect(() => validateRenderRequest(totalClaim)).toThrow(
      "at $.page.pagination.label",
    );

    const aliasedCursor = cloneRequest(repositoryDirectoryRequest);
    setPath(
      aliasedCursor,
      ["page", "pagination", "nextHref"],
      "/repositories?cursor=next%2Dpage",
    );
    expect(() => validateRenderRequest(aliasedCursor)).toThrow(
      "at $.page.pagination.nextHref",
    );
  });

  it("reports a precise nested path without reflecting hostile data", () => {
    const input = cloneRequest(runDetailRequest);
    setPath(
      input,
      ["page", "jobs", "items", 0, "status", "tone"],
      "<script>bad()</script>",
    );

    expect(() => validateRenderRequest(input)).toThrow(
      "Invalid Automata render request at $.page.jobs.items[0].status.tone",
    );
    try {
      validateRenderRequest(input);
    } catch (error) {
      expect(String(error)).not.toContain("<script>");
    }
  });

  it("requires a CSP nonce before any executable document can render", () => {
    const input = cloneRequest(runListRequest);
    const host = getRecord(input, ["host"]);
    delete host.cspNonce;

    expect(() => validateRenderRequest(input)).toThrow("at $.host.cspNonce");
  });

  it.each([
    ["unknown schema", ["schemaVersion"], 2, "$.schemaVersion"],
    ["invalid locale", ["host", "locale"], "../../en", "$.host.locale"],
    ["unsupported locale", ["host", "locale"], "fr", "$.host.locale"],
    [
      "invalid nonce",
      ["host", "cspNonce"],
      "nonce with spaces",
      "$.host.cspNonce",
    ],
    ["wrong page kind", ["page", "kind"], "dashboard", "$.page.kind"],
    [
      "invalid status",
      ["page", "run", "status", "tone"],
      "done",
      "$.page.run.status.tone",
    ],
    [
      "unknown status label",
      ["page", "run", "status", "label"],
      "Almost done",
      "$.page.run.status.label",
    ],
    [
      "mismatched status label",
      ["page", "run", "status", "label"],
      "Succeeded",
      "$.page.run.status.tone",
    ],
    [
      "invalid timestamp",
      ["page", "run", "createdAt", "iso"],
      "yesterday",
      "$.page.run.createdAt.iso",
    ],
    [
      "fractional attempt",
      ["page", "run", "attempt"],
      1.5,
      "$.page.run.attempt",
    ],
    [
      "invalid digest",
      ["page", "artifacts", "items", 0, "digest"],
      "sha256:nope",
      "$.page.artifacts.items[0].digest",
    ],
    [
      "uppercase digest",
      ["page", "artifacts", "items", 0, "digest"],
      "A".repeat(64),
      "$.page.artifacts.items[0].digest",
    ],
    [
      "uppercase short SHA",
      ["page", "run", "commit", "shortSha"],
      "26713A8",
      "$.page.run.commit.shortSha",
    ],
  ] as const)("rejects %s", (_name, path, replacement, errorPath) => {
    const input = cloneRequest(runDetailRequest);
    setPath(input, path, replacement);
    expect(() => validateRenderRequest(input)).toThrow(`at ${errorPath}`);
  });

  it("rejects unknown fields at every object boundary", () => {
    const input = cloneRequest(runListRequest);
    const filters = getRecord(input, ["page", "filters"]);
    filters.unversionedBehavior = true;
    expect(() => validateRenderRequest(input)).toThrow(
      "at $.page.filters.unversionedBehavior",
    );
  });

  it("validates all three publication audiences independently", () => {
    const acceptedPolicies = [
      { dashboard: "public", logs: "authenticated", artifacts: "private" },
      { dashboard: "private", logs: "public", artifacts: "authenticated" },
    ] as const;
    for (const policy of acceptedPolicies) {
      const input = cloneRequest(repositorySettingsRequest);
      getRecord(input, ["page"]).policy = policy;
      expect(() => validateRenderRequest(input)).not.toThrow();
    }

    for (const field of ["dashboard", "logs", "artifacts"] as const) {
      const input = cloneRequest(repositorySettingsRequest);
      getRecord(input, ["page", "policy"])[field] = "everyone";
      expect(() => validateRenderRequest(input)).toThrow(
        `at $.page.policy.${field}`,
      );
    }
  });

  it("keeps the publication revision lossless and current-only", () => {
    const maximum = cloneRequest(repositorySettingsRequest);
    getRecord(maximum, ["page"]).revision = "9223372036854775807";
    getRecord(maximum, ["page"]).update = null;
    expect(() => validateRenderRequest(maximum)).not.toThrow();

    const unadvanceable = cloneRequest(repositorySettingsRequest);
    getRecord(unadvanceable, ["page"]).revision = "9223372036854775807";
    expect(() => validateRenderRequest(unadvanceable)).toThrow(
      "at $.page.revision",
    );

    for (const revision of [7, "0", "07", "9223372036854775808", "7.0"]) {
      const input = cloneRequest(repositorySettingsRequest);
      getRecord(input, ["page"]).revision = revision;
      expect(() => validateRenderRequest(input)).toThrow("at $.page.revision");
    }
  });

  it("treats action and CSRF as one optional update capability", () => {
    const readOnly = cloneRequest(repositorySettingsRequest);
    getRecord(readOnly, ["page"]).update = null;
    expect(() => validateRenderRequest(readOnly)).not.toThrow();

    const legacyReason = cloneRequest(repositorySettingsRequest);
    getRecord(legacyReason, ["page"]).readOnlyReason = "permission";
    expect(() => validateRenderRequest(legacyReason)).toThrow(
      "at $.page.readOnlyReason",
    );

    const anonymous = cloneRequest(repositorySettingsRequest);
    getRecord(anonymous, ["page", "shell"]).viewer = null;
    getRecord(anonymous, ["page", "shell"]).signOut = null;
    expect(() => validateRenderRequest(anonymous)).toThrow(
      "at $.page.repository.settingsHref",
    );

    const missingToken = cloneRequest(repositorySettingsRequest);
    delete getRecord(missingToken, ["page", "update"]).csrfToken;
    expect(() => validateRenderRequest(missingToken)).toThrow(
      "at $.page.update.csrfToken",
    );

    const hostileToken = "<script>do-not-reflect-this-token</script>";
    const malformedToken = cloneRequest(repositorySettingsRequest);
    getRecord(malformedToken, ["page", "update"]).csrfToken = hostileToken;
    try {
      validateRenderRequest(malformedToken);
      throw new Error("Malformed CSRF token unexpectedly passed validation");
    } catch (error) {
      expect(String(error)).toContain("at $.page.update.csrfToken");
      expect(String(error)).not.toContain(hostileToken);
    }
  });

  it("requires an authorized settings GET destination on the settings page", () => {
    const input = cloneRequest(repositorySettingsRequest);
    getRecord(input, ["page", "repository"]).settingsHref = null;

    expect(() => validateRenderRequest(input)).toThrow(
      "at $.page.repository.settingsHref",
    );
  });

  it("validates lossless positive run numbers on every page kind", () => {
    const cases: readonly {
      readonly request: RenderRequest;
      readonly path: readonly PathSegment[];
      readonly errorPath: string;
    }[] = [
      {
        request: runListRequest,
        path: ["page", "runs", 0, "number"],
        errorPath: "$.page.runs[0].number",
      },
      {
        request: runDetailRequest,
        path: ["page", "run", "number"],
        errorPath: "$.page.run.number",
      },
      {
        request: jobLogRequest,
        path: ["page", "run", "number"],
        errorPath: "$.page.run.number",
      },
    ];

    for (const testCase of cases) {
      const maximum = cloneRequest(testCase.request);
      setPath(maximum, testCase.path, "18446744073709551615");
      expect(() => validateRenderRequest(maximum)).not.toThrow();

      for (const invalidNumber of [
        1842,
        "0",
        "01842",
        "18446744073709551616",
      ]) {
        const input = cloneRequest(testCase.request);
        setPath(input, testCase.path, invalidNumber);
        expect(() => validateRenderRequest(input)).toThrow(
          `at ${testCase.errorPath}`,
        );
      }
    }
  });

  it("enforces collection bounds before traversing their contents", () => {
    const input = cloneRequest(runListRequest);
    setPath(
      input,
      ["page", "runs"],
      Array.from({ length: RENDER_REQUEST_LIMITS.runCount + 1 }, () => null),
    );
    expect(() => validateRenderRequest(input)).toThrow(
      `expected an array with at most ${RENDER_REQUEST_LIMITS.runCount} items`,
    );
  });

  it("enforces text bounds", () => {
    const input = cloneRequest(runListRequest);
    setPath(
      input,
      ["page", "heading"],
      "x".repeat(RENDER_REQUEST_LIMITS.shortTextLength + 1),
    );
    expect(() => validateRenderRequest(input)).toThrow("at $.page.heading");

    const multibyte = cloneRequest(runListRequest);
    setPath(
      multibyte,
      ["page", "heading"],
      "é".repeat(RENDER_REQUEST_LIMITS.shortTextLength / 2 + 1),
    );
    expect(() => validateRenderRequest(multibyte)).toThrow("at $.page.heading");
  });

  it.each([
    "",
    "   ",
    "\u200B\uFE0F",
    "\u3164",
    "Visible\ncontrol",
    "safe\u202Efdp.exe",
  ])("rejects unusable display copy %#", (replacement) => {
    const input = cloneRequest(runListRequest);
    setPath(input, ["page", "heading"], replacement);
    expect(() => validateRenderRequest(input)).toThrow("at $.page.heading");
  });

  it("allows default-ignorable code points inside otherwise visible copy", () => {
    const input = cloneRequest(runListRequest);
    setPath(input, ["page", "heading"], "Deploy\u200Dservice");
    expect(() => validateRenderRequest(input)).not.toThrow();
  });

  it("keeps durable commit subjects within the 1,024-byte source bound", () => {
    const input = cloneRequest(runListRequest);
    setPath(
      input,
      ["page", "runs", 0, "commit", "message"],
      "x".repeat(RENDER_REQUEST_LIMITS.shortTextLength + 1),
    );
    expect(() => validateRenderRequest(input)).toThrow(
      "at $.page.runs[0].commit.message",
    );
  });

  it.each([
    "2023-02-29T00:00:00Z",
    "2024-02-30T00:00:00Z",
    "2026-01-01T24:00:00Z",
    "2026-01-01T23:60:00Z",
    "2026-01-01T23:59:60Z",
    "2026-01-01T23:59:59+24:00",
  ])("rejects the non-existent RFC 3339 timestamp %s", (timestamp) => {
    const input = cloneRequest(runDetailRequest);
    setPath(input, ["page", "run", "createdAt", "iso"], timestamp);
    expect(() => validateRenderRequest(input)).toThrow(
      "at $.page.run.createdAt.iso",
    );
  });

  it("rejects sparse collections that serialize differently from their in-memory shape", () => {
    const input = cloneRequest(runListRequest);
    setPath(input, ["page", "shell", "navigation"], new Array(1));
    expect(() => validateRenderRequest(input)).toThrow(
      "at $.page.shell.navigation[0]",
    );
  });

  it("rejects duplicate keyed collection values", () => {
    const input = cloneRequest(runListRequest);
    const runs = getArray(input, ["page", "runs"]);
    const duplicate = structuredClone(runs[0]);
    runs.push(duplicate);
    expect(() => validateRenderRequest(input)).toThrow("at $.page.runs[2].id");

    const duplicateHref = cloneRequest(runListRequest);
    const hrefRuns = getArray(duplicateHref, ["page", "runs"]);
    getRecord(hrefRuns, [1]).href = getRecord(hrefRuns, [0]).href;
    expect(() => validateRenderRequest(duplicateHref)).toThrow(
      "at $.page.runs[1].href",
    );
  });

  it("rejects status filters outside the UI-owned closed select options", () => {
    const missingSelection = cloneRequest(runListRequest);
    setPath(missingSelection, ["page", "filters", "status"], "missing");
    expect(() => validateRenderRequest(missingSelection)).toThrow(
      "at $.page.filters.status",
    );
  });

  it.each([" main", "main ", "\u200B", "main\u202E"])(
    "rejects unsafe or non-canonical branch filter state %j",
    (branch) => {
      const input = cloneRequest(runListRequest);
      setPath(input, ["page", "filters", "branch"], branch);

      expect(() => validateRenderRequest(input)).toThrow(
        "at $.page.filters.branch",
      );
    },
  );

  it("binds filter submission and clearing to the selected workflow", () => {
    const wrongAction = cloneRequest(runListRequest);
    setPath(wrongAction, ["page", "filters", "action"], "/unrelated");
    expect(() => validateRenderRequest(wrongAction)).toThrow(
      "at $.page.filters.action",
    );

    const wrongClear = cloneRequest(runListRequest);
    setPath(wrongClear, ["page", "filters", "clearHref"], "/unrelated");
    expect(() => validateRenderRequest(wrongClear)).toThrow(
      "at $.page.filters.clearHref",
    );

    if (
      runListRequest.page.kind !== "run-list" ||
      runListRequest.page.workflowNavigation === null ||
      runListRequest.page.workflowNavigation.workflows[1] === undefined
    ) {
      throw new Error("The release workflow fixture is unavailable");
    }
    const release = runListRequest.page.workflowNavigation.workflows[1];
    const selected = cloneRequest(runListRequest);
    const workflowHref = release.href;
    setPath(
      selected,
      ["page", "workflowNavigation", "selectedWorkflow"],
      release,
    );
    setPath(selected, ["page", "filters", "action"], workflowHref);
    setPath(selected, ["page", "filters", "clearHref"], workflowHref);
    expect(() => validateRenderRequest(selected)).not.toThrow();
  });

  it("requires one unambiguous current primary-navigation item", () => {
    const noneCurrent = cloneRequest(runListRequest);
    delete getRecord(noneCurrent, ["page", "shell", "navigation", 2]).current;
    expect(() => validateRenderRequest(noneCurrent)).toThrow(
      "at $.page.shell.navigation",
    );

    const twoCurrent = cloneRequest(runListRequest);
    getArray(twoCurrent, ["page", "shell", "navigation"]).push({
      label: "Another current item",
      href: "/other",
      current: true,
    });
    expect(() => validateRenderRequest(twoCurrent)).toThrow(
      "at $.page.shell.navigation",
    );
  });

  it("accepts nullable Automata destinations as explicit nulls", () => {
    const landing = cloneRequest(repositoryDirectoryRequest);
    setPath(landing, ["page", "shell", "signIn"], null);
    expect(() => validateRenderRequest(landing)).not.toThrow();

    const detail = cloneRequest(runDetailRequest);
    setPath(detail, ["page", "artifacts", "items", 0, "downloadHref"], null);
    expect(() => validateRenderRequest(detail)).not.toThrow();
  });

  it("binds sign-in actions to anonymous GitHub login", () => {
    const authenticated = cloneRequest(runListRequest);
    setPath(authenticated, ["page", "shell", "signIn"], {
      action: "/auth/github/login",
      returnPath: "/repositories",
    });
    expect(() => validateRenderRequest(authenticated)).toThrow(
      "at $.page.shell.signIn",
    );

    const wrongAction = cloneRequest(repositoryDirectoryRequest);
    setPath(wrongAction, ["page", "shell", "signIn", "action"], "/login");
    expect(() => validateRenderRequest(wrongAction)).toThrow(
      "at $.page.shell.signIn.action",
    );

    for (const returnPath of [
      "?view=runs",
      "#main-content",
      "//evil.invalid/path",
      `/${"x".repeat(2_048)}`,
    ]) {
      const invalidReturn = cloneRequest(repositoryDirectoryRequest);
      setPath(
        invalidReturn,
        ["page", "shell", "signIn", "returnPath"],
        returnPath,
      );
      expect(() => validateRenderRequest(invalidReturn)).toThrow(
        "at $.page.shell.signIn.returnPath",
      );
    }
  });

  it("treats authenticated sign-out as one exact shell capability", () => {
    const unavailable = cloneRequest(runListRequest);
    setPath(unavailable, ["page", "shell", "signOut"], null);
    expect(() => validateRenderRequest(unavailable)).not.toThrow();

    const anonymous = cloneRequest(repositoryDirectoryRequest);
    setPath(anonymous, ["page", "shell", "signOut"], {
      action: "/auth/logout",
      csrfToken: SHELL_CSRF_TOKEN,
    });
    expect(() => validateRenderRequest(anonymous)).toThrow(
      "at $.page.shell.signOut",
    );

    const wrongAction = cloneRequest(runListRequest);
    setPath(wrongAction, ["page", "shell", "signOut", "action"], "/logout");
    expect(() => validateRenderRequest(wrongAction)).toThrow(
      "at $.page.shell.signOut.action",
    );

    const missingToken = cloneRequest(runListRequest);
    delete getRecord(missingToken, ["page", "shell", "signOut"]).csrfToken;
    expect(() => validateRenderRequest(missingToken)).toThrow(
      "at $.page.shell.signOut.csrfToken",
    );

    const unknownField = cloneRequest(runListRequest);
    getRecord(unknownField, ["page", "shell", "signOut"]).returnPath = "/repositories";
    expect(() => validateRenderRequest(unknownField)).toThrow(
      "at $.page.shell.signOut.returnPath",
    );

    for (const csrfToken of [
      "A".repeat(42),
      "A".repeat(44),
      `${"A".repeat(42)}B`,
      `${"A".repeat(41)}+AA`,
    ]) {
      const malformedToken = cloneRequest(runListRequest);
      setPath(
        malformedToken,
        ["page", "shell", "signOut", "csrfToken"],
        csrfToken,
      );
      expect(() => validateRenderRequest(malformedToken)).toThrow(
        "at $.page.shell.signOut.csrfToken",
      );
    }
  });

  it("binds repository updates to the displayed settings destination", () => {
    const input = cloneRequest(repositorySettingsRequest);
    setPath(input, ["page", "update", "action"], "/unrelated/settings");
    expect(() => validateRenderRequest(input)).toThrow(
      "at $.page.update.action",
    );
  });

  it("bounds the canonical Git reference represented by a branch filter", () => {
    const boundary = cloneRequest(runListRequest);
    setPath(
      boundary,
      ["page", "filters", "branch"],
      "a".repeat(1_024 - "refs/heads/".length),
    );
    expect(() => validateRenderRequest(boundary)).not.toThrow();

    const oversized = cloneRequest(runListRequest);
    setPath(
      oversized,
      ["page", "filters", "branch"],
      "a".repeat(1_025 - "refs/heads/".length),
    );
    expect(() => validateRenderRequest(oversized)).toThrow(
      "at $.page.filters.branch",
    );
  });

  it.each([
    [
      "source repository",
      runListRequest,
      ["page", "repository", "sourceHref"],
      "$.page.repository.sourceHref",
    ],
    [
      "run-list workflow",
      runListRequest,
      ["page", "runs", 0, "workflowHref"],
      "$.page.runs[0].workflowHref",
    ],
    [
      "run-list commit",
      runListRequest,
      ["page", "runs", 0, "commit", "href"],
      "$.page.runs[0].commit.href",
    ],
    [
      "run-detail workflow",
      runDetailRequest,
      ["page", "run", "workflowHref"],
      "$.page.run.workflowHref",
    ],
    [
      "run-detail commit",
      runDetailRequest,
      ["page", "run", "commit", "href"],
      "$.page.run.commit.href",
    ],
    [
      "job-log workflow",
      jobLogRequest,
      ["page", "run", "workflowHref"],
      "$.page.run.workflowHref",
    ],
  ] as const)(
    "requires the %s destination",
    (_name, request, path, errorPath) => {
      const input = cloneRequest(request);
      setPath(input, path, null);
      expect(() => validateRenderRequest(input)).toThrow(`at ${errorPath}`);
    },
  );

  it("accepts absent durable metadata as explicit nulls", () => {
    const list = cloneRequest(runListRequest);
    setPath(list, ["page", "runs", 0, "sourceRef"], null);
    setPath(list, ["page", "runs", 0, "actor"], null);
    setPath(list, ["page", "runs", 0, "commit", "message"], null);
    setPath(list, ["page", "runs", 1, "durationLabel"], null);
    expect(() => validateRenderRequest(list)).not.toThrow();

    const detail = cloneRequest(runDetailRequest);
    setPath(detail, ["page", "run", "sourceRef"], null);
    setPath(detail, ["page", "run", "actor"], null);
    setPath(detail, ["page", "run", "commit", "message"], null);
    setPath(detail, ["page", "jobs", "items", 0, "runnerLabel"], null);
    setPath(detail, ["page", "artifacts", "items", 0, "expiresAt"], null);
    expect(() => validateRenderRequest(detail)).not.toThrow();

    const jobLog = cloneRequest(jobLogRequest);
    setPath(jobLog, ["page", "job", "runnerLabel"], null);
    expect(() => validateRenderRequest(jobLog)).not.toThrow();
  });

  it("models result visibility atomically and rejects the removed step projection", () => {
    for (const visibility of ["full", "restricted"] as const) {
      const input = cloneRequest(runDetailRequest);
      setPath(input, ["page", "jobs", "visibility"], visibility);
      setPath(input, ["page", "artifacts", "visibility"], visibility);
      expect(() => validateRenderRequest(input)).not.toThrow();
    }

    const unknownVisibility = cloneRequest(runDetailRequest);
    setPath(unknownVisibility, ["page", "jobs", "visibility"], "partial");
    expect(() => validateRenderRequest(unknownVisibility)).toThrow(
      "at $.page.jobs.visibility",
    );

    const formerArray = cloneRequest(runDetailRequest);
    setPath(formerArray, ["page", "jobs"], []);
    expect(() => validateRenderRequest(formerArray)).toThrow("at $.page.jobs");

    const formerSteps = cloneRequest(runDetailRequest);
    getRecord(formerSteps, ["page", "jobs", "items", 0]).steps = [];
    expect(() => validateRenderRequest(formerSteps)).toThrow(
      "at $.page.jobs.items[0].steps",
    );
  });

  it("requires distinct result destinations", () => {
    const duplicateJobHref = cloneRequest(runDetailRequest);
    const jobs = getArray(duplicateJobHref, ["page", "jobs", "items"]);
    jobs.push({
      ...structuredClone(getRecord(jobs, [0])),
      id: "job-duplicate-href",
    });
    expect(() => validateRenderRequest(duplicateJobHref)).toThrow(
      "at $.page.jobs.items[1].href",
    );

    const duplicateArtifactHref = cloneRequest(runDetailRequest);
    const artifacts = getArray(duplicateArtifactHref, [
      "page",
      "artifacts",
      "items",
    ]);
    artifacts.push({
      ...structuredClone(getRecord(artifacts, [0])),
      id: "artifact-duplicate-href",
    });
    expect(() => validateRenderRequest(duplicateArtifactHref)).toThrow(
      "at $.page.artifacts.items[1].downloadHref",
    );
  });

  it.each([
    [
      "run list",
      runListRequest,
      ["page", "runs", 1, "durationLabel"],
      "$.page.runs[1].durationLabel",
    ],
    [
      "run detail",
      runDetailRequest,
      ["page", "run", "durationLabel"],
      "$.page.run.durationLabel",
    ],
    [
      "run-detail job",
      runDetailRequest,
      ["page", "jobs", "items", 0, "durationLabel"],
      "$.page.jobs.items[0].durationLabel",
    ],
    [
      "selected log job",
      jobLogRequest,
      ["page", "job", "durationLabel"],
      "$.page.job.durationLabel",
    ],
  ] as const)(
    "rejects an empty recorded duration on the %s",
    (_name, request, path, errorPath) => {
      const input = cloneRequest(request);
      setPath(input, path, "");

      expect(() => validateRenderRequest(input)).toThrow(`at ${errorPath}`);
    },
  );

  it.each([
    [
      runListRequest,
      ["page", "runs", 0, "sourceRef"],
      false,
      "$.page.runs[0].sourceRef",
    ],
    [
      runListRequest,
      ["page", "runs", 0, "actor"],
      false,
      "$.page.runs[0].actor",
    ],
    [
      runListRequest,
      ["page", "runs", 0, "commit", "message"],
      false,
      "$.page.runs[0].commit.message",
    ],
    [
      runDetailRequest,
      ["page", "jobs", "items", 0, "runnerLabel"],
      false,
      "$.page.jobs.items[0].runnerLabel",
    ],
    [
      runDetailRequest,
      ["page", "artifacts", "items", 0, "expiresAt"],
      false,
      "$.page.artifacts.items[0].expiresAt",
    ],
    [
      jobLogRequest,
      ["page", "job", "runnerLabel"],
      false,
      "$.page.job.runnerLabel",
    ],
    [
      runListRequest,
      ["page", "runs", 0, "durationLabel"],
      false,
      "$.page.runs[0].durationLabel",
    ],
    [
      runDetailRequest,
      ["page", "run", "durationLabel"],
      false,
      "$.page.run.durationLabel",
    ],
    [
      runDetailRequest,
      ["page", "jobs", "items", 0, "durationLabel"],
      false,
      "$.page.jobs.items[0].durationLabel",
    ],
    [
      jobLogRequest,
      ["page", "job", "durationLabel"],
      false,
      "$.page.job.durationLabel",
    ],
  ] as const)(
    "rejects a non-null value with the wrong optional metadata type",
    (request, path, replacement, errorPath) => {
      const input = cloneRequest(request);
      setPath(input, path, replacement);
      expect(() => validateRenderRequest(input)).toThrow(`at ${errorPath}`);
    },
  );

  it("uses createdAt, not the former startedAt field, for list rows", () => {
    const input = cloneRequest(runListRequest);
    const run = getRecord(input, ["page", "runs", 0]);
    run.startedAt = run.createdAt;
    delete run.createdAt;

    expect(() => validateRenderRequest(input)).toThrow(
      "at $.page.runs[0].startedAt",
    );
  });

  it("treats source refs as one atomic object", () => {
    const missingSourceRef = cloneRequest(runDetailRequest);
    delete getRecord(missingSourceRef, ["page", "run"]).sourceRef;
    expect(() => validateRenderRequest(missingSourceRef)).toThrow(
      "at $.page.run.sourceRef",
    );

    for (const field of ["name", "kind", "href"] as const) {
      const missingField = cloneRequest(runDetailRequest);
      delete getRecord(missingField, ["page", "run", "sourceRef"])[field];
      expect(() => validateRenderRequest(missingField)).toThrow(
        `at $.page.run.sourceRef.${field}`,
      );
    }

    const unknownField = cloneRequest(runDetailRequest);
    getRecord(unknownField, ["page", "run", "sourceRef"]).branchHref =
      "https://github.com/automata-ci/automata/tree/main";
    expect(() => validateRenderRequest(unknownField)).toThrow(
      "at $.page.run.sourceRef.branchHref",
    );
  });

  it.each([
    ["csrfToken", "$.page.csrfToken"],
    ["operations", "$.page.operations"],
  ] as const)(
    "rejects the removed run mutation field %s",
    (field, errorPath) => {
      const input = cloneRequest(runDetailRequest);
      getRecord(input, ["page"])[field] =
        field === "operations" ? [] : "legacy-token";

      expect(() => validateRenderRequest(input)).toThrow(`at ${errorPath}`);
    },
  );

  it.each([
    [
      "repository href",
      runListRequest,
      ["page", "repository"],
      "href",
      "/automata-ci/automata",
      "$.page.repository.href",
    ],
    [
      "run-list branch",
      runListRequest,
      ["page", "runs", 0],
      "branch",
      "main",
      "$.page.runs[0].branch",
    ],
    [
      "run-detail branch",
      runDetailRequest,
      ["page", "run"],
      "branch",
      "main",
      "$.page.run.branch",
    ],
    [
      "run-detail branch href",
      runDetailRequest,
      ["page", "run"],
      "branchHref",
      "/branches/main",
      "$.page.run.branchHref",
    ],
    [
      "run-detail ID",
      runDetailRequest,
      ["page", "run"],
      "id",
      PRIMARY_RUN_ID,
      "$.page.run.id",
    ],
    [
      "job-log run ID",
      jobLogRequest,
      ["page", "run"],
      "id",
      PRIMARY_RUN_ID,
      "$.page.run.id",
    ],
    [
      "job-log run status",
      jobLogRequest,
      ["page", "run"],
      "status",
      { label: "In progress", tone: "running" },
      "$.page.run.status",
    ],
  ] as const)(
    "rejects the removed wire field %s",
    (_name, request, objectPath, field, value, errorPath) => {
      const input = cloneRequest(request);
      getRecord(input, objectPath)[field] = value;

      expect(() => validateRenderRequest(input)).toThrow(`at ${errorPath}`);
    },
  );

  it("accepts exact branch, tag, and pull-request source mappings", () => {
    const branch = cloneRequest(runListRequest);
    setPath(
      branch,
      ["page", "runs", 0, "sourceRef", "name"],
      "feature/release #1",
    );
    setPath(
      branch,
      ["page", "runs", 0, "sourceRef", "href"],
      "https://github.com/automata-ci/automata/tree/feature%2Frelease%20%231",
    );
    expect(() => validateRenderRequest(branch)).not.toThrow();

    const tag = cloneRequest(runDetailRequest);
    setPath(tag, ["page", "run", "sourceRef", "kind"], "tag");
    setPath(tag, ["page", "run", "sourceRef", "name"], "v1.2.3");
    setPath(
      tag,
      ["page", "run", "sourceRef", "href"],
      "https://github.com/automata-ci/automata/tree/v1.2.3",
    );
    expect(() => validateRenderRequest(tag)).not.toThrow();

    for (const suffix of ["head", "merge"] as const) {
      const pullRequest = cloneRequest(runDetailRequest);
      setPath(pullRequest, ["page", "run", "sourceRef", "kind"], "ref");
      setPath(
        pullRequest,
        ["page", "run", "sourceRef", "name"],
        `pull/42/${suffix}`,
      );
      setPath(
        pullRequest,
        ["page", "run", "sourceRef", "href"],
        "https://github.com/automata-ci/automata/pull/42",
      );
      expect(() => validateRenderRequest(pullRequest)).not.toThrow();
    }
  });

  it.each([
    [
      "source route in place of GitHub",
      ["page", "repository", "sourceHref"],
      "/automata-ci/automata",
      "$.page.repository.sourceHref",
    ],
    [
      "GitHub lookalike host",
      ["page", "repository", "sourceHref"],
      "https://github.com.evil.invalid/automata-ci/automata",
      "$.page.repository.sourceHref",
    ],
    [
      "repository query",
      ["page", "repository", "sourceHref"],
      "https://github.com/automata-ci/automata?tab=readme",
      "$.page.repository.sourceHref",
    ],
    [
      "commit from another repository",
      ["page", "runs", 0, "commit", "href"],
      "https://github.com/automata-ci/other/commit/26713a895eb6744012da74726e59230a259357c4",
      "$.page.runs[0].commit.href",
    ],
    [
      "commit with mismatched display SHA",
      ["page", "runs", 0, "commit", "href"],
      "https://github.com/automata-ci/automata/commit/deadbeef5eb6744012da74726e59230a259357c4",
      "$.page.runs[0].commit.href",
    ],
    [
      "commit query",
      ["page", "runs", 0, "commit", "href"],
      "https://github.com/automata-ci/automata/commit/26713a895eb6744012da74726e59230a259357c4?diff=split",
      "$.page.runs[0].commit.href",
    ],
    [
      "unencoded branch path",
      ["page", "runs", 0, "sourceRef", "href"],
      "https://github.com/automata-ci/automata/tree/main/escape",
      "$.page.runs[0].sourceRef.href",
    ],
  ] as const)(
    "rejects a non-canonical SCM %s",
    (_name, path, href, errorPath) => {
      const input = cloneRequest(runListRequest);
      setPath(input, path, href);
      expect(() => validateRenderRequest(input)).toThrow(`at ${errorPath}`);
    },
  );

  it("binds every SCM destination to the declared repository identity", () => {
    const repositoryMismatch = cloneRequest(runListRequest);
    setPath(repositoryMismatch, ["page", "repository", "owner"], "other-owner");
    expect(() => validateRenderRequest(repositoryMismatch)).toThrow(
      "at $.page.repository.sourceHref",
    );

    const childLinkMismatch = cloneRequest(runListRequest);
    setPath(
      childLinkMismatch,
      ["page", "repository", "sourceHref"],
      "https://github.com/automata-ci/automata-renamed",
    );
    setPath(
      childLinkMismatch,
      ["page", "repository", "name"],
      "automata-renamed",
    );
    expect(() => validateRenderRequest(childLinkMismatch)).toThrow(
      "at $.page.runs[0].sourceRef.href",
    );
  });

  it.each([
    [
      "unknown kind",
      "branchish",
      "main",
      "https://github.com/automata-ci/automata/tree/main",
      "$.page.run.sourceRef.kind",
    ],
    [
      "arbitrary ref",
      "ref",
      "refs/pull/42/merge",
      "https://github.com/automata-ci/automata/pull/42",
      "$.page.run.sourceRef.name",
    ],
    [
      "zero pull ref",
      "ref",
      "pull/0/merge",
      "https://github.com/automata-ci/automata/pull/0",
      "$.page.run.sourceRef.name",
    ],
    [
      "oversized pull ref",
      "ref",
      "pull/18446744073709551616/merge",
      "https://github.com/automata-ci/automata/pull/18446744073709551616",
      "$.page.run.sourceRef.name",
    ],
    [
      "pull files view",
      "ref",
      "pull/42/merge",
      "https://github.com/automata-ci/automata/pull/42/files",
      "$.page.run.sourceRef.href",
    ],
    [
      "pull URL for branch",
      "branch",
      "main",
      "https://github.com/automata-ci/automata/pull/42",
      "$.page.run.sourceRef.href",
    ],
  ] as const)(
    "rejects the unsupported source-ref mapping %s",
    (_name, kind, name, href, errorPath) => {
      const input = cloneRequest(runDetailRequest);
      setPath(input, ["page", "run", "sourceRef", "kind"], kind);
      setPath(input, ["page", "run", "sourceRef", "name"], name);
      setPath(input, ["page", "run", "sourceRef", "href"], href);
      expect(() => validateRenderRequest(input)).toThrow(`at ${errorPath}`);
    },
  );

  it("validates supplied workflow navigation and its selected workflow", () => {
    const inconsistent = cloneRequest(runListRequest);
    const firstWorkflow = getRecord(inconsistent, [
      "page",
      "workflowNavigation",
      "workflows",
      0,
    ]);
    setPath(
      inconsistent,
      ["page", "workflowNavigation", "selectedWorkflow"],
      { ...firstWorkflow, name: "Different name" },
    );
    expect(() => validateRenderRequest(inconsistent)).toThrow(
      "at $.page.workflowNavigation.workflows[0]",
    );

    const duplicate = cloneRequest(runListRequest);
    const workflows = getArray(duplicate, [
      "page",
      "workflowNavigation",
      "workflows",
    ]);
    workflows.push(structuredClone(workflows[0]));
    expect(() => validateRenderRequest(duplicate)).toThrow(
      "at $.page.workflowNavigation.workflows[2].id",
    );

    const duplicateHref = cloneRequest(runListRequest);
    const hrefWorkflows = getArray(duplicateHref, [
      "page",
      "workflowNavigation",
      "workflows",
    ]);
    getRecord(hrefWorkflows, [1]).href = getRecord(hrefWorkflows, [0]).href;
    expect(() => validateRenderRequest(duplicateHref)).toThrow(
      "at $.page.workflowNavigation.workflows[1].href",
    );

    const invalidEnabled = cloneRequest(runListRequest);
    setPath(
      invalidEnabled,
      ["page", "workflowNavigation", "workflows", 1, "enabled"],
      "false",
    );
    expect(() => validateRenderRequest(invalidEnabled)).toThrow(
      "at $.page.workflowNavigation.workflows[1].enabled",
    );

    const allWorkflowsOnly = cloneRequest(runListRequest);
    setPath(allWorkflowsOnly, ["page", "workflowNavigation"], null);
    expect(() => validateRenderRequest(allWorkflowsOnly)).not.toThrow();
  });

  it("admits bounded workflow and job pages without unbounded renderer vectors", () => {
    const workflowsRequest = cloneRequest(runListRequest);
    const navigation = getRecord(workflowsRequest, [
      "page",
      "workflowNavigation",
    ]);
    const workflowTemplate = getRecord(navigation, ["workflows", 0]);
    navigation.workflows = Array.from({ length: 250 }, (_, index) => ({
      ...workflowTemplate,
      id: `workflow-${index}`,
      name: `Workflow ${index + 1}`,
      href: `/automata-ci/automata/actions/workflows/workflow-${index}`,
    }));
    const selectedWorkflow = {
      ...workflowTemplate,
      id: "workflow-250",
      name: "Workflow 251",
      href: "/automata-ci/automata/actions/workflows/workflow-250",
    };
    navigation.selectedWorkflow = selectedWorkflow;
    navigation.pagination = {
      previousHref: null,
      nextHref:
        "/automata-ci/automata/actions/workflows/workflow-250?status=completed&cursor=run_page&workflow_cursor=workflow_page",
      label: "250 workflows",
    };
    setPath(
      workflowsRequest,
      ["page", "filters", "action"],
      selectedWorkflow.href,
    );
    setPath(
      workflowsRequest,
      ["page", "filters", "clearHref"],
      selectedWorkflow.href,
    );
    expect(() => validateRenderRequest(workflowsRequest)).not.toThrow();
    getArray(workflowsRequest, [
      "page",
      "workflowNavigation",
      "workflows",
    ]).push({
      ...workflowTemplate,
      id: "workflow-overflow",
      href: "/automata-ci/automata/actions/workflows/workflow-overflow",
    });
    expect(() => validateRenderRequest(workflowsRequest)).toThrow(
      "at $.page.workflowNavigation.workflows",
    );

    const detail = cloneRequest(runDetailRequest);
    const detailJobs = getArray(detail, ["page", "jobs", "items"]);
    const detailJob = getRecord(detailJobs, [0]);
    detailJobs.splice(
      0,
      detailJobs.length,
      ...Array.from({ length: 200 }, (_, index) => ({
        ...detailJob,
        id: `job-${index}`,
        name: `Job ${index + 1}`,
        href: `/automata-ci/automata/actions/runs/${PRIMARY_RUN_ID}/jobs/job-${index}`,
      })),
    );
    setPath(
      detail,
      ["page", "jobPagination", "nextHref"],
      `/automata-ci/automata/actions/runs/${PRIMARY_RUN_ID}?job_cursor=next_jobs`,
    );
    expect(() => validateRenderRequest(detail)).not.toThrow();
    detailJobs.push({
      ...detailJob,
      id: "job-200",
      href: `/automata-ci/automata/actions/runs/${PRIMARY_RUN_ID}/jobs/job-200`,
    });
    expect(() => validateRenderRequest(detail)).toThrow("at $.page.jobs.items");
  });

  it("requires a consistent selected navigation job", () => {
    const missingSelectedJob = cloneRequest(jobLogRequest);
    setPath(missingSelectedJob, ["page", "job", "id"], "unknown-job");
    expect(() => validateRenderRequest(missingSelectedJob)).toThrow(
      "at $.page.job.id",
    );

    for (const [path, replacement] of [
      [["page", "job", "name"], "Different job"],
      [["page", "job", "href"], "/different-job"],
    ] as const) {
      const mismatched = cloneRequest(jobLogRequest);
      setPath(mismatched, path, replacement);
      expect(() => validateRenderRequest(mismatched)).toThrow(
        "at $.page.job",
      );
    }

    const mismatchedStatus = cloneRequest(jobLogRequest);
    setPath(mismatchedStatus, ["page", "job", "status", "label"], "Queued");
    setPath(mismatchedStatus, ["page", "job", "status", "tone"], "queued");
    expect(() => validateRenderRequest(mismatchedStatus)).toThrow(
      "at $.page.job",
    );

    const duplicateJobHref = cloneRequest(jobLogRequest);
    const navigationJobs = getArray(duplicateJobHref, ["page", "jobs"]);
    getRecord(navigationJobs, [1]).href = getRecord(navigationJobs, [0]).href;
    expect(() => validateRenderRequest(duplicateJobHref)).toThrow(
      "at $.page.jobs[1].href",
    );
  });

  it.each([
    [
      "navigation job query",
      ["page", "jobs", 0, "href"],
      "/job?existing=1",
      "$.page.jobs[0].href",
    ],
    [
      "selected job fragment",
      ["page", "job", "href"],
      "/job#output",
      "$.page.job.href",
    ],
  ] as const)(
    "rejects a job-log %s",
    (_name, path, replacement, errorPath) => {
      const input = cloneRequest(jobLogRequest);
      setPath(input, path, replacement);
      expect(() => validateRenderRequest(input)).toThrow(
        `Invalid Automata render request at ${errorPath}: expected a query- and fragment-free job-log destination`,
      );
    },
  );

  it("rejects an equality-consistent job-log destination with URL metadata", () => {
    const input = cloneRequest(jobLogRequest);
    const destination = "/job?existing=1#output";
    setPath(input, ["page", "jobs", 0, "href"], destination);
    setPath(input, ["page", "job", "href"], destination);
    expect(() => validateRenderRequest(input)).toThrow(
      "Invalid Automata render request at $.page.jobs[0].href: expected a query- and fragment-free job-log destination",
    );
  });

  it("validates the structured live-log ticket contract", () => {
    const malformed = cloneRequest(jobLogRequest);
    setPath(malformed, ["page", "live", "ticketHref"], "/wrong/live-ticket");
    expect(() => validateRenderRequest(malformed)).toThrow(
      "at $.page.live.ticketHref",
    );

    const legacyState = cloneRequest(jobLogRequest);
    setPath(legacyState, ["page", "live", "state"], "open");
    expect(() => validateRenderRequest(legacyState)).toThrow(
      "at $.page.live.state: expected no unknown field",
    );

    const restricted = cloneRequest(jobLogRequest);
    setPath(restricted, ["page", "logVisibility"], "restricted");
    expect(() => validateRenderRequest(restricted)).toThrow("at $.page.live");

    setPath(restricted, ["page", "live"], null);
    expect(() => validateRenderRequest(restricted)).not.toThrow();
  });

  it.each([0, -1, 4_294_967_296, 1.5])(
    "rejects invalid job-log job attempt %s",
    (attempt) => {
      const input = cloneRequest(jobLogRequest);
      setPath(input, ["page", "job", "attempt"], attempt);
      expect(() => validateRenderRequest(input)).toThrow(
        "at $.page.job.attempt",
      );
    },
  );

  it.each(routeFields)(
    "rejects an unsafe URL at $expectedErrorPath",
    ({ request, path, expectedErrorPath }) => {
      const input = cloneRequest(request);
      setPath(input, path, "https://evil.invalid/steal");
      expect(() => validateRenderRequest(input)).toThrow(
        `at ${expectedErrorPath}`,
      );
    },
  );

  it.each([
    [
      ["host", "assets", "clientEntry"],
      "javascript:alert(1)",
      "$.host.assets.clientEntry",
    ],
    [
      ["host", "assets", "clientEntry"],
      "/assets/client.css",
      "$.host.assets.clientEntry",
    ],
    [
      ["host", "assets", "stylesheets", 0],
      "//evil.invalid/theme.css",
      "$.host.assets.stylesheets[0]",
    ],
    [
      ["host", "assets", "stylesheets", 0],
      "/assets/theme.js",
      "$.host.assets.stylesheets[0]",
    ],
  ] as const)(
    "rejects an unsafe or mistyped executable asset",
    (path, replacement, errorPath) => {
      const input = cloneRequest(runListRequest);
      setPath(input, path, replacement);
      expect(() => validateRenderRequest(input)).toThrow(`at ${errorPath}`);
    },
  );

  it("validates bounded run priority and merge-queue ownership", () => {
    const editable = cloneRequest(runDetailRequest);
    setPath(editable, ["page", "priorityUpdate"], {
      endpoint: "/automata-ci/automata/actions/runs/550e8400-e29b-41d4-a716-446655440000/priority",
      csrfToken: "csrf",
      current: 99,
    });
    expect(() => validateRenderRequest(editable)).not.toThrow();

    for (const level of [-1, 100, 1.5]) {
      const invalid = structuredClone(editable);
      setPath(invalid, ["page", "priorityUpdate", "current"], level);
      expect(() => validateRenderRequest(invalid)).toThrow(
        "at $.page.priorityUpdate.current",
      );
    }

    const mergeQueue = cloneRequest(runDetailRequest);
    setPath(mergeQueue, ["page", "run", "priority"], {
      level: 100,
      label: "Merge queue",
      mergeQueueManaged: true,
    });
    expect(() => validateRenderRequest(mergeQueue)).not.toThrow();
    setPath(mergeQueue, ["page", "run", "priority", "level"], 99);
    expect(() => validateRenderRequest(mergeQueue)).toThrow(
      "at $.page.run.priority",
    );
  });
});

describe("malformed and fuzz-style input", () => {
  it.each(["", "{", "null", "[]", "true", "42", '"request"'])(
    "rejects malformed or non-object JSON %#",
    (serialized) => {
      expect(() => parseRenderRequest(serialized)).toThrow();
    },
  );

  it("rejects oversized serialized input before parsing", () => {
    const oversized = "x".repeat(MAX_SERIALIZED_RENDER_REQUEST_BYTES + 1);
    expect(() => parseRenderRequest(oversized)).toThrow("exceeds");
  });

  it("measures the wire contract in UTF-8 bytes rather than UTF-16 code units", () => {
    expect(utf8ByteLength("aé😀\ud800")).toBe(10);
    const oversizedUnicode = "😀".repeat(
      MAX_SERIALIZED_RENDER_REQUEST_BYTES / 4 + 1,
    );
    expect(oversizedUnicode.length).toBeLessThan(
      MAX_SERIALIZED_RENDER_REQUEST_BYTES,
    );
    expect(() => parseRenderRequest(oversizedUnicode)).toThrow(
      `${MAX_SERIALIZED_RENDER_REQUEST_BYTES} UTF-8 bytes`,
    );
  });

  it("rejects a deterministic corpus of deeply malformed scalar replacements", () => {
    const replacements: readonly unknown[] = [null, false, 7, [], {}];
    for (let seed = 0; seed < 100; seed += 1) {
      const input = cloneRequest(runDetailRequest);
      const path = fuzzableStringFields[seed % fuzzableStringFields.length];
      const replacement =
        replacements[
          Math.floor(seed / fuzzableStringFields.length) % replacements.length
        ];
      if (path === undefined || replacement === undefined) {
        throw new Error(
          "The deterministic validation corpus must not be empty",
        );
      }
      setPath(input, path, replacement);
      expect(() => validateRenderRequest(input), `seed ${seed}`).toThrow();
    }
  });

  it.each([
    ["user list", userListRequest],
    ["user detail", userDetailRequest],
    ["role list", roleListRequest],
    ["role detail", roleDetailRequest],
    ["direct binding list", directBindingListRequest],
  ])("accepts the exact current %s management contract", (_name, request) => {
    expect(() => validateRenderRequest(request)).not.toThrow();
  });

  it("requires an authenticated shell and page-matched management navigation", () => {
    const anonymous = cloneRequest(userListRequest);
    setPath(anonymous, ["page", "shell", "viewer"], null);
    setPath(anonymous, ["page", "shell", "signOut"], null);
    expect(() => validateRenderRequest(anonymous)).toThrow(
      "at $.page.shell.viewer",
    );

    const wrongArea = cloneRequest(roleListRequest);
    setPath(wrongArea, ["page", "managementNav", "current"], "users");
    expect(() => validateRenderRequest(wrongArea)).toThrow(
      "at $.page.managementNav.current",
    );

    const duplicateHref = cloneRequest(userListRequest);
    const usersHref = getRecord(duplicateHref, [
      "page",
      "managementNav",
    ]).usersHref;
    setPath(duplicateHref, ["page", "managementNav", "rolesHref"], usersHref);
    expect(() => validateRenderRequest(duplicateHref)).toThrow(
      "at $.page.managementNav.rolesHref",
    );

    const siloedShell = cloneRequest(userListRequest);
    setPath(
      siloedShell,
      ["page", "shell", "homeHref"],
      "/settings/access/users",
    );
    setPath(
      siloedShell,
      ["page", "shell", "navigation"],
      [{ label: "Access", href: "/settings/access/users", current: true }],
    );
    expect(() => validateRenderRequest(siloedShell)).toThrow(
      "at $.page.shell.navigation",
    );
  });

  it.each([
    [
      "nil principal",
      userListRequest,
      ["page", "users", 0, "id"],
      "00000000-0000-0000-0000-000000000000",
      "$.page.users[0].id",
    ],
    [
      "uppercase principal",
      userListRequest,
      ["page", "users", 0, "id"],
      "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
      "$.page.users[0].id",
    ],
    [
      "noncanonical role",
      roleDetailRequest,
      ["page", "role", "id"],
      "not-a-role-id",
      "$.page.role.id",
    ],
    [
      "nil binding principal",
      directBindingListRequest,
      ["page", "bindings", 0, "principal", "id"],
      "00000000-0000-0000-0000-000000000000",
      "$.page.bindings[0].principal.id",
    ],
  ] as const)(
    "rejects the %s UUID",
    (_name, request, path, replacement, errorPath) => {
      const input = cloneRequest(request);
      setPath(input, path, replacement);
      expect(() => validateRenderRequest(input)).toThrow(`at ${errorPath}`);
    },
  );

  it("binds entity links and assignment fragments to their exact stable IDs", () => {
    const user = cloneRequest(userListRequest);
    setPath(
      user,
      ["page", "users", 0, "href"],
      "/settings/access/users/not-this-user",
    );
    expect(() => validateRenderRequest(user)).toThrow(
      "at $.page.users[0].href",
    );

    const assignment = cloneRequest(userDetailRequest);
    setPath(
      assignment,
      ["page", "roleAssignments", 0, "bindingHref"],
      "/settings/access/direct-bindings#aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    );
    expect(() => validateRenderRequest(assignment)).toThrow(
      "at $.page.roleAssignments[0].bindingHref",
    );

    const binding = cloneRequest(directBindingListRequest);
    setPath(
      binding,
      ["page", "bindings", 0, "role", "href"],
      "/settings/access/roles/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    );
    expect(() => validateRenderRequest(binding)).toThrow(
      "at $.page.bindings[0].role.href",
    );

    const misleadingHeading = cloneRequest(roleDetailRequest);
    setPath(misleadingHeading, ["page", "heading"], "Different role");
    expect(() => validateRenderRequest(misleadingHeading)).toThrow(
      "at $.page.heading",
    );
  });

  it("accepts only canonical forward pagination within the current management list", () => {
    const user = cloneRequest(userListRequest);
    setPath(
      user,
      ["page", "pagination", "nextHref"],
      "/settings/access/users?cursor=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    );
    expect(() => validateRenderRequest(user)).not.toThrow();

    const direct = cloneRequest(directBindingListRequest);
    setPath(
      direct,
      ["page", "pagination", "nextHref"],
      "/settings/access/direct-bindings?cursor=d%3Aeeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
    );
    expect(() => validateRenderRequest(direct)).not.toThrow();

    const provider = cloneRequest(directBindingListRequest);
    setPath(
      provider,
      ["page", "pagination", "nextHref"],
      "/settings/access/direct-bindings?cursor=g%3Aaaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa%3Affffffff-ffff-4fff-8fff-ffffffffffff",
    );
    expect(() => validateRenderRequest(provider)).not.toThrow();

    const wrongList = cloneRequest(roleListRequest);
    setPath(
      wrongList,
      ["page", "pagination", "nextHref"],
      "/settings/access/users?cursor=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    );
    expect(() => validateRenderRequest(wrongList)).toThrow(
      "at $.page.pagination.nextHref",
    );

    const backwards = cloneRequest(userListRequest);
    setPath(
      backwards,
      ["page", "pagination", "previousHref"],
      "/settings/access/users?cursor=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    );
    expect(() => validateRenderRequest(backwards)).toThrow(
      "at $.page.pagination.previousHref",
    );
  });

  it.each([
    [userListRequest, ["page", "feedback"]],
    [userListRequest, ["page", "users", 0, "revision"]],
    [userListRequest, ["page", "users", 0, "authorizationRevision"]],
    [userDetailRequest, ["page", "sessionsHref"]],
    [userDetailRequest, ["page", "statusOperation"]],
    [userDetailRequest, ["page", "roleAssignments", 0, "revision"]],
    [roleListRequest, ["page", "revision"]],
    [roleListRequest, ["page", "createRole"]],
    [roleDetailRequest, ["page", "role", "revision"]],
    [roleDetailRequest, ["page", "updateRole"]],
    [roleDetailRequest, ["page", "deleteRole"]],
    [roleDetailRequest, ["page", "permissions", 0, "operation"]],
    [directBindingListRequest, ["page", "revision"]],
    [directBindingListRequest, ["page", "grantBinding"]],
  ] as const)(
    "rejects obsolete management capability alias %#",
    (request, path) => {
      const input = cloneRequest(request);
      setPath(input, path, null);
      expect(() => validateRenderRequest(input)).toThrow(
        `at ${formatPath(path)}`,
      );
    },
  );

  it("enforces management collection bounds before traversal", () => {
    const users = cloneRequest(userListRequest);
    setPath(
      users,
      ["page", "users"],
      Array.from({ length: RENDER_REQUEST_LIMITS.userCount + 1 }, () => null),
    );
    expect(() => validateRenderRequest(users)).toThrow(
      `at $.page.users: expected an array with at most ${RENDER_REQUEST_LIMITS.userCount} items`,
    );
  });

  it("rejects unknown fields, role-kind disagreement, and permission-count drift", () => {
    const unknown = cloneRequest(userDetailRequest);
    getRecord(unknown, ["page", "user"]).isAdmin = true;
    expect(() => validateRenderRequest(unknown)).toThrow(
      "at $.page.user.isAdmin",
    );

    const customImmutable = cloneRequest(roleDetailRequest);
    setPath(customImmutable, ["page", "role", "immutable"], true);
    expect(() => validateRenderRequest(customImmutable)).toThrow(
      "at $.page.role.immutable",
    );

    const countDrift = cloneRequest(roleDetailRequest);
    setPath(countDrift, ["page", "permissions", 0, "granted"], false);
    expect(() => validateRenderRequest(countDrift)).toThrow(
      "at $.page.role.permissionCount",
    );
  });

  it("requires explicit, revision-coherent role permission operations", () => {
    const input = cloneRequest(roleDetailRequest);
    const envelope = {
      csrfToken: SHELL_CSRF_TOKEN,
      expectedAuthorizationRevision: "7",
      expectedRevision: "5",
    };
    setPath(input, ["page", "update"], {
      ...envelope,
      action: `/settings/access/roles/${RBAC_ROLE_ID}`,
    });
    setPath(input, ["page", "delete"], {
      ...envelope,
      action: `/settings/access/roles/${RBAC_ROLE_ID}/delete`,
    });
    setPath(input, ["page", "permissions", 0, "update"], {
      ...envelope,
      action: `/settings/access/roles/${RBAC_ROLE_ID}/permissions/runs:read`,
      operation: "remove",
    });
    setPath(input, ["page", "permissions", 1, "update"], {
      ...envelope,
      action: `/settings/access/roles/${RBAC_ROLE_ID}/permissions/artifacts:download`,
      operation: "add",
    });
    expect(() => validateRenderRequest(input)).not.toThrow();

    const toggle = structuredClone(input);
    setPath(
      toggle,
      ["page", "permissions", 0, "update", "operation"],
      "toggle",
    );
    expect(() => validateRenderRequest(toggle)).toThrow(
      "at $.page.permissions[0].update.operation",
    );

    const mismatchedRevision = structuredClone(input);
    setPath(
      mismatchedRevision,
      ["page", "permissions", 0, "update", "expectedAuthorizationRevision"],
      "8",
    );
    expect(() => validateRenderRequest(mismatchedRevision)).toThrow(
      "at $.page.permissions[0].update",
    );

    const immutable = structuredClone(input);
    setPath(immutable, ["page", "role", "kind"], "built-in");
    setPath(immutable, ["page", "role", "immutable"], true);
    expect(() => validateRenderRequest(immutable)).toThrow("at $.page.update");
  });

  it("preserves role deletion after revision exhaustion without leaking advancing controls", () => {
    const maximumRevision = "9223372036854775807";
    const deleteOnly = cloneRequest(roleDetailRequest);
    setPath(deleteOnly, ["page", "delete"], {
      action: `/settings/access/roles/${RBAC_ROLE_ID}/delete`,
      csrfToken: SHELL_CSRF_TOKEN,
      expectedAuthorizationRevision: "7",
      expectedRevision: maximumRevision,
    });
    expect(() => validateRenderRequest(deleteOnly)).not.toThrow();

    const prematureDeleteOnly = structuredClone(deleteOnly);
    setPath(prematureDeleteOnly, ["page", "delete", "expectedRevision"], "5");
    expect(() => validateRenderRequest(prematureDeleteOnly)).toThrow(
      "at $.page.update",
    );

    const leakedUpdate = structuredClone(deleteOnly);
    setPath(leakedUpdate, ["page", "update"], {
      action: `/settings/access/roles/${RBAC_ROLE_ID}`,
      csrfToken: SHELL_CSRF_TOKEN,
      expectedAuthorizationRevision: "7",
      expectedRevision: maximumRevision,
    });
    expect(() => validateRenderRequest(leakedUpdate)).toThrow(
      "at $.page.update.expectedRevision",
    );

    const leakedPermission = cloneRequest(roleDetailRequest);
    const envelope = {
      csrfToken: SHELL_CSRF_TOKEN,
      expectedAuthorizationRevision: "7",
      expectedRevision: "5",
    };
    setPath(leakedPermission, ["page", "update"], {
      ...envelope,
      action: `/settings/access/roles/${RBAC_ROLE_ID}`,
    });
    setPath(leakedPermission, ["page", "delete"], {
      ...envelope,
      action: `/settings/access/roles/${RBAC_ROLE_ID}/delete`,
    });
    setPath(leakedPermission, ["page", "permissions", 0, "update"], {
      ...envelope,
      expectedRevision: maximumRevision,
      action: `/settings/access/roles/${RBAC_ROLE_ID}/permissions/runs:read`,
      operation: "remove",
    });
    setPath(leakedPermission, ["page", "permissions", 1, "update"], {
      ...envelope,
      action: `/settings/access/roles/${RBAC_ROLE_ID}/permissions/artifacts:download`,
      operation: "add",
    });
    expect(() => validateRenderRequest(leakedPermission)).toThrow(
      "at $.page.permissions[0].update.expectedRevision",
    );
  });

  it("rejects toggle and noncanonical member status submissions", () => {
    const input = cloneRequest(userDetailRequest);
    setPath(input, ["page", "statusUpdate"], {
      action: `/settings/access/users/${RBAC_USER_ID}/status`,
      csrfToken: SHELL_CSRF_TOKEN,
      expectedAuthorizationRevision: "7",
      expectedRevision: "3",
      operation: "disable",
    });
    expect(() => validateRenderRequest(input)).not.toThrow();

    const toggle = structuredClone(input);
    setPath(toggle, ["page", "statusUpdate", "operation"], "toggle");
    expect(() => validateRenderRequest(toggle)).toThrow(
      "at $.page.statusUpdate.operation",
    );

    const noncanonicalRevision = structuredClone(input);
    setPath(
      noncanonicalRevision,
      ["page", "statusUpdate", "expectedRevision"],
      "03",
    );
    expect(() => validateRenderRequest(noncanonicalRevision)).toThrow(
      "at $.page.statusUpdate.expectedRevision",
    );

    const exhaustedRevision = structuredClone(input);
    setPath(
      exhaustedRevision,
      ["page", "statusUpdate", "expectedRevision"],
      "9223372036854775807",
    );
    expect(() => validateRenderRequest(exhaustedRevision)).toThrow(
      "at $.page.statusUpdate.expectedRevision",
    );
  });

  it("fails direct-grant options closed and protects provider-observed bindings", () => {
    const missingRevision = cloneRequest(directBindingListRequest);
    setPath(missingRevision, ["page", "bindings", 0, "revision"], null);
    expect(() => validateRenderRequest(missingRevision)).toThrow(
      "at $.page.bindings[0].revision",
    );

    const input = cloneRequest(directBindingListRequest);
    setPath(input, ["page", "grant"], {
      action: "/settings/access/direct-bindings",
      csrfToken: SHELL_CSRF_TOKEN,
      expectedAuthorizationRevision: "7",
      principals: [{ value: RBAC_USER_ID, label: "Ada Lovelace" }],
      roles: [{ value: RBAC_ROLE_ID, label: "Release reviewer" }],
      scopes: [{ value: "tenant", label: "Production tenant" }],
    });
    setPath(input, ["page", "readOnlyReason"], null);
    setPath(input, ["page", "bindings", 0, "revoke"], {
      action: `/settings/access/direct-bindings/${RBAC_BINDING_ID}/revoke`,
      csrfToken: SHELL_CSRF_TOKEN,
      expectedAuthorizationRevision: "7",
      expectedRevision: "4",
    });
    expect(() => validateRenderRequest(input)).not.toThrow();

    const capabilityMismatch = structuredClone(input);
    setPath(
      capabilityMismatch,
      ["page", "bindings", 0, "revoke", "expectedAuthorizationRevision"],
      "8",
    );
    expect(() => validateRenderRequest(capabilityMismatch)).toThrow(
      "at $.page.bindings[0].revoke",
    );

    const targetMismatch = structuredClone(input);
    setPath(
      targetMismatch,
      ["page", "bindings", 0, "revoke", "expectedRevision"],
      "3",
    );
    expect(() => validateRenderRequest(targetMismatch)).toThrow(
      "at $.page.bindings[0].revoke.expectedRevision",
    );

    const providerObserved = structuredClone(input);
    setPath(providerObserved, ["page", "bindings", 1, "revoke"], {
      action:
        "/settings/access/direct-bindings/ffffffff-ffff-4fff-8fff-ffffffffffff/revoke",
      csrfToken: SHELL_CSRF_TOKEN,
      expectedAuthorizationRevision: "7",
      expectedRevision: "4",
    });
    expect(() => validateRenderRequest(providerObserved)).toThrow(
      "at $.page.bindings[1].revoke",
    );

    const overflow = structuredClone(input);
    setPath(overflow, ["page", "grant"], null);
    setPath(overflow, ["page", "readOnlyReason"], "options-overflow");
    expect(() => validateRenderRequest(overflow)).not.toThrow();

    const leakedGrant = structuredClone(input);
    setPath(leakedGrant, ["page", "readOnlyReason"], "options-overflow");
    expect(() => validateRenderRequest(leakedGrant)).toThrow(
      "at $.page.readOnlyReason",
    );

    const oversizedOptions = structuredClone(input);
    setPath(
      oversizedOptions,
      ["page", "grant", "principals"],
      Array.from({ length: 501 }, () => null),
    );
    expect(() => validateRenderRequest(oversizedOptions)).toThrow(
      "at $.page.grant.principals",
    );

    const noAuthority = cloneRequest(directBindingListRequest);
    setPath(noAuthority, ["page", "bindings", 0, "revoke"], {
      action: `/settings/access/direct-bindings/${RBAC_BINDING_ID}/revoke`,
      csrfToken: SHELL_CSRF_TOKEN,
      expectedAuthorizationRevision: "7",
      expectedRevision: "2",
    });
    expect(() => validateRenderRequest(noAuthority)).toThrow(
      "at $.page.bindings[0].revoke",
    );

    const missingRevoke = structuredClone(input);
    setPath(missingRevoke, ["page", "bindings", 0, "revoke"], null);
    expect(() => validateRenderRequest(missingRevoke)).toThrow(
      "at $.page.bindings[0].revoke",
    );

    const mismatchedCsrf = structuredClone(input);
    setPath(
      mismatchedCsrf,
      ["page", "bindings", 0, "revoke", "csrfToken"],
      "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI",
    );
    expect(() => validateRenderRequest(mismatchedCsrf)).toThrow(
      "at $.page.bindings[0].revoke",
    );

    const exhausted = structuredClone(input);
    setPath(
      exhausted,
      ["page", "bindings", 0, "revision"],
      "9223372036854775807",
    );
    setPath(exhausted, ["page", "bindings", 0, "revoke"], null);
    expect(() => validateRenderRequest(exhausted)).not.toThrow();

    const leakedExhaustedRevoke = structuredClone(input);
    setPath(
      leakedExhaustedRevoke,
      ["page", "bindings", 0, "revision"],
      "9223372036854775807",
    );
    setPath(
      leakedExhaustedRevoke,
      ["page", "bindings", 0, "revoke", "expectedRevision"],
      "9223372036854775807",
    );
    expect(() => validateRenderRequest(leakedExhaustedRevoke)).toThrow(
      "at $.page.bindings[0].revoke",
    );
  });

  it("accepts only the closed mutation notice vocabulary", () => {
    const saved = cloneRequest(userListRequest);
    setPath(saved, ["page", "notice"], "saved");
    expect(() => validateRenderRequest(saved)).not.toThrow();

    const reflected = cloneRequest(userListRequest);
    setPath(reflected, ["page", "notice"], "<secret>");
    expect(() => validateRenderRequest(reflected)).toThrow("at $.page.notice");
  });
});

function routeCase(
  request: RenderRequest,
  path: readonly PathSegment[],
): UrlFieldCase {
  return { request, path, expectedErrorPath: formatPath(path) };
}

function formatPath(path: readonly PathSegment[]): string {
  return path.reduce<string>(
    (formatted, segment) =>
      typeof segment === "number"
        ? `${formatted}[${segment}]`
        : `${formatted}.${segment}`,
    "$",
  );
}

function cloneRequest(request: RenderRequest): Record<string, unknown> {
  return structuredClone(request) as unknown as Record<string, unknown>;
}

function setPath(
  root: unknown,
  path: readonly PathSegment[],
  replacement: unknown,
): void {
  if (path.length === 0) {
    throw new Error("Test path must not be empty");
  }

  let cursor = root;
  for (let index = 0; index < path.length - 1; index += 1) {
    const segment = path[index];
    if (segment === undefined) {
      throw new Error("Test path contains an unavailable segment");
    }
    cursor = readSegment(cursor, segment);
  }

  const finalSegment = path[path.length - 1];
  if (finalSegment === undefined) {
    throw new Error("Test path must have a final segment");
  }
  if (typeof finalSegment === "number") {
    if (!Array.isArray(cursor)) {
      throw new Error(`Test fixture segment ${finalSegment} is not an array`);
    }
    cursor[finalSegment] = replacement;
  } else {
    if (!isRecord(cursor)) {
      throw new Error(`Test fixture segment ${finalSegment} is not an object`);
    }
    cursor[finalSegment] = replacement;
  }
}

function readSegment(value: unknown, segment: PathSegment): unknown {
  if (typeof segment === "number") {
    if (!Array.isArray(value)) {
      throw new Error(`Test fixture segment ${segment} is not an array`);
    }
    return value[segment];
  }
  if (!isRecord(value)) {
    throw new Error(`Test fixture segment ${segment} is not an object`);
  }
  return value[segment];
}

function getRecord(
  root: unknown,
  path: readonly PathSegment[],
): Record<string, unknown> {
  const value = path.reduce(readSegment, root);
  if (!isRecord(value)) {
    throw new Error("Test fixture path is not an object");
  }
  return value;
}

function getArray(root: unknown, path: readonly PathSegment[]): unknown[] {
  const value = path.reduce(readSegment, root);
  if (!Array.isArray(value)) {
    throw new Error("Test fixture path is not an array");
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
