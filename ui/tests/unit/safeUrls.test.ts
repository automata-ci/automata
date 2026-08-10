import { describe, expect, it } from "vitest";
import {
  isSafeGitHubScmUrl,
  isSafeSameOriginAssetPath,
  isSafeSameOriginRoutePath,
  MAX_GITHUB_SCM_URL_LENGTH,
  MAX_ROUTE_PATH_LENGTH,
} from "../../src/safeUrls";

describe("same-origin route paths", () => {
  it.each([
    "/",
    "/repositories/automata/actions/runs?status=running#run-42",
    "/branches/feature%2Fvalidation",
    "?page=2",
    "#step-3",
  ])("accepts %s", (path) => {
    expect(isSafeSameOriginRoutePath(path)).toBe(true);
  });

  it.each([
    "",
    "runs",
    "./runs",
    "../runs",
    "https://evil.invalid/run",
    "javascript:alert(1)",
    "//evil.invalid/run",
    "///evil.invalid/run",
    "\\\\evil.invalid\\run",
    "/\\evil.invalid/run",
    "/run with spaces",
    "/run\nnext",
    "/runs/../settings",
    "/runs/%2e%2e/settings",
    "/runs/%zz",
    "?q=%2f",
    "?q=%",
    "?q=café",
  ])("rejects %s", (path) => {
    expect(isSafeSameOriginRoutePath(path)).toBe(false);
  });

  it("admits worst-case encoded filters but retains a finite route ceiling", () => {
    const encodedFilter = encodeURIComponent("é".repeat(512));
    expect(isSafeSameOriginRoutePath(`?q=${encodedFilter}`)).toBe(true);
    expect(encodedFilter.length).toBe(3_072);
    expect(isSafeSameOriginRoutePath(`/${"x".repeat(MAX_ROUTE_PATH_LENGTH)}`)).toBe(
      false,
    );
  });
});

describe("same-origin asset paths", () => {
  it.each([
    ["/assets/entry-client-a1b2.js", "client-script"],
    ["/assets/renderer.mjs?v=2", "client-script"],
    ["/assets/entry-client-a1b2.css", "stylesheet"],
  ] as const)("accepts %s as %s", (path, kind) => {
    expect(isSafeSameOriginAssetPath(path, kind)).toBe(true);
  });

  it.each([
    ["https://cdn.invalid/app.js", "client-script"],
    ["//cdn.invalid/app.js", "client-script"],
    ["?asset=/app.js", "client-script"],
    ["/assets/app.js#", "client-script"],
    ["/assets/app.js#fragment", "client-script"],
    ["/assets/app.css", "client-script"],
    ["/assets/app.js", "stylesheet"],
    ["/assets/app.css#fragment", "stylesheet"],
    ["/assets/app.css?v=1#", "stylesheet"],
  ] as const)("rejects %s as %s", (path, kind) => {
    expect(isSafeSameOriginAssetPath(path, kind)).toBe(false);
  });
});

describe("trusted GitHub SCM URLs", () => {
  const owner = "automata-ci";
  const repository = "automata";
  const sha1 = "26713a895eb6744012da74726e59230a259357c4";
  const sha256 = `${sha1}0123456789abcdef01234567`;

  it.each([
    [
      `https://github.com/${owner}/${repository}`,
      { kind: "repository" },
    ],
    [
      `https://github.com/${owner}/${repository}/commit/${sha1}`,
      { kind: "commit", shortSha: sha1.slice(0, 7) },
    ],
    [
      `https://github.com/${owner}/${repository}/commit/${sha256}`,
      { kind: "commit", shortSha: sha256.slice(0, 12) },
    ],
    [
      `https://github.com/${owner}/${repository}/tree/feature%2Frelease%20%231`,
      { kind: "tree", refName: "feature/release #1" },
    ],
    [
      `https://github.com/${owner}/${repository}/tree/release@1;lhs=rhs&x+y$,`,
      { kind: "tree", refName: "release@1;lhs=rhs&x+y$," },
    ],
    [
      `https://github.com/${owner}/${repository}/tree/feature%2Frelease%25candidate%5Cnext`,
      { kind: "tree", refName: "feature/release%candidate\\next" },
    ],
    [
      `https://github.com/${owner}/${repository}/tree/caf%C3%A9%2F%CE%B4%F0%9F%9A%80`,
      { kind: "tree", refName: "café/δ🚀" },
    ],
    [
      `https://github.com/${owner}/${repository}/pull/42`,
      { kind: "pull", pullNumber: "42" },
    ],
  ] as const)("accepts the exact repository-bound target %s", (url, target) => {
    expect(isSafeGitHubScmUrl(url, owner, repository, target)).toBe(true);
  });

  it.each([
    "http://github.com/automata-ci/automata",
    "HTTPS://GITHUB.COM/automata-ci/automata",
    "https://www.github.com/automata-ci/automata",
    "https://github.com.evil.invalid/automata-ci/automata",
    "https://evil.invalid@github.com/automata-ci/automata",
    "https://github.com:443/automata-ci/automata",
    "https://github.com/other/automata",
    "https://github.com/automata-ci/other",
    "https://github.com/automata-ci/automata-evil",
    "https://github.com/automata-ci%2Fautomata",
    "https://github.com/automata-ci/automata/",
    "https://github.com/automata-ci/automata?tab=readme",
    "https://github.com/automata-ci/automata#readme",
  ])("rejects the repository URL alias %s", (url) => {
    expect(
      isSafeGitHubScmUrl(url, owner, repository, { kind: "repository" }),
    ).toBe(false);
  });

  it.each([
    [
      `https://github.com/${owner}/${repository}/commit/${sha1}?diff=split`,
      { kind: "commit", shortSha: sha1.slice(0, 7) },
    ],
    [
      `https://github.com/${owner}/${repository}/commit/${sha1.slice(0, 12)}`,
      { kind: "commit", shortSha: sha1.slice(0, 7) },
    ],
    [
      `https://github.com/${owner}/${repository}/commit/${sha1}`,
      { kind: "commit", shortSha: "deadbee" },
    ],
    [
      `https://github.com/${owner}/${repository}/commit/${sha1.toUpperCase()}`,
      { kind: "commit", shortSha: sha1.slice(0, 7) },
    ],
    [
      `https://github.com/${owner}/${repository}/commit/${sha1}`,
      { kind: "commit", shortSha: sha1.slice(0, 7).toUpperCase() },
    ],
    [
      `https://github.com/${owner}/${repository}/tree/feature/release`,
      { kind: "tree", refName: "feature/release" },
    ],
    [
      `https://github.com/${owner}/${repository}/tree/main#readme`,
      { kind: "tree", refName: "main" },
    ],
    [
      `https://github.com/${owner}/${repository}/tree/.`,
      { kind: "tree", refName: "." },
    ],
    [
      `https://github.com/${owner}/${repository}/tree/%EF%BF%BD`,
      { kind: "tree", refName: "\ud800" },
    ],
    [
      `https://github.com/${owner}/${repository}/pull/42/files`,
      { kind: "pull", pullNumber: "42" },
    ],
    [
      `https://github.com/${owner}/${repository}/pull/0`,
      { kind: "pull", pullNumber: "0" },
    ],
    [
      `https://github.com/${owner}/${repository}/pull/042`,
      { kind: "pull", pullNumber: "042" },
    ],
    [
      `https://github.com/${owner}/${repository}/pull/18446744073709551616`,
      { kind: "pull", pullNumber: "18446744073709551616" },
    ],
  ] as const)("rejects the non-canonical SCM target %s", (url, target) => {
    expect(isSafeGitHubScmUrl(url, owner, repository, target)).toBe(false);
  });

  it.each([
    ["owner/escape", repository],
    ["-owner", repository],
    ["owner--name", repository],
    [owner, "repo/escape"],
    [owner, ".."],
  ])("rejects an invalid repository identity %s/%s", (invalidOwner, invalidName) => {
    expect(
      isSafeGitHubScmUrl(
        `https://github.com/${invalidOwner}/${invalidName}`,
        invalidOwner,
        invalidName,
        { kind: "repository" },
      ),
    ).toBe(false);
  });

  it("admits a maximally encoded durable ref without removing the URL ceiling", () => {
    const refName = "é".repeat(506);
    const url = `https://github.com/${owner}/${repository}/tree/${encodeURIComponent(refName)}`;
    expect(url.length).toBeLessThan(MAX_GITHUB_SCM_URL_LENGTH);
    expect(isSafeGitHubScmUrl(url, owner, repository, { kind: "tree", refName })).toBe(
      true,
    );

    const oversizedRef = "é".repeat(700);
    const oversizedUrl = `https://github.com/${owner}/${repository}/tree/${encodeURIComponent(oversizedRef)}`;
    expect(oversizedUrl.length).toBeGreaterThan(MAX_GITHUB_SCM_URL_LENGTH);
    expect(
      isSafeGitHubScmUrl(oversizedUrl, owner, repository, {
        kind: "tree",
        refName: oversizedRef,
      }),
    ).toBe(false);
  });
});
