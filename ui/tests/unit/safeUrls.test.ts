import { describe, expect, it } from "vitest";
import {
  isSafeSameOriginAssetPath,
  isSafeSameOriginRoutePath,
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
  ])("rejects %s", (path) => {
    expect(isSafeSameOriginRoutePath(path)).toBe(false);
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
    ["/assets/app.js#fragment", "client-script"],
    ["/assets/app.css", "client-script"],
    ["/assets/app.js", "stylesheet"],
    ["/assets/app.css#fragment", "stylesheet"],
  ] as const)("rejects %s as %s", (path, kind) => {
    expect(isSafeSameOriginAssetPath(path, kind)).toBe(false);
  });
});
