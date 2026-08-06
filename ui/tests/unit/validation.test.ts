import { describe, expect, it } from "vitest";
import type { RenderRequest } from "../../src/models";
import { parseRenderRequest } from "../../src/serialization";
import {
  MAX_SERIALIZED_RENDER_REQUEST_BYTES,
  RENDER_REQUEST_LIMITS,
  utf8ByteLength,
  validateRenderRequest,
} from "../../src/validation";
import { runDetailRequest, runListRequest } from "../fixtures/renderRequests";

type PathSegment = string | number;

interface UrlFieldCase {
  readonly request: RenderRequest;
  readonly path: readonly PathSegment[];
  readonly expectedErrorPath: string;
}

const routeFields: readonly UrlFieldCase[] = [
  routeCase(runListRequest, ["page", "shell", "homeHref"]),
  routeCase(runListRequest, ["page", "shell", "signInHref"]),
  routeCase(runListRequest, ["page", "shell", "viewer", "profileHref"]),
  routeCase(runListRequest, ["page", "shell", "navigation", 0, "href"]),
  routeCase(runListRequest, ["page", "repository", "href"]),
  routeCase(runListRequest, ["page", "repository", "runsHref"]),
  routeCase(runListRequest, ["page", "filters", "action"]),
  routeCase(runListRequest, ["page", "filters", "clearHref"]),
  routeCase(runListRequest, ["page", "runs", 0, "href"]),
  routeCase(runListRequest, ["page", "runs", 0, "commit", "href"]),
  routeCase(runListRequest, ["page", "pagination", "previousHref"]),
  routeCase(runListRequest, ["page", "pagination", "nextHref"]),
  routeCase(runDetailRequest, ["page", "run", "workflowHref"]),
  routeCase(runDetailRequest, ["page", "run", "branchHref"]),
  routeCase(runDetailRequest, ["page", "run", "commit", "href"]),
  routeCase(runDetailRequest, ["page", "operations", 0, "action"]),
  routeCase(runDetailRequest, ["page", "jobs", 0, "href"]),
  routeCase(runDetailRequest, ["page", "jobs", 0, "steps", 0, "logHref"]),
  routeCase(runDetailRequest, ["page", "artifacts", 0, "downloadHref"]),
];

const fuzzableStringFields: readonly (readonly PathSegment[])[] = [
  ["host", "locale"],
  ["page", "shell", "productName"],
  ["page", "shell", "documentTitle"],
  ["page", "repository", "owner"],
  ["page", "repository", "name"],
  ["page", "run", "name"],
  ["page", "run", "status", "label"],
  ["page", "run", "commit", "message"],
  ["page", "jobs", 0, "name"],
  ["page", "jobs", 0, "steps", 0, "name"],
  ["page", "artifacts", 0, "name"],
];

describe("render request validation", () => {
  it.each([
    ["run-list", runListRequest],
    ["run-detail", runDetailRequest],
  ])("deeply accepts the complete %s contract", (_kind, request) => {
    expect(parseRenderRequest(JSON.stringify(request))).toEqual(request);
    expect(validateRenderRequest(structuredClone(request))).toEqual(request);
  });

  it("reports a precise nested path without reflecting hostile data", () => {
    const input = cloneRequest(runDetailRequest);
    setPath(input, ["page", "jobs", 0, "steps", 0, "status", "tone"], "<script>bad()</script>");

    expect(() => validateRenderRequest(input)).toThrow(
      "Invalid Automata render request at $.page.jobs[0].steps[0].status.tone",
    );
    try {
      validateRenderRequest(input);
    } catch (error) {
      expect(String(error)).not.toContain("<script>");
    }
  });

  it.each([
    ["unknown schema", ["schemaVersion"], 2, "$.schemaVersion"],
    ["invalid locale", ["host", "locale"], "../../en", "$.host.locale"],
    ["invalid nonce", ["host", "cspNonce"], "nonce with spaces", "$.host.cspNonce"],
    ["wrong page kind", ["page", "kind"], "dashboard", "$.page.kind"],
    ["invalid status", ["page", "run", "status", "tone"], "done", "$.page.run.status.tone"],
    ["invalid timestamp", ["page", "run", "createdAt", "iso"], "yesterday", "$.page.run.createdAt.iso"],
    ["fractional attempt", ["page", "run", "attempt"], 1.5, "$.page.run.attempt"],
    ["invalid digest", ["page", "artifacts", 0, "digest"], "sha256:nope", "$.page.artifacts[0].digest"],
    ["wrong optional type", ["page", "operations", 0, "confirmation"], false, "$.page.operations[0].confirmation"],
  ] as const)("rejects %s", (_name, path, replacement, errorPath) => {
    const input = cloneRequest(runDetailRequest);
    setPath(input, path, replacement);
    expect(() => validateRenderRequest(input)).toThrow(`at ${errorPath}`);
  });

  it("rejects unknown fields at every object boundary", () => {
    const input = cloneRequest(runListRequest);
    const filters = getRecord(input, ["page", "filters"]);
    filters.unversionedBehavior = true;
    expect(() => validateRenderRequest(input)).toThrow("at $.page.filters.unversionedBehavior");
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
  });

  it("rejects sparse collections that serialize differently from their in-memory shape", () => {
    const input = cloneRequest(runListRequest);
    setPath(input, ["page", "shell", "navigation"], new Array(1));
    expect(() => validateRenderRequest(input)).toThrow("at $.page.shell.navigation[0]");
  });

  it("applies the aggregate serialized-size bound to direct object validation", () => {
    const input = cloneRequest(runDetailRequest);
    const originalJob = getRecord(input, ["page", "jobs", 0]);
    const originalStep = getRecord(originalJob, ["steps", 0]);
    const largeJobs = Array.from({ length: 2 }, (_unused, jobIndex) => ({
      ...structuredClone(originalJob),
      id: `large-job-${jobIndex}`,
      steps: Array.from({ length: RENDER_REQUEST_LIMITS.stepCount }, (_step, stepIndex) => ({
        ...structuredClone(originalStep),
        number: stepIndex + 1,
        name: "x".repeat(RENDER_REQUEST_LIMITS.shortTextLength),
        durationLabel: "x".repeat(RENDER_REQUEST_LIMITS.shortTextLength),
        status: {
          label: "x".repeat(RENDER_REQUEST_LIMITS.shortTextLength),
          tone: "running",
        },
      })),
    }));
    setPath(input, ["page", "jobs"], largeJobs);
    expect(() => validateRenderRequest(input)).toThrow(
      `expected at most ${MAX_SERIALIZED_RENDER_REQUEST_BYTES} serialized UTF-8 bytes`,
    );
  });

  it("rejects duplicate keyed collection values", () => {
    const input = cloneRequest(runListRequest);
    const runs = getArray(input, ["page", "runs"]);
    const duplicate = structuredClone(runs[0]);
    runs.push(duplicate);
    expect(() => validateRenderRequest(input)).toThrow("at $.page.runs[2].id");
  });

  it.each(routeFields)("rejects an unsafe URL at $expectedErrorPath", ({ request, path, expectedErrorPath }) => {
    const input = cloneRequest(request);
    setPath(input, path, "https://evil.invalid/steal");
    expect(() => validateRenderRequest(input)).toThrow(`at ${expectedErrorPath}`);
  });

  it.each([
    [["host", "assets", "clientEntry"], "javascript:alert(1)", "$.host.assets.clientEntry"],
    [["host", "assets", "clientEntry"], "/assets/client.css", "$.host.assets.clientEntry"],
    [["host", "assets", "stylesheets", 0], "//evil.invalid/theme.css", "$.host.assets.stylesheets[0]"],
    [["host", "assets", "stylesheets", 0], "/assets/theme.js", "$.host.assets.stylesheets[0]"],
  ] as const)("rejects an unsafe or mistyped executable asset", (path, replacement, errorPath) => {
    const input = cloneRequest(runListRequest);
    setPath(input, path, replacement);
    expect(() => validateRenderRequest(input)).toThrow(`at ${errorPath}`);
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
    const oversizedUnicode = "😀".repeat(MAX_SERIALIZED_RENDER_REQUEST_BYTES / 4 + 1);
    expect(oversizedUnicode.length).toBeLessThan(MAX_SERIALIZED_RENDER_REQUEST_BYTES);
    expect(() => parseRenderRequest(oversizedUnicode)).toThrow(
      `${MAX_SERIALIZED_RENDER_REQUEST_BYTES} UTF-8 bytes`,
    );
  });

  it("rejects a deterministic corpus of deeply malformed scalar replacements", () => {
    const replacements: readonly unknown[] = [null, false, 7, [], {}];
    for (let seed = 0; seed < 100; seed += 1) {
      const input = cloneRequest(runDetailRequest);
      const path = fuzzableStringFields[seed % fuzzableStringFields.length];
      const replacement = replacements[Math.floor(seed / fuzzableStringFields.length) % replacements.length];
      setPath(input, path, replacement);
      expect(() => validateRenderRequest(input), `seed ${seed}`).toThrow();
    }
  });
});

function routeCase(request: RenderRequest, path: readonly PathSegment[]): UrlFieldCase {
  return { request, path, expectedErrorPath: formatPath(path) };
}

function formatPath(path: readonly PathSegment[]): string {
  return path.reduce<string>(
    (formatted, segment) =>
      typeof segment === "number" ? `${formatted}[${segment}]` : `${formatted}.${segment}`,
    "$",
  );
}

function cloneRequest(request: RenderRequest): Record<string, unknown> {
  return structuredClone(request) as unknown as Record<string, unknown>;
}

function setPath(root: unknown, path: readonly PathSegment[], replacement: unknown): void {
  if (path.length === 0) {
    throw new Error("Test path must not be empty");
  }

  let cursor = root;
  for (let index = 0; index < path.length - 1; index += 1) {
    cursor = readSegment(cursor, path[index]);
  }

  const finalSegment = path[path.length - 1];
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

function getRecord(root: unknown, path: readonly PathSegment[]): Record<string, unknown> {
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
