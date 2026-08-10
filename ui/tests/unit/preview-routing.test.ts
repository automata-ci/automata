import { describe, expect, it, vi } from "vitest";
import {
  installPreviewFormRouting,
  previewGetDestination,
} from "../../src/preview/formRouting";

describe("preview GET routing", () => {
  it("preserves the demo route while replacing submitted filter fields", () => {
    const form = createForm(
      "http://automata.test/demo/?view=runs&workflow=release&branch=old",
      [
        ["branch", "fix/runner-heartbeat"],
        ["status", "completed"],
      ],
    );

    expect(previewGetDestination(form, "http://automata.test/demo/?view=runs")).toBe(
      "/demo/?view=runs&workflow=release&branch=fix%2Frunner-heartbeat&status=completed",
    );
  });

  it("preserves run and job identity for log searches", () => {
    const form = createForm(
      "http://automata.test/demo/?view=job&run=run-a4f69c2e&job=job-1&q=old",
      [["q", "Operating System"]],
    );

    expect(previewGetDestination(form, "http://automata.test/demo/?view=job")).toBe(
      "/demo/?view=job&run=run-a4f69c2e&job=job-1&q=Operating+System",
    );
  });

  it("does not enhance mutations or navigation away from the current preview path", () => {
    const mutation = createForm("http://automata.test/demo/?view=runs", []);
    mutation.method = "post";
    expect(previewGetDestination(mutation, "http://automata.test/demo/")).toBeNull();

    const otherPath = createForm("http://automata.test/other/?view=runs", []);
    expect(previewGetDestination(otherPath, "http://automata.test/demo/")).toBeNull();

    const external = createForm("https://example.test/demo/?view=runs", []);
    expect(previewGetDestination(external, "http://automata.test/demo/")).toBeNull();
  });

  it("honors a submit button's native action, method, name, and value", () => {
    const form = createForm(
      "http://automata.test/demo/?view=runs&q=old&intent=old",
      [["q", "runner"]],
    );
    const submitter = document.createElement("button");
    submitter.type = "submit";
    submitter.name = "intent";
    submitter.value = "search";
    submitter.setAttribute(
      "formaction",
      "http://automata.test/demo/?view=job&run=run-a4f69c2e&job=job-1&q=old&intent=old",
    );
    form.append(submitter);

    expect(
      previewGetDestination(
        form,
        "http://automata.test/demo/?view=runs",
        submitter,
      ),
    ).toBe(
      "/demo/?view=job&run=run-a4f69c2e&job=job-1&q=runner&intent=search",
    );

    submitter.setAttribute("formmethod", "post");
    expect(
      previewGetDestination(
        form,
        "http://automata.test/demo/?view=runs",
        submitter,
      ),
    ).toBeNull();

  });

  it("fails closed for malformed locations and invalid submitters", () => {
    const form = createForm("http://automata.test/demo/?view=runs", []);
    expect(previewGetDestination(form, "not a URL")).toBeNull();

    const unrelated = document.createElement("button");
    unrelated.type = "submit";
    expect(
      previewGetDestination(
        form,
        "http://automata.test/demo/?view=runs",
        unrelated,
      ),
    ).toBeNull();

    const fileInput = document.createElement("input");
    fileInput.type = "file";
    fileInput.name = "upload";
    form.append(fileInput);
    expect(
      previewGetDestination(form, "http://automata.test/demo/?view=runs"),
    ).toBeNull();
  });

  it("returns an exact listener teardown for HMR", () => {
    const root = document.createElement("div");
    const addListener = vi.spyOn(root, "addEventListener");
    const removeListener = vi.spyOn(root, "removeEventListener");

    const uninstall = installPreviewFormRouting(root);
    const installedListener = addListener.mock.calls[0]?.[1];
    expect(installedListener).toBeDefined();

    uninstall();
    expect(removeListener).toHaveBeenCalledOnce();
    expect(removeListener).toHaveBeenCalledWith("submit", installedListener);
  });
});

function createForm(
  action: string,
  fields: readonly (readonly [name: string, value: string])[],
): HTMLFormElement {
  const form = document.createElement("form");
  form.action = action;
  form.method = "get";
  for (const [name, value] of fields) {
    const input = document.createElement("input");
    input.name = name;
    input.value = value;
    form.append(input);
  }
  return form;
}
