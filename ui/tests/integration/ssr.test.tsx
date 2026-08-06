import { act } from "react";
import { hydrateRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HtmlDocument } from "../../src/Document";
import { render, renderPage } from "../../src/entry-server";
import { readRenderRequest } from "../../src/serialization";
import { runDetailRequest, runListRequest } from "../fixtures/renderRequests";

describe("server rendering", () => {
  it("renders the run list as a complete, useful document", () => {
    const html = renderPage(runListRequest);

    expect(html).toMatch(/^<!doctype html><html lang="en">/);
    expect(html).toContain("Workflow runs");
    expect(html).toContain("Dogfood Automata &lt;generation G1&gt;");
    expect(html).toContain('href="/automata/automata/actions/runs/1842"');
    expect(html).toContain('action="/automata/automata/actions/runs"');
    expect(html).toContain('name="branch"');
    expect(html).toContain("6 Aug 2026, 08:15 UTC");
    expect(html).toContain('src="/assets/entry-client-abc123.js"');
    expect(html).toContain('href="/assets/entry-client-abc123.css"');
  });

  it("renders run details, jobs, artifacts, and ordinary POST operations", () => {
    const html = renderPage(runDetailRequest);

    expect(html).toContain("Dogfood Automata generation G1");
    expect(html).toContain("Static Linux build");
    expect(html).toContain("Build automata");
    expect(html).toContain("automata-x86_64-unknown-linux-musl");
    expect(html).toContain('method="post"');
    expect(html).toContain('name="csrf_token"');
    expect(html).toContain("csrf&lt;&amp;token");
    expect(html).toContain('data-confirm="Cancel this workflow run?"');
  });

  it("escapes visible values and the embedded hydration payload", () => {
    const html = renderPage(runListRequest);

    expect(html).not.toContain("ada<script>alert(1)</script>");
    expect(html).toContain("ada&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).not.toContain("</script><script>alert(1)</script>");
    expect(html).toContain("ada\\u003cscript\\u003ealert(1)\\u003c/script\\u003e");
  });

  it("accepts the serialized stable renderer boundary", () => {
    const html = render(JSON.stringify(runDetailRequest));
    expect(html).toContain("<!doctype html>");
    expect(html).toContain("Dogfood Automata generation G1");
  });
});

describe("hydration", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it.each([
    ["run list", runListRequest, "Workflow runs"],
    ["run detail", runDetailRequest, "Dogfood Automata generation G1"],
  ])("hydrates the %s document without recoverable mismatch errors", async (_name, request, heading) => {
    document.open();
    document.write(renderPage(request));
    document.close();
    const parsedRequest = readRenderRequest(document);
    const errors: unknown[] = [];
    vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);

    let root: ReturnType<typeof hydrateRoot> | undefined;
    await act(async () => {
      root = hydrateRoot(
        document,
        <HtmlDocument request={parsedRequest} enableEnhancements />,
        { onRecoverableError: (error) => errors.push(error) },
      );
    });

    expect(errors).toEqual([]);
    expect(document.querySelector("h1")?.textContent).toBe(heading);

    await act(async () => root?.unmount());
  });

  it("progressively enhances confirmations without replacing native POST forms", async () => {
    document.open();
    document.write(renderPage(runDetailRequest));
    document.close();
    const parsedRequest = readRenderRequest(document);
    const confirm = vi.fn(() => false);
    vi.stubGlobal("confirm", confirm);
    vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);

    let root: ReturnType<typeof hydrateRoot> | undefined;
    await act(async () => {
      root = hydrateRoot(document, <HtmlDocument request={parsedRequest} enableEnhancements />);
    });

    const form = document.querySelector<HTMLFormElement>('form[data-confirm]');
    expect(form?.method).toBe("post");
    const cancelledSubmission = new SubmitEvent("submit", { bubbles: true, cancelable: true });
    form?.dispatchEvent(cancelledSubmission);
    expect(confirm).toHaveBeenCalledWith("Cancel this workflow run?");
    expect(cancelledSubmission.defaultPrevented).toBe(true);

    confirm.mockReturnValue(true);
    const acceptedSubmission = new SubmitEvent("submit", { bubbles: true, cancelable: true });
    form?.dispatchEvent(acceptedSubmission);
    expect(acceptedSubmission.defaultPrevented).toBe(false);

    await act(async () => root?.unmount());
  });
});
