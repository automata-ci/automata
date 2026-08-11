import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderPage } from "../../src/entry-server";
import { PAGE_MODEL_ELEMENT_ID } from "../../src/serialization";
import { runListRequest } from "../fixtures/renderRequests";

const hydrateRoot = vi.hoisted(() => vi.fn());

vi.mock("react-dom/client", () => ({ hydrateRoot }));

beforeEach(() => {
  vi.resetModules();
  hydrateRoot.mockClear();
});

afterEach(() => {
  document.open();
  document.write("<!doctype html><html><head></head><body></body></html>");
  document.close();
});

describe("client bootstrap", () => {
  it("hydrates the document with the validated embedded render request", async () => {
    document.open();
    document.write(renderPage(runListRequest));
    document.close();
    const { HtmlDocument } = await import("../../src/Document");

    await import("../../src/entry-client");

    expect(hydrateRoot).toHaveBeenCalledOnce();
    const [container, element] = hydrateRoot.mock.calls[0] ?? [];
    expect(container).toBe(document);
    expect((element as ReactElement).type).toBe(HtmlDocument);
    expect((element as ReactElement<{ request: unknown }>).props.request).toEqual(
      runListRequest,
    );
    expect(
      (element as ReactElement<{ request: unknown }>).props.request,
    ).not.toBe(runListRequest);
  });

  it.each([
    {
      name: "missing",
      markup: "<!doctype html><html><body></body></html>",
      error: "Automata page model is missing from the document",
    },
    {
      name: "malformed",
      markup: `<!doctype html><html><body><script id="${PAGE_MODEL_ELEMENT_ID}" type="application/json">{</script></body></html>`,
      error: "Malformed Automata render request JSON",
    },
  ])("rejects $name embedded data before hydration", async ({ markup, error }) => {
    document.open();
    document.write(markup);
    document.close();

    await expect(import("../../src/entry-client")).rejects.toThrow(error);
    expect(hydrateRoot).not.toHaveBeenCalled();
  });
});
