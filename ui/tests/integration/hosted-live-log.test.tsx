import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "../../src/App";
import type { LiveLogAccessProvider } from "../../src/logs";
import { jobLogRequest } from "../fixtures/renderRequests";

let root: ReturnType<typeof createRoot> | null = null;

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
});

describe("hosted live logs", () => {
  it("uses the host-supplied live-log authority", async () => {
    if (jobLogRequest.page.kind !== "job-log") {
      throw new Error("The job-log fixture is unavailable");
    }
    const access = vi.fn<LiveLogAccessProvider>(
      () => new Promise(() => undefined),
    );
    const container = document.createElement("div");
    document.body.replaceChildren(container);
    vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);

    root = createRoot(container);
    await act(async () => {
      root?.render(<App jobLogAccess={access} page={jobLogRequest.page} />);
    });

    expect(access).toHaveBeenCalledOnce();
    expect(access.mock.calls[0]?.[0]).toBeInstanceOf(AbortSignal);
  });
});
