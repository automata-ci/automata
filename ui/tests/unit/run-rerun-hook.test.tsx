import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useRunRerun } from "../../src/hooks/useRunRerun";

const startRunRerun = vi.hoisted(() => vi.fn());

vi.mock("../../src/services/runRerun", () => ({ startRunRerun }));

let root: Root | null = null;

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  document.body.replaceChildren();
  vi.clearAllMocks();
  vi.unstubAllGlobals();
});

describe("useRunRerun", () => {
  it("rejects duplicate starts before React can render the pending state", async () => {
    startRunRerun.mockRejectedValue(new Error("offline"));
    let latest: ReturnType<typeof useRunRerun> | null = null;

    function Harness() {
      latest = useRunRerun({
        controls: {
          endpoint: "/runs/one/rerun",
          csrfToken: "csrf-token",
          failedJobsAvailable: true,
        },
        runsHref: "/automata-ci/automata/actions",
      });
      return null;
    }

    await render(<Harness />);
    if (latest === null) throw new Error("rerun hook did not render");
    await act(async () => {
      (latest as ReturnType<typeof useRunRerun>).rerunAll();
      (latest as ReturnType<typeof useRunRerun>).rerunAll();
    });

    expect(startRunRerun).toHaveBeenCalledOnce();
    expect((latest as ReturnType<typeof useRunRerun>).pending).toBe(false);
    expect((latest as ReturnType<typeof useRunRerun>).error).toContain(
      "could not be started",
    );
  });
});

async function render(element: React.ReactNode): Promise<void> {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
  await act(async () => root?.render(element));
}
