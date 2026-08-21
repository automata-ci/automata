import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useRunPriority } from "../../src/hooks/useRunPriority";

const updateRunPriority = vi.hoisted(() => vi.fn());
vi.mock("../../src/services/runPriority", () => ({ updateRunPriority }));

let root: Root | null = null;

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  document.body.replaceChildren();
  vi.clearAllMocks();
  vi.unstubAllGlobals();
});

describe("useRunPriority", () => {
  it("updates the draft and rejects duplicate submissions while pending", async () => {
    updateRunPriority.mockRejectedValue(new Error("offline"));
    let latest: ReturnType<typeof useRunPriority> | null = null;
    const controls = { endpoint: "/runs/one/priority", csrfToken: "csrf", current: 0 };

    function Harness() {
      latest = useRunPriority(controls);
      return null;
    }

    await render(<Harness />);
    if (latest === null) throw new Error("priority hook did not render");
    await act(async () => (latest as ReturnType<typeof useRunPriority>).setLevel(50));
    await act(async () => {
      (latest as ReturnType<typeof useRunPriority>).submit();
      (latest as ReturnType<typeof useRunPriority>).submit();
    });

    expect(updateRunPriority).toHaveBeenCalledOnce();
    expect(updateRunPriority).toHaveBeenCalledWith(controls, 50);
    expect((latest as ReturnType<typeof useRunPriority>).pending).toBe(false);
    expect((latest as ReturnType<typeof useRunPriority>).error).toContain("could not be updated");
  });
});

async function render(element: React.ReactNode): Promise<void> {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
  await act(async () => root?.render(element));
}
