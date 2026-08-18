import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { usePublicationPolicyForm } from "../../src/hooks/usePublicationPolicyForm";
import { useSingleSubmit } from "../../src/hooks/useSingleSubmit";
import type { PublicationPolicyFormState } from "../../src/viewModels/publicationPolicy";

let root: Root | null = null;
afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  document.body.replaceChildren();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("enhanced native form hooks", () => {
  it("tracks publication drafts, unchanged submissions, and history restores", async () => {
    let latest: PublicationPolicyFormState | null = null;
    function Harness() {
      latest = usePublicationPolicyForm({ dashboard: "private", logs: "private", artifacts: "private" });
      return <form onSubmit={latest.onSubmit}><button type="submit">save</button></form>;
    }
    const container = await render(<Harness />);
    const current = () => {
      if (latest === null) throw new Error("policy hook did not render");
      return latest as PublicationPolicyFormState;
    };
    expect(current().saveDisabled).toBe(true);
    const unchanged = new Event("submit", { bubbles: true, cancelable: true });
    container.querySelector("form")?.dispatchEvent(unchanged);
    expect(unchanged.defaultPrevented).toBe(true);

    await act(async () => current().onChange("logs", "public"));
    expect(current().draftPolicy.logs).toBe("public");
    expect(current().saveDisabled).toBe(false);
    await act(async () => container.querySelector("form")?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
    expect(current().isSubmitting).toBe(true);
    const go = vi.spyOn(window.history, "go").mockImplementation(() => undefined);
    await act(async () => window.dispatchEvent(persistedPageShow()));
    expect(go).toHaveBeenCalledWith(0);
  });

  it("allows one native submission and prevents duplicates", async () => {
    let state: ReturnType<typeof useSingleSubmit> | null = null;
    function Harness() {
      state = useSingleSubmit();
      return <form onSubmit={state.onSubmit}><button type="submit">submit</button></form>;
    }
    const container = await render(<Harness />);
    const form = container.querySelector("form");
    const first = new Event("submit", { bubbles: true, cancelable: true });
    await act(async () => form?.dispatchEvent(first));
    expect(first.defaultPrevented).toBe(false);
    if (state === null) throw new Error("single-submit hook did not render");
    expect((state as ReturnType<typeof useSingleSubmit>).isSubmitting).toBe(true);
    const second = new Event("submit", { bubbles: true, cancelable: true });
    await act(async () => form?.dispatchEvent(second));
    expect(second.defaultPrevented).toBe(true);
  });
});

async function render(element: React.ReactNode): Promise<HTMLDivElement> {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  const container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
  await act(async () => root?.render(element));
  return container;
}

function persistedPageShow(): PageTransitionEvent {
  const event = new Event("pageshow") as PageTransitionEvent;
  Object.defineProperty(event, "persisted", { value: true });
  return event;
}
