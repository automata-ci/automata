import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RbacTableRegion } from "../../src/components/RbacManagement";

let root: ReturnType<typeof createRoot> | null = null;

afterEach(async () => {
  await act(async () => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
  document.body.replaceChildren();
});

describe("RBAC table overflow admission", () => {
  it("adds a keyboard stop only while the region actually overflows", async () => {
    vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
    vi.stubGlobal("ResizeObserver", undefined);
    const container = document.createElement("div");
    document.body.append(container);
    root = createRoot(container);
    await act(async () => {
      root?.render(
        <RbacTableRegion labelledBy="table-heading">
          <table><tbody><tr><td>row</td></tr></tbody></table>
        </RbacTableRegion>,
      );
    });

    const region = container.querySelector<HTMLElement>(".rbac-table-region");
    expect(region).not.toBeNull();
    if (region === null) throw new Error("RBAC region must render");
    expect(region.getAttribute("tabindex")).toBeNull();
    Object.defineProperties(region, {
      clientWidth: { configurable: true, value: 600 },
      scrollWidth: { configurable: true, value: 700 },
    });
    await act(async () => window.dispatchEvent(new Event("resize")));
    expect(region.getAttribute("tabindex")).toBe("0");

    Object.defineProperty(region, "scrollWidth", {
      configurable: true,
      value: 500,
    });
    await act(async () => window.dispatchEvent(new Event("resize")));
    expect(region.getAttribute("tabindex")).toBeNull();
  });

  it("observes the region and table and disconnects the primary observer", async () => {
    vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
    let observer: MockResizeObserver | undefined;
    class MockResizeObserver {
      readonly observe = vi.fn();
      readonly disconnect = vi.fn();
      readonly unobserve = vi.fn();
      private readonly callback: ResizeObserverCallback;

      constructor(callback: ResizeObserverCallback) {
        this.callback = callback;
        observer = this;
      }

      notify(): void {
        this.callback([], this as unknown as ResizeObserver);
      }
    }
    vi.stubGlobal("ResizeObserver", MockResizeObserver);
    const container = document.createElement("div");
    document.body.append(container);
    root = createRoot(container);
    await act(async () => {
      root?.render(
        <RbacTableRegion labelledBy="table-heading">
          <table><tbody><tr><td>row</td></tr></tbody></table>
        </RbacTableRegion>,
      );
    });

    const region = container.querySelector<HTMLElement>(".rbac-table-region");
    const table = region?.firstElementChild;
    expect(region).not.toBeNull();
    expect(table).not.toBeNull();
    expect(observer?.observe).toHaveBeenCalledTimes(2);
    expect(observer?.observe).toHaveBeenNthCalledWith(1, region);
    expect(observer?.observe).toHaveBeenNthCalledWith(2, table);
    if (region === null) throw new Error("RBAC region must render");
    Object.defineProperties(region, {
      clientWidth: { configurable: true, value: 600 },
      scrollWidth: { configurable: true, value: 700 },
    });
    await act(async () => observer?.notify());
    expect(region.getAttribute("tabindex")).toBe("0");

    await act(async () => root?.unmount());
    root = null;
    expect(observer?.disconnect).toHaveBeenCalledOnce();
  });
});
