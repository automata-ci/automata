import type { ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

interface PreviewRoot {
  readonly render: (node: ReactNode) => void;
}

const previewRootMock = vi.hoisted(() => ({
  makeRoot: vi.fn<(container: Element) => PreviewRoot>(),
  render: vi.fn<(node: ReactNode) => void>(),
}));

vi.mock("react-dom/client", () => ({
  createRoot: (container: Element) => previewRootMock.makeRoot(container),
}));

beforeEach(() => {
  vi.resetModules();
  vi.clearAllMocks();
  window.history.replaceState({}, "", "/preview/");
  document.title = "";
  document.body.innerHTML = '<div id="root"></div>';
  previewRootMock.makeRoot.mockImplementation((container) => ({
    render(node) {
      previewRootMock.render(node);
      container.innerHTML = renderToStaticMarkup(node);
    },
  }));
});

afterEach(() => {
  document.body.replaceChildren();
  document.documentElement.removeAttribute("data-theme");
  window.history.replaceState({}, "", "/preview/");
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("preview bootstrap routing", () => {
  it.each([
    {
      route: "/preview/",
      title: "Repositories · Automata",
      heading: "Repositories",
      content: "automata-ci/automata",
    },
    {
      route: "/preview/?view=runs&workflow=release&status=completed",
      title: "Workflow runs · Automata",
      heading: "Workflow runs",
      content: "Release",
    },
    {
      route: "/preview/?view=run&run=run-a4f69c2e",
      title: "Build and test release candidate · Automata",
      heading: "Build and test release candidate",
      content: "Run summary",
    },
    {
      route: "/preview/?view=job&run=run-a4f69c2e&job=job-1&q=Operating%20System",
      title: "Linux release build logs · Automata",
      heading: "Linux release build",
      content: "Operating System",
    },
    {
      route: "/preview/?view=settings",
      title: "Repository access settings · Automata",
      heading: "Repository access",
      content: "Defaults for new runs",
    },
    {
      route: "/preview/?view=secrets",
      title: "Repository secrets · Automata",
      heading: "Repository secrets",
      content: "DEPLOY_TOKEN",
    },
    {
      route: "/preview/?view=user&user=ada-lovelace",
      title: "Ada Lovelace · Access management · Automata",
      heading: "Ada Lovelace",
      content: "Release reviewer",
    },
  ])("renders the supported $route route", async ({ route, title, heading, content }) => {
    const root = requiredRoot();
    const addListener = vi.spyOn(root, "addEventListener");

    await bootstrapPreview(route);

    expect(document.title).toBe(title);
    expect(root.querySelector("main h1")?.textContent).toBe(heading);
    expect(root.textContent).toContain(content);
    expect(previewRootMock.makeRoot).toHaveBeenCalledOnce();
    expect(previewRootMock.makeRoot).toHaveBeenCalledWith(root);
    expect(previewRootMock.render).toHaveBeenCalledOnce();
    expect(addListener).toHaveBeenCalledWith("submit", expect.any(Function));
  });

  it.each([
    {
      route: "/preview/?view=run&run=missing",
      title: "Run not found · Automata",
      heading: "Run not found",
      message: "That workflow run is not part of this demo.",
    },
    {
      route: "/preview/?view=job&run=run-a4f69c2e&job=missing",
      title: "Job not found · Automata",
      heading: "Job not found",
      message: "That workflow job is not part of this demo.",
    },
    {
      route: "/preview/?view=repositories&unexpected=1",
      title: "Page not found · Automata",
      heading: "Page not found",
      message: "Those repository directory parameters are not part of this demo.",
    },
    {
      route: "/preview/?view=settings&revision=7",
      title: "Page not found · Automata",
      heading: "Page not found",
      message: "Those repository settings parameters are not part of this demo.",
    },
    {
      route: "/preview/?view=secrets&notice=saved",
      title: "Page not found · Automata",
      heading: "Page not found",
      message: "Those repository secrets parameters are not part of this demo.",
    },
    {
      route: "/preview/?view=user",
      title: "Page not found · Automata",
      heading: "Page not found",
      message: "Those access management parameters are not part of this demo.",
    },
    {
      route: "/preview/?view=runs&workflow=unknown",
      title: "Page not found · Automata",
      heading: "Page not found",
      message: "Those workflow run filters are not part of this demo.",
    },
    {
      route: "/preview/?view=unknown",
      title: "Page not found · Automata",
      heading: "Page not found",
      message: "That page is not part of this demo.",
    },
  ])("renders the exact not-found contract for $route", async ({
    route,
    title,
    heading,
    message,
  }) => {
    await bootstrapPreview(route);

    const root = requiredRoot();
    expect(document.title).toBe(title);
    expect(root.querySelector("main")?.id).toBe("main-content");
    expect(root.querySelector("main")?.getAttribute("tabindex")).toBe("-1");
    expect(root.querySelector("h1")?.textContent).toBe(heading);
    expect(root.querySelector(".empty-state p")?.textContent).toBe(message);
    expect(
      root.querySelector<HTMLAnchorElement>(".empty-state a")?.getAttribute(
        "href",
      ),
    ).toBe("?view=repositories");
    expect(root.querySelector(".empty-state a")?.textContent).toBe(
      "Back to repositories",
    );
  });

  it("fails clearly before creating a React root when the preview mount is absent", async () => {
    document.body.replaceChildren();
    window.history.replaceState({}, "", "/preview/?view=runs");

    await expect(import("../../src/preview")).rejects.toThrow(
      "The UI preview root is missing",
    );
    expect(previewRootMock.makeRoot).not.toHaveBeenCalled();
  });
});

describe("preview hash reconciliation", () => {
  it("decodes, marks, focuses, and centers a rendered hash target", async () => {
    const focus = vi
      .spyOn(HTMLElement.prototype, "focus")
      .mockImplementation(() => undefined);
    const scrollDescriptor = Object.getOwnPropertyDescriptor(
      HTMLElement.prototype,
      "scrollIntoView",
    );
    const scrollIntoView = vi.fn();
    Object.defineProperty(HTMLElement.prototype, "scrollIntoView", {
      configurable: true,
      value: scrollIntoView,
    });

    try {
      await bootstrapPreview("/preview/?view=repositories#main%2Dcontent");

      const target = requiredRoot().querySelector("#main-content");
      expect(target?.classList).toContain("preview-hash-target");
      expect(focus).toHaveBeenCalledWith({ preventScroll: true });
      expect(scrollIntoView).toHaveBeenCalledWith({ block: "center" });
    } finally {
      if (scrollDescriptor === undefined) {
        delete (HTMLElement.prototype as Partial<HTMLElement>).scrollIntoView;
      } else {
        Object.defineProperty(
          HTMLElement.prototype,
          "scrollIntoView",
          scrollDescriptor,
        );
      }
    }
  });

  it("retries a not-yet-rendered target and ignores malformed hash encoding", async () => {
    const frames: FrameRequestCallback[] = [];
    const requestFrame = vi.fn((callback: FrameRequestCallback) => {
      frames.push(callback);
      return frames.length;
    });
    vi.stubGlobal("requestAnimationFrame", requestFrame);

    await bootstrapPreview("/preview/?view=repositories#late-target");
    expect(frames).toHaveLength(1);
    const target = document.createElement("div");
    target.id = "late-target";
    const focus = vi.spyOn(target, "focus").mockImplementation(() => undefined);
    const scrollIntoView = vi.fn();
    Object.defineProperty(target, "scrollIntoView", {
      configurable: true,
      value: scrollIntoView,
    });
    requiredRoot().append(target);

    frames.shift()?.(0);
    expect(target.classList).toContain("preview-hash-target");
    expect(focus).toHaveBeenCalledWith({ preventScroll: true });
    expect(scrollIntoView).toHaveBeenCalledWith({ block: "center" });
    expect(requestFrame).toHaveBeenCalledOnce();

    vi.resetModules();
    document.body.innerHTML = '<div id="root"></div>';
    window.history.replaceState(
      {},
      "",
      "/preview/?view=repositories#%E0%A4%A",
    );
    await import("../../src/preview");
    expect(requestFrame).toHaveBeenCalledOnce();
  });
});

async function bootstrapPreview(route: string): Promise<void> {
  window.history.replaceState({}, "", route);
  await import("../../src/preview");
}

function requiredRoot(): HTMLElement {
  const root = document.getElementById("root");
  if (root === null) {
    throw new Error("The preview test root is missing");
  }
  return root;
}
