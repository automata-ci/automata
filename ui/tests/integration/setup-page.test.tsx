import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { act } from "react";
import { hydrateRoot } from "react-dom/client";
import { describe, expect, it, vi } from "vitest";
import { HtmlDocument } from "../../src/Document";
import { renderPage } from "../../src/entry-server";
import type { RenderRequest } from "../../src/models";
import { readRenderRequest } from "../../src/serialization";

const BOOTSTRAP_SENTINEL = "setup-bootstrap-sentinel-0123456789abcdef";

const setupRequest = {
  schemaVersion: 1,
  host: {
    locale: "en",
    assets: {
      clientEntry: "/assets/entry-client-abc123.js",
      stylesheets: ["/assets/entry-client-abc123.css"],
    },
    cspNonce: "setupnonce123",
  },
  page: {
    kind: "setup",
    shell: {
      productName: "Automata",
      homeHref: "/setup",
      signIn: null,
      signOut: null,
      documentTitle: "Set up Automata",
      description:
        "Complete the one-time administrator setup for this Automata installation.",
      viewer: null,
      navigation: [{ label: "Setup", href: "/setup", current: true }],
    },
    form: {
      action: "/setup/auth/github",
      returnPath: "/",
    },
  },
} as const satisfies RenderRequest;

describe("installation setup page", () => {
  it("server-renders one exact native form without disclosing a token", () => {
    const html = renderPage(setupRequest);
    const document = new DOMParser().parseFromString(html, "text/html");
    const form = document.querySelector<HTMLFormElement>(
      'form[action="/setup/auth/github"]',
    );
    const token = form?.querySelector<HTMLInputElement>(
      'input[name="bootstrap_token"]',
    );
    const returnPath = form?.querySelector<HTMLInputElement>(
      'input[name="return_path"]',
    );

    expect(document.title).toBe("Set up Automata");
    expect(document.querySelector("main h1")?.textContent).toBe("Set up Automata");
    expect(form?.method).toBe("post");
    expect(form?.getAttribute("autocomplete")).toBe("off");
    expect(form?.getAttribute("onsubmit")).toBeNull();
    expect(token?.type).toBe("password");
    expect(token?.required).toBe(true);
    expect(token?.autocomplete).toBe("new-password");
    expect(token?.getAttribute("autocapitalize")).toBe("none");
    expect(token?.getAttribute("autocorrect")).toBe("off");
    expect(token?.getAttribute("spellcheck")).toBe("false");
    expect(token?.hasAttribute("value")).toBe(false);
    expect(returnPath?.type).toBe("hidden");
    expect(returnPath?.value).toBe("/");
    expect(form?.querySelectorAll('input[name="bootstrap_token"]')).toHaveLength(1);
    expect(form?.querySelectorAll('input[name="return_path"]')).toHaveLength(1);
    expect(form?.querySelector("button[type=submit]")?.textContent).toContain(
      "Continue with GitHub",
    );
    expect(html).not.toContain(BOOTSTRAP_SENTINEL);
    expect(html).not.toContain("bootstrap_token=");
  });

  it("exposes useful label, help, status, and landmark relationships", () => {
    const document = new DOMParser().parseFromString(
      renderPage(setupRequest),
      "text/html",
    );
    const token = document.querySelector<HTMLInputElement>("#setup-bootstrap-token");
    const describedBy = token?.getAttribute("aria-describedby")?.split(" ") ?? [];

    expect(document.querySelector('label[for="setup-bootstrap-token"]')?.textContent)
      .toBe("Bootstrap token");
    expect(describedBy).toEqual(["setup-form-help", "setup-security-note"]);
    for (const id of describedBy) {
      expect(document.getElementById(id)?.textContent?.trim().length).toBeGreaterThan(0);
    }
    expect(document.querySelector('[role="status"]')?.textContent).toContain(
      "Setup is ready",
    );
    expect(document.querySelector("main#main-content")?.getAttribute("tabindex"))
      .toBe("-1");
    expect(document.querySelector('section[aria-labelledby="setup-connect-heading"]'))
      .not.toBeNull();
    expect(document.querySelector('aside[aria-labelledby="setup-guidance-heading"]'))
      .not.toBeNull();
    expect(document.querySelectorAll("h1")).toHaveLength(1);
  });

  it("disables the action and shows progress after the first hydrated submit", async () => {
    document.open();
    document.write(renderPage(setupRequest));
    document.close();
    const form = document.querySelector<HTMLFormElement>(
      'form[action="/setup/auth/github"]',
    );
    const submit = form?.querySelector<HTMLButtonElement>('button[type="submit"]');
    const parsedRequest = readRenderRequest(document);
    const errors: unknown[] = [];

    expect(submit?.disabled).toBe(false);
    expect(submit?.textContent).toContain("Continue with GitHub");
    expect(form?.hasAttribute("aria-busy")).toBe(false);

    vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
    let root: ReturnType<typeof hydrateRoot> | undefined;
    await act(async () => {
      root = hydrateRoot(document, <HtmlDocument request={parsedRequest} />, {
        onRecoverableError: (error) => errors.push(error),
      });
    });

    expect(errors).toEqual([]);
    const first = new Event("submit", { bubbles: true, cancelable: true });
    await act(async () => form?.dispatchEvent(first));
    expect(first.defaultPrevented).toBe(false);
    expect(form?.getAttribute("aria-busy")).toBe("true");
    expect(submit?.disabled).toBe(true);
    expect(submit?.getAttribute("aria-busy")).toBe("true");
    expect(submit?.textContent).toContain("Connecting…");
    expect(submit?.querySelector(".setup-form__spinner")).not.toBeNull();

    const replay = new Event("submit", { bubbles: true, cancelable: true });
    await act(async () => form?.dispatchEvent(replay));
    expect(replay.defaultPrevented).toBe(true);

    await act(async () => root?.unmount());
  });

  it("keeps compound actions spaced and narrow screens single-column", () => {
    const controls = readFileSync(
      resolve(process.cwd(), "src/styles/components/controls.css"),
      "utf8",
    );
    const stylesheet = readFileSync(
      resolve(process.cwd(), "src/styles/conditions/responsive.css"),
      "utf8",
    );

    expect(controls).toMatch(
      /\.button\s*\{[\s\S]*gap:\s*6px;/u,
    );
    expect(stylesheet).toMatch(
      /@media \(max-width: 767px\)[\s\S]*\.setup-page__layout\s*\{[\s\S]*grid-template-columns:\s*minmax\(0, 1fr\);/u,
    );
    expect(stylesheet).toMatch(
      /@media \(max-width: 767px\)[\s\S]*\.setup-form__actions > \.button\s*\{[\s\S]*width:\s*100%;[\s\S]*min-height:\s*40px;/u,
    );
  });
});
