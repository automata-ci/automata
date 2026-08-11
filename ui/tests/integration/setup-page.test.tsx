import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { renderPage } from "../../src/entry-server";
import type { RenderRequest } from "../../src/models";

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

  it("has an explicit narrow-screen single-column and full-width action contract", () => {
    const stylesheet = readFileSync(
      resolve(process.cwd(), "src/styles/conditions/responsive.css"),
      "utf8",
    );

    expect(stylesheet).toMatch(
      /@media \(max-width: 767px\)[\s\S]*\.setup-page__layout\s*\{[\s\S]*grid-template-columns:\s*minmax\(0, 1fr\);/u,
    );
    expect(stylesheet).toMatch(
      /@media \(max-width: 767px\)[\s\S]*\.setup-form__actions > \.button\s*\{[\s\S]*width:\s*100%;[\s\S]*min-height:\s*40px;/u,
    );
  });
});
