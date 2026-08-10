import { describe, expect, it } from "vitest";
import { validateRenderRequest } from "../../src/validation";

const SETUP_DESCRIPTION =
  "Complete the one-time administrator setup for this Automata installation.";

function setupRequest(): Record<string, unknown> {
  return {
    schemaVersion: 1,
    host: {
      locale: "en",
      cspNonce: "setupnonce123",
      assets: {
        clientEntry: "/assets/entry-client-abc123.js",
        stylesheets: ["/assets/entry-client-abc123.css"],
      },
    },
    page: {
      kind: "setup",
      shell: {
        productName: "Automata",
        homeHref: "/setup",
        signIn: null,
        signOut: null,
        documentTitle: "Set up Automata",
        description: SETUP_DESCRIPTION,
        viewer: null,
        navigation: [{ label: "Setup", href: "/setup", current: true }],
      },
      form: {
        action: "/setup/auth/github",
        returnPath: "/",
      },
    },
  };
}

function page(request: Record<string, unknown>): Record<string, unknown> {
  return request.page as Record<string, unknown>;
}

function shell(request: Record<string, unknown>): Record<string, unknown> {
  return page(request).shell as Record<string, unknown>;
}

function form(request: Record<string, unknown>): Record<string, unknown> {
  return page(request).form as Record<string, unknown>;
}

describe("setup page model validation", () => {
  it("accepts only the fixed value-free setup projection", () => {
    const request = setupRequest();
    expect(validateRenderRequest(request)).toBe(request);
  });

  it.each([
    ["$.page.form.action", (request: Record<string, unknown>) => {
      form(request).action = "/auth/github/login";
    }],
    ["$.page.form.returnPath", (request: Record<string, unknown>) => {
      form(request).returnPath = "/setup?token=forbidden";
    }],
    ["$.page.form.bootstrapToken", (request: Record<string, unknown>) => {
      form(request).bootstrapToken = "setup-bootstrap-sentinel-0123456789abcdef";
    }],
    ["$.page.shell", (request: Record<string, unknown>) => {
      shell(request).signIn = {
        action: "/auth/github/login",
        returnPath: "/setup",
      };
    }],
    ["$.page.shell.navigation", (request: Record<string, unknown>) => {
      shell(request).navigation = [
        { label: "Repositories", href: "/repositories", current: true },
      ];
    }],
    ["$.page.shell.description", (request: Record<string, unknown>) => {
      shell(request).description = "setup-bootstrap-sentinel-0123456789abcdef";
    }],
  ])("rejects non-canonical or secret-capable data at %s", (path, mutate) => {
    const request = setupRequest();
    mutate(request);
    expect(() => validateRenderRequest(request)).toThrow(path);
  });
});
