import { act } from "react";
import { hydrateRoot } from "react-dom/client";
import { describe, expect, it, vi } from "vitest";
import { HtmlDocument } from "../../src/Document";
import type { RenderRequest } from "../../src/models";
import { renderPage } from "../../src/entry-server";
import { readRenderRequest } from "../../src/serialization";
import {
  REPOSITORY_SECRET_ID,
  repositorySecretsRequest,
} from "../fixtures/renderRequests";

describe("repository secrets SSR", () => {
  it("renders exact native forms without serializing a secret value", () => {
    const html = renderPage(repositorySecretsRequest);
    const document = new DOMParser().parseFromString(html, "text/html");
    const root = "/automata-ci/automata/settings/secrets";
    const create = document.querySelector<HTMLFormElement>(
      `main form[action="${root}"]`,
    );
    const replacement = document.querySelector<HTMLFormElement>(
      `main form[action="${root}/${REPOSITORY_SECRET_ID}/replace"]`,
    );
    const deletion = document.querySelector<HTMLFormElement>(
      `main form[action="${root}/${REPOSITORY_SECRET_ID}/delete"]`,
    );

    expect(create?.method).toBe("post");
    expect(replacement?.method).toBe("post");
    expect(deletion?.method).toBe("post");
    expect(
      document.querySelector(
        '.repository-settings-navigation a[aria-current="page"]',
      )?.textContent,
    ).toBe("Secrets");
    expect(document.querySelector(".repository-secret-row strong")?.textContent).toBe(
      "DEPLOY_TOKEN",
    );

    const valueInputs = [
      ...document.querySelectorAll<HTMLInputElement>(
        'main input[name="value"][type="password"]',
      ),
    ];
    expect(valueInputs).toHaveLength(2);
    expect(valueInputs.every((input) => !input.hasAttribute("value"))).toBe(true);
    expect(
      valueInputs.every(
        (input) =>
          input.autocomplete === "new-password" &&
          input.required &&
          input.maxLength === 65_536,
      ),
    ).toBe(true);
    expect(html).not.toContain("plaintext-fixture");
    expect(html).not.toContain("onSubmit=");
  });

  it("keeps a read-only page useful without rendering inert mutation UI", () => {
    const request = structuredClone(repositorySecretsRequest);
    if (request.page.kind !== "repository-secrets") {
      throw new Error("unexpected fixture kind");
    }
    const readOnlyRequest: RenderRequest = {
      ...request,
      page: {
      ...request.page,
      create: null,
      provider: request.page.provider === null
        ? null
        : { ...request.page.provider, activation: null },
      secrets: request.page.secrets.map((secret) => ({
        ...secret,
        replace: null,
        delete: null,
      })),
      },
    };

    const document = new DOMParser().parseFromString(
      renderPage(readOnlyRequest),
      "text/html",
    );
    expect(document.querySelectorAll('main form[method="post"]')).toHaveLength(0);
    expect(document.querySelector('main input[name="value"]')).toBeNull();
    expect(document.querySelector(".repository-secret-read-only")?.textContent).toContain(
      "Read-only",
    );
    expect(document.querySelector(".repository-secret-row")?.textContent).toContain(
      "DEPLOY_TOKEN",
    );
    expect(document.querySelector(".repository-secret-row")?.textContent).toContain(
      "Version",
    );
  });

  it("hydrates both value fields with the shared UTF-8 byte limit", async () => {
    document.open();
    document.write(renderPage(repositorySecretsRequest));
    document.close();
    const parsedRequest = readRenderRequest(document);
    const errors: unknown[] = [];
    vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);

    let root: ReturnType<typeof hydrateRoot> | undefined;
    await act(async () => {
      root = hydrateRoot(document, <HtmlDocument request={parsedRequest} />, {
        onRecoverableError: (error) => errors.push(error),
      });
    });
    expect(errors).toEqual([]);

    const valueInputs = [
      ...document.querySelectorAll<HTMLInputElement>(
        'main input[name="value"][type="password"]',
      ),
    ];
    expect(valueInputs).toHaveLength(2);
    const setValue = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    )?.set;
    const oversizedValue = "🚀".repeat(65_536 / 4 + 1);
    for (const input of valueInputs) {
      await act(async () => {
        setValue?.call(input, oversizedValue);
        input.dispatchEvent(new Event("input", { bubbles: true }));
      });
      expect(input.checkValidity()).toBe(false);
      expect(input.validationMessage).toBe(
        "Use at most 65,536 UTF-8 bytes.",
      );
      expect(input.validationMessage).not.toContain(oversizedValue);

      await act(async () => {
        setValue?.call(input, "valid replacement");
        input.dispatchEvent(new Event("input", { bubbles: true }));
      });
      expect(input.checkValidity()).toBe(true);
    }

    await act(async () => root?.unmount());
    vi.unstubAllGlobals();
  });
});
