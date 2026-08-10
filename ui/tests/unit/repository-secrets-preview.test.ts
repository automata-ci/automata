import { describe, expect, it } from "vitest";
import {
  isPreviewRepositorySecretsStateSupported,
  previewRepositorySecrets,
} from "../../src/preview/models";

describe("repository secrets preview", () => {
  it("is explicitly read-only and value-free", () => {
    const page = previewRepositorySecrets();
    expect(page.create).toBeNull();
    expect(page.provider?.activation).toBeNull();
    expect(page.secrets.every((secret) => secret.replace === null)).toBe(true);
    expect(page.secrets.every((secret) => secret.delete === null)).toBe(true);
    expect(JSON.stringify(page)).not.toMatch(/csrf|mutationId|secret value/iu);
  });

  it("accepts only the exact preview route", () => {
    expect(
      isPreviewRepositorySecretsStateSupported(
        new URLSearchParams("view=secrets"),
      ),
    ).toBe(true);
    expect(
      isPreviewRepositorySecretsStateSupported(
        new URLSearchParams("view=secrets&notice=created"),
      ),
    ).toBe(false);
    expect(
      isPreviewRepositorySecretsStateSupported(
        new URLSearchParams("view=secrets&view=secrets"),
      ),
    ).toBe(false);
  });
});
