import { describe, expect, it } from "vitest";
import type { RenderRequest } from "../../src/models";
import { validateRenderRequest } from "../../src/validation";
import { repositorySecretsRequest } from "../fixtures/renderRequests";

describe("repository secrets render contract", () => {
  it("accepts the complete value-free production model", () => {
    const request = structuredClone(repositorySecretsRequest);
    expect(validateRenderRequest(request)).toEqual(repositorySecretsRequest);
    expect(JSON.stringify(request)).not.toContain("plaintext-fixture");
  });

  it("requires one exact page-wide value limit and rejects the obsolete create-local shape", () => {
    const wrongLimit = clone();
    pageRecord(wrongLimit).maximumValueBytes = 65_535;
    expect(() => validateRenderRequest(wrongLimit)).toThrow(
      "at $.page.maximumValueBytes",
    );

    const createLocalLimit = clone();
    const create = pageRecord(createLocalLimit).create as Record<string, unknown>;
    create.maximumValueBytes = 65_536;
    expect(() => validateRenderRequest(createLocalLimit)).toThrow(
      "at $.page.create.maximumValueBytes",
    );
  });

  it("rejects value fields and never reflects their contents", () => {
    const request = clone();
    const page = pageRecord(request);
    const secret = (page.secrets as Record<string, unknown>[])[0];
    if (secret === undefined) throw new Error("missing fixture secret");
    secret.value = "plaintext-fixture-do-not-reflect";

    try {
      validateRenderRequest(request);
      throw new Error("secret value unexpectedly entered the render contract");
    } catch (error) {
      expect(String(error)).toContain("at $.page.secrets[0].value");
      expect(String(error)).not.toContain("plaintext-fixture-do-not-reflect");
    }
  });

  it("binds every mutation to one route, CSRF proof, and authorization revision", () => {
    const wrongAction = clone();
    const create = pageRecord(wrongAction).create as Record<string, unknown>;
    create.action = "/automata-ci/other/settings/secrets";
    expect(() => validateRenderRequest(wrongAction)).toThrow(
      "at $.page.create.action",
    );

    const wrongCsrf = clone();
    const replacement = firstReplacement(wrongCsrf);
    replacement.csrfToken = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIh";
    expect(() => validateRenderRequest(wrongCsrf)).toThrow(
      "at $.page.secrets[0].replace.csrfToken",
    );

    const staleRevision = clone();
    firstReplacement(staleRevision).expectedAuthorizationRevision = "11";
    expect(() => validateRenderRequest(staleRevision)).toThrow(
      "at $.page.secrets[0].replace.expectedAuthorizationRevision",
    );
  });

  it("rejects incoherent metadata, reserved names, and invented capability", () => {
    const provisioningVersion = clone();
    const secret = firstSecret(provisioningVersion);
    secret.state = "provisioning";
    expect(() => validateRenderRequest(provisioningVersion)).toThrow(
      "at $.page.secrets[0].currentVersion",
    );

    const reservedName = clone();
    firstSecret(reservedName).name = "GITHUB_TOKEN";
    expect(() => validateRenderRequest(reservedName)).toThrow(
      "at $.page.secrets[0].name",
    );

    const activeProvider = clone();
    const provider = pageRecord(activeProvider).provider as Record<string, unknown>;
    provider.activation = {
      action: "/automata-ci/automata/settings/secrets/provider/activate",
      csrfToken: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
      expectedAuthorizationRevision: "12",
      expectedRevision: "3",
    };
    expect(() => validateRenderRequest(activeProvider)).toThrow(
      "at $.page.provider.activation",
    );

    const exhaustedSecret = clone();
    const exhausted = firstSecret(exhaustedSecret);
    exhausted.revision = "9223372036854775807";
    exhausted.replace = null;
    expect(() => validateRenderRequest(exhaustedSecret)).toThrow(
      "at $.page.secrets[0].delete",
    );
  });

  it("accepts an authorized metadata-only page with no mutation controls", () => {
    const request = clone();
    const page = pageRecord(request);
    page.create = null;
    page.provider = null;
    for (const secret of page.secrets as Record<string, unknown>[]) {
      secret.replace = null;
      secret.delete = null;
    }
    expect(() => validateRenderRequest(request)).not.toThrow();
  });
});

function clone(): RenderRequest {
  return structuredClone(repositorySecretsRequest);
}

function pageRecord(request: RenderRequest): Record<string, unknown> {
  return request.page as unknown as Record<string, unknown>;
}

function firstSecret(request: RenderRequest): Record<string, unknown> {
  const secret = (pageRecord(request).secrets as Record<string, unknown>[])[0];
  if (secret === undefined) throw new Error("missing fixture secret");
  return secret;
}

function firstReplacement(request: RenderRequest): Record<string, unknown> {
  return firstSecret(request).replace as Record<string, unknown>;
}
