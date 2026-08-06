import path from "node:path";
import { pathToFileURL } from "node:url";

const SHA256_PATTERN = /^[0-9a-f]{64}$/;

function assertRecord(value, name) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${name} must be a JSON object`);
  }
}

function transformCanonical(value, transformString) {
  if (typeof value === "string") {
    return transformString(value);
  }

  if (Array.isArray(value)) {
    return value.map((entry) => transformCanonical(entry, transformString));
  }

  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, transformCanonical(value[key], transformString)]),
    );
  }

  return value;
}

function visitStrings(value, visitor) {
  if (typeof value === "string") {
    visitor(value);
    return;
  }

  if (Array.isArray(value)) {
    for (const entry of value) {
      visitStrings(entry, visitor);
    }
    return;
  }

  if (value !== null && typeof value === "object") {
    for (const entry of Object.values(value)) {
      visitStrings(entry, visitor);
    }
  }
}

export function normalizeCycloneDx(
  input,
  { repositoryRoot, sourceDateEpoch, componentSha256 },
) {
  assertRecord(input, "CycloneDX document");
  if (input.bomFormat !== "CycloneDX" || input.specVersion !== "1.5") {
    throw new TypeError("expected a CycloneDX 1.5 document");
  }
  assertRecord(input.metadata, "CycloneDX metadata");
  assertRecord(input.metadata.component, "CycloneDX metadata.component");

  if (!Number.isSafeInteger(sourceDateEpoch) || sourceDateEpoch < 0) {
    throw new TypeError("SOURCE_DATE_EPOCH must be a non-negative safe integer");
  }

  const resolvedRoot = path.resolve(repositoryRoot);
  const repositoryUri = pathToFileURL(resolvedRoot).href;
  const timestamp = new Date(sourceDateEpoch * 1_000);
  if (Number.isNaN(timestamp.valueOf())) {
    throw new TypeError("SOURCE_DATE_EPOCH is outside the supported date range");
  }

  const document = structuredClone(input);
  delete document.serialNumber;
  document.metadata.timestamp = timestamp.toISOString();

  if (componentSha256 !== undefined) {
    if (!SHA256_PATTERN.test(componentSha256)) {
      throw new TypeError("component SHA-256 must be 64 lowercase hexadecimal characters");
    }
    document.metadata.component.hashes = [
      { alg: "SHA-256", content: componentSha256 },
    ];
  }

  const normalized = transformCanonical(document, (value) =>
    value.replaceAll(repositoryUri, "file:///workspace"),
  );
  visitStrings(normalized, (value) => {
    if (value.includes(resolvedRoot) || value.includes(repositoryUri)) {
      throw new TypeError("normalized SBOM still contains the checkout path");
    }
    if (
      value.startsWith("path+file:///") &&
      !value.startsWith("path+file:///workspace")
    ) {
      throw new TypeError(`non-canonical local package reference: ${value}`);
    }
  });

  return normalized;
}

export function serializeCanonicalJson(value) {
  return `${JSON.stringify(transformCanonical(value, (entry) => entry), null, 2)}\n`;
}
