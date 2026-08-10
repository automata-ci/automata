import { describe, expect, it } from "vitest";
import {
  enforceBranchFilterValidity,
  enforceLogQueryValidity,
  enforceShortTextByteLimit,
  enforceUtf8ByteLimit,
  isValidLogQuery,
} from "../../src/components/textInputConstraints";
import { RENDER_REQUEST_LIMITS } from "../../src/validation";

describe("text input wire constraints", () => {
  it("accepts 1,024 ASCII bytes and rejects shorter UTF-16 text over the byte bound", () => {
    const input = document.createElement("input");
    input.value = "x".repeat(RENDER_REQUEST_LIMITS.shortTextLength);
    enforceShortTextByteLimit(input);
    expect(input.checkValidity()).toBe(true);

    input.value = "🚀".repeat(RENDER_REQUEST_LIMITS.shortTextLength / 4 + 1);
    expect(input.value.length).toBeLessThan(RENDER_REQUEST_LIMITS.shortTextLength);
    enforceShortTextByteLimit(input);
    expect(input.checkValidity()).toBe(false);
    expect(input.validationMessage).toContain("1,024 UTF-8 bytes");

    input.value = "valid";
    enforceShortTextByteLimit(input);
    expect(input.checkValidity()).toBe(true);
  });

  it("enforces a host-projected secret limit in UTF-8 bytes without reflecting input", () => {
    const input = document.createElement("input");
    const maximumBytes = 65_536;
    input.value = "x".repeat(maximumBytes);
    enforceUtf8ByteLimit(input, maximumBytes);
    expect(input.checkValidity()).toBe(true);

    const sensitiveValue = "🚀".repeat(maximumBytes / 4 + 1);
    input.value = sensitiveValue;
    expect(input.value.length).toBeLessThan(maximumBytes);
    enforceUtf8ByteLimit(input, maximumBytes);
    expect(input.checkValidity()).toBe(false);
    expect(input.validationMessage).toBe(
      "Use at most 65,536 UTF-8 bytes.",
    );
    expect(input.validationMessage).not.toContain(sensitiveValue);

    input.value = "replacement";
    enforceUtf8ByteLimit(input, maximumBytes);
    expect(input.checkValidity()).toBe(true);
  });

  it("accounts for the implicit Git head prefix and rejects invisible filters", () => {
    const input = document.createElement("input");
    input.value = "  main  ";
    enforceBranchFilterValidity(input);
    expect(input.value).toBe("main");
    expect(input.checkValidity()).toBe(true);

    input.value = "x".repeat(1_013);
    enforceBranchFilterValidity(input);
    expect(input.checkValidity()).toBe(true);

    input.value = "x".repeat(1_014);
    enforceBranchFilterValidity(input);
    expect(input.checkValidity()).toBe(false);
    expect(input.validationMessage).toContain("complete Git reference");

    input.value = "\u200B";
    enforceBranchFilterValidity(input);
    expect(input.checkValidity()).toBe(false);

    input.value = "main\u202E";
    enforceBranchFilterValidity(input);
    expect(input.checkValidity()).toBe(false);
  });

  it("keeps log search validity aligned with the server display contract", () => {
    const input = document.createElement("input");
    input.value = "build failed";
    enforceLogQueryValidity(input);
    expect(input.checkValidity()).toBe(true);

    input.value = "\uFE0F";
    enforceLogQueryValidity(input);
    expect(input.checkValidity()).toBe(false);

    input.value = "error\u0001next";
    enforceLogQueryValidity(input);
    expect(input.checkValidity()).toBe(false);

    expect(isValidLogQuery("build failed")).toBe(true);
    expect(isValidLogQuery("\uFE0F")).toBe(false);
    expect(
      isValidLogQuery("🚀".repeat(RENDER_REQUEST_LIMITS.shortTextLength / 4 + 1)),
    ).toBe(false);
  });
});
