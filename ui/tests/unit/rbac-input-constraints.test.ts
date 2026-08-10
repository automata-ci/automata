import { describe, expect, it } from "vitest";
import {
  enforceRbacDisplayNameValidity,
  enforceRbacReasonValidity,
} from "../../src/components/rbacInputConstraints";

describe("RBAC native-form text constraints", () => {
  it("enforces exact UTF-8 display-name bounds", () => {
    const input = document.createElement("input");
    input.required = true;

    input.value = "🚀".repeat(63);
    enforceRbacDisplayNameValidity(input);
    expect(input.checkValidity()).toBe(true);

    input.value = "🚀".repeat(64);
    enforceRbacDisplayNameValidity(input);
    expect(input.checkValidity()).toBe(false);
    expect(input.validationMessage).toContain("255 UTF-8 bytes");
  });

  it.each(["   ", "\u200B", "review\u202Erole", "review\u0007role"])(
    "rejects unsafe or visually blank display text %#",
    (value) => {
      const input = document.createElement("input");
      input.value = value;
      enforceRbacDisplayNameValidity(input);
      expect(input.checkValidity()).toBe(false);
    },
  );

  it("uses the same contract for input and textarea reasons", () => {
    for (const control of [
      document.createElement("input"),
      document.createElement("textarea"),
    ]) {
      control.value = "🚀".repeat(256);
      enforceRbacReasonValidity(control);
      expect(control.checkValidity()).toBe(true);

      control.value = "🚀".repeat(257);
      enforceRbacReasonValidity(control);
      expect(control.checkValidity()).toBe(false);

    }

    const textarea = document.createElement("textarea");
    textarea.value = "line\nbreak";
    enforceRbacReasonValidity(textarea);
    expect(textarea.checkValidity()).toBe(false);

    const input = document.createElement("input");
    input.value = "line\nbreak";
    expect(input.value).toBe("linebreak");
  });
});
