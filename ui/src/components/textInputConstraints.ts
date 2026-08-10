import {
  RENDER_REQUEST_LIMITS,
  utf8ByteLength,
} from "../validation/limits";
import {
  hasForbiddenDisplayCharacter,
  hasVisibleDisplayCharacter,
} from "../unicode";

const SHORT_TEXT_BYTE_LIMIT = RENDER_REQUEST_LIMITS.shortTextLength;

/** Keep browser-side form validity aligned with the UTF-8 wire contract. */
export function enforceShortTextByteLimit(input: HTMLInputElement): void {
  enforceUtf8ByteLimit(input, SHORT_TEXT_BYTE_LIMIT);
}

/** Add a non-reflecting browser validity error for one exact UTF-8 byte cap. */
export function enforceUtf8ByteLimit(
  input: HTMLInputElement,
  maximumBytes: number,
): void {
  input.setCustomValidity(
    utf8ByteLength(input.value) > maximumBytes
      ? `Use at most ${maximumBytes.toLocaleString("en")} UTF-8 bytes.`
      : "",
  );
}

export function enforceBranchFilterValidity(input: HTMLInputElement): void {
  const value = input.value.trim();
  input.value = value;
  if (value.length === 0) {
    input.setCustomValidity("");
    return;
  }
  if (!isSafeFilterText(value)) {
    input.setCustomValidity("Enter a visible branch or Git ref without control characters.");
    return;
  }
  const canonical = value.startsWith("refs/") ? value : `refs/heads/${value}`;
  input.setCustomValidity(
    utf8ByteLength(canonical) > SHORT_TEXT_BYTE_LIMIT
      ? "The complete Git reference must use at most 1,024 UTF-8 bytes."
      : "",
  );
}

export function enforceLogQueryValidity(input: HTMLInputElement): void {
  if (isValidLogQuery(input.value)) {
    input.setCustomValidity("");
    return;
  }
  const value = input.value.trim();
  if (!isSafeFilterText(value)) {
    input.setCustomValidity("Enter visible search text without control characters.");
    return;
  }
  enforceShortTextByteLimit(input);
}

/** Whether a log query can be submitted to the render host unchanged. */
export function isValidLogQuery(value: string): boolean {
  const trimmed = value.trim();
  return (
    utf8ByteLength(value) <= SHORT_TEXT_BYTE_LIMIT &&
    (trimmed.length === 0 || isSafeFilterText(trimmed))
  );
}

function isSafeFilterText(value: string): boolean {
  return (
    hasVisibleDisplayCharacter(value) && !hasForbiddenDisplayCharacter(value)
  );
}
