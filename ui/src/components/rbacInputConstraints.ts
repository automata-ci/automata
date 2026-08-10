import {
  hasForbiddenDisplayCharacter,
  hasVisibleDisplayCharacter,
} from "../unicode";
import { utf8ByteLength } from "../validation/limits";

const RBAC_DISPLAY_NAME_BYTES = 255;
const RBAC_REASON_BYTES = 1_024;

type RbacTextControl = HTMLInputElement | HTMLTextAreaElement;

/** Keep editable RBAC display names aligned with the durable UTF-8 contract. */
export function enforceRbacDisplayNameValidity(input: HTMLInputElement): void {
  enforceRbacTextValidity(input, RBAC_DISPLAY_NAME_BYTES, "display name");
}

/** Keep one-line RBAC audit reasons aligned with the durable UTF-8 contract. */
export function enforceRbacReasonValidity(input: RbacTextControl): void {
  enforceRbacTextValidity(input, RBAC_REASON_BYTES, "reason");
}

function enforceRbacTextValidity(
  input: RbacTextControl,
  maximumBytes: number,
  fieldName: string,
): void {
  const { value } = input;
  if (value.length === 0) {
    // Let the native required constraint own empty-field copy.
    input.setCustomValidity("");
    return;
  }
  if (utf8ByteLength(value) > maximumBytes) {
    input.setCustomValidity(
      `Use at most ${maximumBytes.toLocaleString("en")} UTF-8 bytes for the ${fieldName}.`,
    );
    return;
  }
  input.setCustomValidity(
    !hasVisibleDisplayCharacter(value) || hasForbiddenDisplayCharacter(value)
      ? `Enter a visible ${fieldName} without control or bidirectional formatting characters.`
      : "",
  );
}
