import type { RenderRequest } from "./models";
import {
  MAX_SERIALIZED_RENDER_REQUEST_BYTES,
  utf8ByteLength,
  validateRenderRequest,
} from "./validation";

export const PAGE_MODEL_ELEMENT_ID = "automata-page-model";

/**
 * JSON embedded in a script data block must not be able to close that block.
 * Escaping ampersands and the two JavaScript line separators also makes the
 * serialized bytes safe if an embedder later moves them into an inline script.
 */
export function serializeForHtml(value: unknown): string {
  const serialized = JSON.stringify(value);
  if (serialized === undefined) {
    throw new Error("Automata page model is not JSON-serializable");
  }

  return serialized
    .replaceAll("&", "\\u0026")
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e")
    .replaceAll("\u2028", "\\u2028")
    .replaceAll("\u2029", "\\u2029");
}

export function parseRenderRequest(serialized: string): RenderRequest {
  if (utf8ByteLength(serialized) > MAX_SERIALIZED_RENDER_REQUEST_BYTES) {
    throw new Error(
      `Automata render request exceeds ${MAX_SERIALIZED_RENDER_REQUEST_BYTES} UTF-8 bytes`,
    );
  }

  let value: unknown;
  try {
    value = JSON.parse(serialized);
  } catch {
    throw new Error("Malformed Automata render request JSON");
  }

  return validateRenderRequest(value);
}

export function readRenderRequest(root: Document): RenderRequest {
  const element = root.getElementById(PAGE_MODEL_ELEMENT_ID);
  if (
    element === null ||
    element.tagName !== "SCRIPT" ||
    element.getAttribute("type") !== "application/json" ||
    element.textContent === null
  ) {
    throw new Error("Automata page model is missing from the document");
  }
  return parseRenderRequest(element.textContent);
}
