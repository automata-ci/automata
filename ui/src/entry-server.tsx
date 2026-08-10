import { renderToString } from "react-dom/server";
import { HtmlDocument } from "./Document";
import type { RenderRequest } from "./models";
import { parseRenderRequest } from "./serialization";
import { validateRenderRequest } from "./validation";

function renderValidatedPage(request: RenderRequest): string {
  return `<!doctype html>${renderToString(<HtmlDocument request={request} />)}`;
}

/** Source-level API for trusted in-process rendering and focused tests. */
export function renderPage(request: RenderRequest): string {
  return renderValidatedPage(validateRenderRequest(request));
}

/** Stable bundle boundary: serialized RenderRequest in, a complete HTML document out. */
export function render(serializedRequest: string): string {
  return renderValidatedPage(parseRenderRequest(serializedRequest));
}
