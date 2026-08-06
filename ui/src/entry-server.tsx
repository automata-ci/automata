import { renderToString } from "react-dom/server";
import { HtmlDocument } from "./Document";
import type { RenderRequest } from "./models";
import { parseRenderRequest } from "./serialization";
import { validateRenderRequest } from "./validation";

function renderValidatedPage(request: RenderRequest): string {
  return `<!doctype html>${renderToString(<HtmlDocument request={request} />)}`;
}

/** Source-level API used by tests and by future in-process renderer adapters. */
export function renderPage(request: RenderRequest): string {
  return renderValidatedPage(validateRenderRequest(request));
}

/** Stable bundle boundary: serialized PageModel in, a complete HTML document out. */
export function render(serializedRequest: string): string {
  return renderValidatedPage(parseRenderRequest(serializedRequest));
}
