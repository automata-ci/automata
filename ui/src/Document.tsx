import { App } from "./App";
import type { RenderRequest } from "./models";
import { PAGE_MODEL_ELEMENT_ID, serializeForHtml } from "./serialization";

export interface HtmlDocumentProps {
  readonly request: RenderRequest;
  readonly enableEnhancements?: boolean;
}

export function HtmlDocument({ request, enableEnhancements = false }: HtmlDocumentProps) {
  const { page } = request;
  const { assets, cspNonce, locale } = request.host;

  return (
    <html lang={locale}>
      <head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="description" content={page.shell.description} />
        <meta name="color-scheme" content="dark light" />
        <title>{page.shell.documentTitle}</title>
        {assets.stylesheets.map((href) => (
          <link rel="stylesheet" href={href} key={href} />
        ))}
      </head>
      <body>
        <App page={page} enableEnhancements={enableEnhancements} />
        <script
          id={PAGE_MODEL_ELEMENT_ID}
          type="application/json"
          nonce={cspNonce}
          dangerouslySetInnerHTML={{ __html: serializeForHtml(request) }}
        />
        <script type="module" src={assets.clientEntry} nonce={cspNonce} />
      </body>
    </html>
  );
}
